import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Optional

try:
    from .llm_client import LLMClient as _LLMClient
except ImportError:
    _LLMClient = None  # type: ignore[assignment,misc]

import requests
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("responder")

# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------
COORDINATOR_IP   = os.environ.get("COORDINATOR_IP",   "192.168.1.100")
HONEYPOT_IP      = os.environ.get("HONEYPOT_IP",      "192.168.1.99")
RESPONDER_PORT   = int(os.environ.get("RESPONDER_PORT", 5003))
AGENT_ID         = os.environ.get("RESPONDER_ID", "responder-1")

# Paths (project root = four levels up from this file)
_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", "..", ".."))
BLOCKED_IPS_FILE   = os.path.join(PROJECT_ROOT, "blocked_ips.txt")
ACTIONS_LOG_FILE   = os.path.join(PROJECT_ROOT, "responder_actions.log")

# Auto-unblock window (seconds)
# Env priority: AUTO_UNBLOCK_SECONDS > AUTO_UNBLOCK_MINUTES > default (5 min)
def _auto_unblock_seconds() -> int:
    raw = (os.environ.get("AUTO_UNBLOCK_SECONDS") or "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    raw_m = (os.environ.get("AUTO_UNBLOCK_MINUTES") or "").strip()
    if raw_m:
        try:
            return max(0, int(raw_m) * 60)
        except ValueError:
            pass
    return 5 * 60


AUTO_UNBLOCK_SECONDS = _auto_unblock_seconds()

# Pre-emptive (anticipatory) action configuration.
# These mirror EARLY_WARNING_THRESHOLD / CONFIDENCE_THRESHOLD from scout.py
# but are independently configurable via environment variables so the
# two sub-systems can be tuned separately.
PREEMPTIVE_CONFIDENCE_GATE     = float(os.environ.get("PREEMPTIVE_CONFIDENCE_GATE",    "0.40"))
CONFIRMED_CONFIDENCE_GATE      = float(os.environ.get("CONFIRMED_CONFIDENCE_GATE",     "0.60"))
PREEMPTIVE_AUTO_EXPIRE_SECONDS = int(os.environ.get("PREEMPTIVE_EXPIRE_SECONDS",       "60"))
PREEMPTIVE_RATE_LIMIT_PPS      = int(os.environ.get("PREEMPTIVE_RATE_LIMIT_PPS",       "100"))

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


# ===========================================================================
# Helper utilities
# ===========================================================================

def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _run_cmd(args: list) -> bool:
    """
    Run a shell command safely (shell=False).
    Returns True on success, False on failure.
    """
    try:
        result = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            logger.info("CMD OK: %s", " ".join(args))
            return True
        else:
            logger.error(
                "CMD FAILED (rc=%d): %s\nstderr: %s",
                result.returncode, " ".join(args), result.stderr.strip()
            )
            return False
    except FileNotFoundError:
        logger.error("CMD NOT FOUND: %s", args[0])
        return False
    except subprocess.TimeoutExpired:
        logger.error("CMD TIMEOUT: %s", " ".join(args))
        return False
    except Exception as exc:  # noqa: BLE001
        logger.exception("CMD EXCEPTION [%s]: %s", " ".join(args), exc)
        return False


# ===========================================================================
# Core action functions
# ===========================================================================

def block_ip(ip_address: str) -> bool:
    """
    Add ip_address to blocked_ips.txt and install an iptables DROP rule.
    Returns True if the iptables command succeeded.
    """
    # Persist to file
    try:
        with open(BLOCKED_IPS_FILE, "a") as fh:
            fh.write(f"{ip_address}\n")
        logger.info("Added %s to %s", ip_address, BLOCKED_IPS_FILE)
    except OSError as exc:
        logger.error("Could not write to %s: %s", BLOCKED_IPS_FILE, exc)

    # iptables rule
    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    success = _run_cmd(cmd)
    log_action(ip_address, "block", AGENT_ID, success)
    return success


def redirect_to_honeypot(ip_address: str) -> bool:
    """
    Redirect traffic from ip_address to the honeypot via DNAT.
    Returns True if the iptables command succeeded.
    """
    cmd = [
        "sudo", "iptables",
        "-t", "nat",
        "-A", "PREROUTING",
        "-s", ip_address,
        "-j", "DNAT",
        "--to-destination", HONEYPOT_IP,
    ]
    success = _run_cmd(cmd)
    if success:
        logger.info("Redirected %s → honeypot %s", ip_address, HONEYPOT_IP)
    log_action(ip_address, "redirect_to_honeypot", AGENT_ID, success)
    return success


def quarantine_host(ip_address: str) -> bool:
    """
    Block all forwarded traffic to/from ip_address without taking the
    machine fully offline.  Returns True if both iptables rules succeeded.
    """
    cmd_src = [
        "sudo", "iptables", "-A", "FORWARD", "-s", ip_address, "-j", "DROP"
    ]
    cmd_dst = [
        "sudo", "iptables", "-A", "FORWARD", "-d", ip_address, "-j", "DROP"
    ]
    s1 = _run_cmd(cmd_src)
    s2 = _run_cmd(cmd_dst)
    success = s1 and s2
    log_action(ip_address, "quarantine", AGENT_ID, success)
    return success


def unblock_ip(ip_address: str) -> bool:
    """
    Remove ip_address from blocked_ips.txt and delete the iptables DROP rule.
    Returns True if the iptables command succeeded.
    """
    # Remove from file
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r") as fh:
                lines = fh.readlines()
            with open(BLOCKED_IPS_FILE, "w") as fh:
                for line in lines:
                    if line.strip() != ip_address:
                        fh.write(line)
            logger.info("Removed %s from %s", ip_address, BLOCKED_IPS_FILE)
    except OSError as exc:
        logger.error("Could not update %s: %s", BLOCKED_IPS_FILE, exc)

    # Delete iptables rule
    cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
    success = _run_cmd(cmd)
    log_action(ip_address, "unblock", AGENT_ID, success)
    return success


def remove_redirect(ip_address: str) -> bool:
    """
    Remove the DNAT redirect rule for ip_address.
    Returns True if the iptables command succeeded.
    """
    cmd = [
        "sudo", "iptables",
        "-t", "nat",
        "-D", "PREROUTING",
        "-s", ip_address,
        "-j", "DNAT",
        "--to-destination", HONEYPOT_IP,
    ]
    success = _run_cmd(cmd)
    log_action(ip_address, "remove_redirect", AGENT_ID, success)
    return success


# ---------------------------------------------------------------------------
# Pre-emptive (anticipatory) action functions
# These are low-impact, reversible, and expire automatically.
# ---------------------------------------------------------------------------

def rate_limit_ip(
    ip_address: str,
    pps_limit:  int = PREEMPTIVE_RATE_LIMIT_PPS,
) -> bool:
    """
    Apply a per-source packet-rate limit via iptables hashlimit.

    Low-impact pre-emptive action: throttles suspicious traffic *without*
    dropping it outright.  Automatically expired by the auto-unblock thread
    after ``PREEMPTIVE_AUTO_EXPIRE_SECONDS`` seconds.
    Returns True if the iptables command succeeded.
    """
    rule_name = f"rl_{ip_address.replace('.', '_')}"
    cmd = [
        "sudo", "iptables", "-A", "INPUT",
        "-s", ip_address,
        "-m", "hashlimit",
        "--hashlimit-name",  rule_name,
        "--hashlimit-above", f"{pps_limit}/sec",
        "--hashlimit-mode",  "srcip",
        "-j", "DROP",
    ]
    success = _run_cmd(cmd)
    if success:
        logger.info(
            "Rate-limited %s at %d pps (auto-expires in %ds)",
            ip_address, pps_limit, PREEMPTIVE_AUTO_EXPIRE_SECONDS,
        )
    log_action(ip_address, "rate_limit", AGENT_ID, success)
    return success


def remove_rate_limit(
    ip_address: str,
    pps_limit:  int = PREEMPTIVE_RATE_LIMIT_PPS,
) -> bool:
    """
    Remove the hashlimit rate-limit rule for ip_address.
    Returns True if the iptables command succeeded.
    """
    rule_name = f"rl_{ip_address.replace('.', '_')}"
    cmd = [
        "sudo", "iptables", "-D", "INPUT",
        "-s", ip_address,
        "-m", "hashlimit",
        "--hashlimit-name",  rule_name,
        "--hashlimit-above", f"{pps_limit}/sec",
        "--hashlimit-mode",  "srcip",
        "-j", "DROP",
    ]
    success = _run_cmd(cmd)
    log_action(ip_address, "remove_rate_limit", AGENT_ID, success)
    return success


def preemptive_monitor(
    ip_address:    str,
    threat_type:   str   = "unknown",
    current_conf:  float = 0.0,
    predicted_conf: float = 0.0,
) -> bool:
    """
    Elevated monitoring: no enforcement, but creates a tagged action-log entry
    so the auto-unblock thread and dashboards can track pre-emptive observations.
    Always succeeds (returns True).
    """
    logger.info(
        "ELEVATED MONITOR: %s — threat=%s  current=%.2f  predicted=%.2f",
        ip_address, threat_type, current_conf, predicted_conf,
    )
    log_action(ip_address, "elevated_monitor", AGENT_ID, True)
    return True


# ===========================================================================
# Logging helper
# ===========================================================================

def log_action(ip: str, action: str, requester: str, success: bool) -> None:
    """
    Append a structured JSON entry to ACTIONS_LOG_FILE.
    Fields: timestamp, attacker_ip, action_taken, requested_by, success
    """
    entry = {
        "timestamp":    _now_iso(),
        "attacker_ip":  ip,
        "action_taken": action,
        "requested_by": requester,
        "success":      success,
    }
    try:
        with open(ACTIONS_LOG_FILE, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError as exc:
        logger.error("Could not write to %s: %s", ACTIONS_LOG_FILE, exc)
    # Publish to A2A bus (non-blocking; import is deferred to avoid circular deps)
    try:
        from ..utils.message_bus import get_bus, TOPIC_RESPONDER_ACTION
        get_bus().publish(TOPIC_RESPONDER_ACTION, {
            "source_ip": ip,
            "action":    action,
            "requester": requester,
            "success":   success,
            "timestamp": entry["timestamp"],
            "agent_id":  AGENT_ID,
        })
    except Exception:  # noqa: BLE001
        pass


# ===========================================================================
# Report back to Coordinator and Dashboard
# ===========================================================================

def _report_action(source_ip: str, action_taken: str, success: bool) -> None:
    """
    POST a confirmation payload to the Coordinator and Dashboard.
    Runs in its own thread so it never blocks the main response path.
    """
    payload = {
        "timestamp":    _now_iso(),
        "source_ip":    source_ip,
        "action_taken": action_taken,
        "success":      success,
        "agent_id":     AGENT_ID,
    }

    targets = [
        (f"http://{COORDINATOR_IP}:5000/action_taken", "Coordinator"),
        (f"http://{COORDINATOR_IP}:5005/update",       "Dashboard"),
    ]

    for url, name in targets:
        try:
            resp = requests.post(url, json=payload, timeout=5)
            logger.info(
                "Reported action to %s (%s): HTTP %d",
                name, url, resp.status_code
            )
        except requests.exceptions.RequestException as exc:
            logger.warning("Could not reach %s at %s: %s", name, url, exc)


def report_action_async(source_ip: str, action_taken: str, success: bool) -> None:
    """Fire-and-forget report so the Flask handler returns immediately."""
    t = threading.Thread(
        target=_report_action,
        args=(source_ip, action_taken, success),
        daemon=True,
    )
    t.start()


# ===========================================================================
# Pre-emptive safety gate
# ===========================================================================

# Only these low-impact actions may be issued pre-emptively (before confirmation).
_PREEMPTIVE_SAFE_ACTIONS    = frozenset({"rate_limit", "elevated_monitor"})
# These destructive actions must NEVER be issued on an early-warning signal.
_CONFIRMED_ONLY_ACTIONS     = frozenset({"block", "redirect_to_honeypot", "quarantine"})


def _preemptive_safety_gate(
    ip_address:     str,
    recommended:    str,
    current_conf:   float,
    predicted_conf: float,
    alert_level:    str,
) -> tuple:  # (approved: bool, reason: str)
    """
    Strict safety gate applied to every pre-emptive action request.

    All four conditions below must hold for a pre-emptive action to be
    approved.  If any fail, the action is rejected with a reason string;
    the Responder logs the rejection and returns a 200 ``gate_rejected``
    response (not an error — the system is working as intended).

    Gate 1 — action whitelist  : only rate_limit / elevated_monitor allowed.
    Gate 2 — alert-level guard : must be ``early_warning`` (not ``confirmed``
              or higher; confirmed threats take the normal /verdict path).
    Gate 3 — predicted threshold: predicted confidence must be ≥
              ``PREEMPTIVE_CONFIDENCE_GATE`` (rising toward danger).
    Gate 4 — not-yet-confirmed : current confidence must be below
              ``CONFIRMED_CONFIDENCE_GATE`` (otherwise use /verdict instead).

    Returns
    -------
    (True, reason_str)   if all gates pass
    (False, reason_str)  if any gate rejects
    """
    if recommended not in _PREEMPTIVE_SAFE_ACTIONS:
        return (
            False,
            f"action '{recommended}' is not a pre-emptive-safe action — "
            f"use /verdict for destructive actions",
        )
    if alert_level != "early_warning":
        return (
            False,
            f"alert_level '{alert_level}' does not qualify for pre-emptive action — "
            f"must be 'early_warning'",
        )
    if predicted_conf < PREEMPTIVE_CONFIDENCE_GATE:
        return (
            False,
            f"predicted confidence {predicted_conf:.3f} is below gate "
            f"{PREEMPTIVE_CONFIDENCE_GATE} — not yet a credible rising threat",
        )
    if current_conf >= CONFIRMED_CONFIDENCE_GATE:
        return (
            False,
            f"current confidence {current_conf:.3f} is at or above confirmed "
            f"threshold {CONFIRMED_CONFIDENCE_GATE} — use /verdict endpoint instead",
        )
    return (True, "all pre-emptive safety gates passed")


# ===========================================================================
# Decision engine
# ===========================================================================

def decide_and_act(verdict: dict) -> tuple:
    """
    Inspect verdict fields and call the appropriate action function.
    Returns (action_taken: str, success: bool).
    """
    ip          = verdict.get("source_ip", "unknown")
    attack_type = verdict.get("predicted_attack_type", "Normal")
    recommended = verdict.get("recommended_action", "monitor")
    requester   = verdict.get("agent_id", "unknown")

    logger.info(
        "Verdict received — IP: %s | attack: %s | recommended: %s | from: %s",
        ip, attack_type, recommended, requester,
    )

    # Priority: explicit recommended_action first, then attack_type fallback.
    # NOTE: attack_type fallback is intentionally checked AFTER recommended so
    # that the caller's explicit instruction always wins.  The recommended_action
    # field in Scout MC results is the authoritative source (see _monte_carlo_estimate).
    if recommended == "block" or attack_type in ("DDoS", "DoS", "Bot"):
        success = block_ip(ip)
        action  = "block"

    elif recommended == "redirect_to_honeypot" or attack_type == "PortScan":
        success = redirect_to_honeypot(ip)
        action  = "redirect_to_honeypot"

    elif recommended == "quarantine" or attack_type in ("Exfiltration", "Infiltration"):
        # Exfiltration and host infiltration warrant full bidirectional quarantine
        success = quarantine_host(ip)
        action  = "quarantine"

    elif recommended == "rate_limit":
        # Pre-emptive rate-limit — low-impact, auto-expires
        success = rate_limit_ip(ip)
        action  = "rate_limit"

    else:
        # "monitor" or any unrecognised combination
        logger.info("Monitoring IP %s (no active countermeasure applied).", ip)
        log_action(ip, "monitor", requester, True)
        action  = "monitor"
        success = True

    return action, success


# ===========================================================================
# Auto-unblock background thread
# ===========================================================================

def _auto_unblock_loop() -> None:
    """
    Runs every AUTO_UNBLOCK_SECONDS.  Reads ACTIONS_LOG_FILE, finds IPs
    that were *blocked* or *redirected* more than AUTO_UNBLOCK_SECONDS ago
    and haven't been unblocked/redirect-removed yet, then cleans them up.
    """
    while True:
        time.sleep(AUTO_UNBLOCK_SECONDS)
        logger.info("Auto-unblock thread: scanning %s …", ACTIONS_LOG_FILE)

        if not os.path.exists(ACTIONS_LOG_FILE):
            continue

        try:
            with open(ACTIONS_LOG_FILE, "r") as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.error("Auto-unblock: cannot read log: %s", exc)
            continue

        # Build per-IP action history
        ip_history: dict = {}
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                ip = entry.get("attacker_ip")
                if ip:
                    ip_history.setdefault(ip, []).append(entry)
            except json.JSONDecodeError:
                continue

        now = datetime.now(timezone.utc)

        for ip, entries in ip_history.items():
            # Determine the *current* state for this IP
            # (last logged action wins)
            entries_sorted = sorted(entries, key=lambda e: e.get("timestamp", ""))
            last_entry  = entries_sorted[-1]
            last_action = last_entry.get("action_taken", "")
            last_ts_str = last_entry.get("timestamp", "")

            # Handle active blocking/redirect/rate-limit states
            if last_action not in ("block", "redirect_to_honeypot", "rate_limit"):
                continue

            # Parse timestamp
            try:
                last_ts = datetime.fromisoformat(last_ts_str)
            except ValueError:
                continue

            age_seconds = (now - last_ts).total_seconds()
            # Pre-emptive rate-limits expire faster than full blocks
            expiry = (
                PREEMPTIVE_AUTO_EXPIRE_SECONDS
                if last_action == "rate_limit"
                else AUTO_UNBLOCK_SECONDS
            )
            if age_seconds >= expiry:
                if last_action == "block":
                    logger.info(
                        "Auto-unblocking %s (blocked %.0fs ago)", ip, age_seconds
                    )
                    unblock_ip(ip)
                    report_action_async(ip, "auto_unblock", True)
                elif last_action == "redirect_to_honeypot":
                    logger.info(
                        "Auto-removing redirect for %s (set %.0fs ago)",
                        ip, age_seconds
                    )
                    remove_redirect(ip)
                    report_action_async(ip, "auto_remove_redirect", True)
                elif last_action == "rate_limit":
                    logger.info(
                        "Auto-removing rate-limit for %s (set %.0fs ago, limit=%ds)",
                        ip, age_seconds, PREEMPTIVE_AUTO_EXPIRE_SECONDS
                    )
                    remove_rate_limit(ip)
                    report_action_async(ip, "auto_remove_rate_limit", True)


def start_auto_unblock_thread() -> None:
    """Start the background auto-unblock thread (daemon)."""
    t = threading.Thread(target=_auto_unblock_loop, name="auto-unblock", daemon=True)
    t.start()
    logger.info("Auto-unblock thread started (interval: %ds).", AUTO_UNBLOCK_SECONDS)


# ===========================================================================
# LLM prompt engineering (Responder)
# ===========================================================================

_RESPONDER_SYSTEM_PROMPT = (
    "You are a defensive action validation assistant embedded in SwarmShield, "
    "an autonomous cybersecurity defense system.\n\n"
    "Your ONLY task: validate a proposed defensive action produced by a deterministic "
    "decision engine, or flag it for human review.\n\n"
    "CRITICAL CONSTRAINTS — violation will cause system failures:\n"
    "1. The verdict data (source_ip, attack_type, confidence) and proposed_action "
    "below come from a deterministic decision engine with correct priority logic applied.\n"
    "2. Default to validating the proposed action (action_validated: true, "
    "action_override: null) unless you identify a specific, concrete risk.\n"
    "3. Respond with valid JSON containing ONLY the OUTPUT SCHEMA fields. "
    "No prose, no extra keys.\n"
    "4. Do not invent network context not present in the input.\n"
    "5. Use ONLY the enumerated values specified for action fields.\n\n"
    "VALID ACTIONS (for action_override — null if validated):\n"
    "  block                 — iptables DROP all traffic from source IP\n"
    "  rate_limit            — throttle source traffic below safe threshold\n"
    "  redirect_to_honeypot  — DNAT source traffic to honeypot\n"
    "  quarantine            — FORWARD DROP both directions\n"
    "  monitor               — no enforcement; logging only\n"
    "  escalate              — flag for human review\n\n"
    "COLLATERAL RISK GUIDELINES — \"collateral_risk\" must be one of:\n"
    "  high   — IP may be a shared gateway, CDN node, or internal corporate host\n"
    "  medium — single external host but confidence < 0.80\n"
    "  low    — confirmed single external attacker with confidence >= 0.80\n\n"
    "ESCALATION TRIGGERS — set escalation_needed: true if any apply:\n"
    "  • confidence < 0.50 AND proposed action is 'block' or 'quarantine'\n"
    "  • attack_type is 'Normal' or unknown\n"
    "  • action_override is not null (human should review the override)\n\n"
    "OUTPUT SCHEMA — respond with ONLY this JSON object, no other text:\n"
    '{\n'
    '  "action_validated":   <true|false>,\n'
    '  "action_override":    "<action>" or null,\n'
    '  "risk_justification": "<1 sentence based strictly on input data>",\n'
    '  "collateral_risk":    "<high|medium|low>",\n'
    '  "escalation_needed":  <true|false>\n'
    '}'
)

# Module-level LLM client (set at startup via init_responder_llm)
_responder_llm: Optional["_LLMClient"] = None   # type: ignore[valid-type]


def init_responder_llm(client) -> None:
    """Set the module-level LLM client for the Responder agent."""
    global _responder_llm
    _responder_llm = client
    logger.info("Responder LLM client initialised (model=%s).",
                getattr(client, "model", "unknown"))


def _llm_validate_action(
    verdict:        dict,
    proposed_action: str,
    llm_client,
) -> Optional[dict]:
    """
    Call the LLM to validate a proposed defensive action before execution.
    Returns None (silently) if the client is unavailable or the call fails.
    """
    if llm_client is None or not llm_client.available:
        return None
    source_ip   = verdict.get("source_ip",             "unknown")
    attack_type = verdict.get("predicted_attack_type", "unknown")
    confidence  = float(verdict.get("confidence",      0.0))
    recommended = verdict.get("recommended_action",    "monitor")
    user_msg = (
        f"DEFENSIVE ACTION VALIDATION REQUEST\n"
        f"source_ip          : {source_ip}\n"
        f"predicted_attack   : {attack_type}\n"
        f"confidence         : {confidence:.4f}  (algorithm-computed, ground truth)\n"
        f"recommended_action : {recommended}  (from upstream Analyzer)\n"
        f"proposed_action    : {proposed_action}  (selected by decision engine)\n"
        f"\n"
        f"Decision engine priority logic applied:\n"
        f"  1. Explicit recommended_action takes precedence.\n"
        f"  2. Attack-type fallback applies when no explicit recommendation.\n"
        f"\n"
        f"Validate the proposed_action. Only suggest an override if you "
        f"can identify a specific, concrete risk not addressed by the current action."
    )
    return llm_client.complete(_RESPONDER_SYSTEM_PROMPT, user_msg)


# ===========================================================================
# Flask routes
# ===========================================================================

@app.route("/verdict", methods=["POST"])
def verdict_endpoint():
    """
    Receive a verdict JSON from the Analyzer/Evolver and act on it.

    Expected JSON fields:
        source_ip, predicted_attack_type, confidence,
        shap_explanation, recommended_action, agent_id
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    required = [
        "source_ip", "predicted_attack_type", "confidence",
        "shap_explanation", "recommended_action", "agent_id",
    ]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    action, success = decide_and_act(data)
    report_action_async(data["source_ip"], action, success)

    response_body = {
        "status":       "ok",
        "action_taken": action,
        "success":      success,
        "agent_id":     AGENT_ID,
        "timestamp":    _now_iso(),
    }
    llm_validation = _llm_validate_action(data, action, _responder_llm)
    if llm_validation:
        response_body["llm_validation"] = llm_validation
    return jsonify(response_body), 200


@app.route("/preemptive_action", methods=["POST"])
def preemptive_action_endpoint():
    """
    Receive an anticipatory pre-emptive action request produced by
    ``AnalyzerAgent.pre_assess_risk()`` (triggered by Scout's early-warning
    rolling inference).

    Only ``rate_limit`` and ``elevated_monitor`` are accepted here.
    All four safety-gate conditions must pass before any action is taken.
    A ``gate_rejected`` response (HTTP 200) means the gate worked correctly—
    it is not an error.

    Expected JSON fields
    --------------------
    source_ip, alert_level, current_confidence, predicted_confidence,
    recommended_action, agent_id.
    Optional: threat_type, trend_direction, reasoning.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    required = [
        "source_ip", "alert_level", "current_confidence",
        "predicted_confidence", "recommended_action", "agent_id",
    ]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    ip             = data["source_ip"]
    alert_level    = data["alert_level"]
    current_conf   = float(data["current_confidence"])
    predicted_conf = float(data["predicted_confidence"])
    recommended    = data["recommended_action"]
    threat_type    = data.get("threat_type", "unknown")

    logger.info(
        "Pre-emptive request: %s  alert=%s  conf=%.2f→%.2f  action=%s",
        ip, alert_level, current_conf, predicted_conf, recommended,
    )

    # Apply all safety gates before touching any enforcement rules
    approved, gate_reason = _preemptive_safety_gate(
        ip, recommended, current_conf, predicted_conf, alert_level
    )

    if not approved:
        logger.info(
            "Pre-emptive action REJECTED by safety gate for %s: %s", ip, gate_reason
        )
        return jsonify({
            "status":       "gate_rejected",
            "source_ip":    ip,
            "reason":       gate_reason,
            "action_taken": None,
            "agent_id":     AGENT_ID,
            "timestamp":    _now_iso(),
        }), 200

    # Execute the approved pre-emptive action
    if recommended == "rate_limit":
        success = rate_limit_ip(ip)
        action  = "rate_limit"
    else:  # elevated_monitor
        success = preemptive_monitor(ip, threat_type, current_conf, predicted_conf)
        action  = "elevated_monitor"

    report_action_async(ip, action, success)

    return jsonify({
        "status":       "ok",
        "source_ip":    ip,
        "action_taken": action,
        "success":      success,
        "gate_reason":  gate_reason,
        "agent_id":     AGENT_ID,
        "timestamp":    _now_iso(),
    }), 200


@app.route("/cic_block", methods=["POST"])
def cic_block_endpoint():
    """
    CIC-ML addon: act on an IP flagged by the CIC-IDS2017 XGBoost layer.

    This is a lightweight endpoint — no LLM enrichment, no SHAP, no
    threat-graph modelling.  The Analyzer's ``cic_screen()`` calls it
    directly for IPs classified as attacks by the ML model.

    Expected JSON fields
    --------------------
    source_ip          : str   — IP address to act on
    cic_label          : str   — predicted attack class (e.g. "DDoS", "PortScan")
    confidence         : float — model's class probability [0, 1]
    recommended_action : str   — "block" | "redirect_to_honeypot" | "quarantine"
                                 (set by Analyzer.cic_screen; defaults to "block")
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    required = ["source_ip", "cic_label", "confidence"]
    missing  = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    source_ip         = str(data["source_ip"])
    cic_label         = str(data["cic_label"])
    confidence        = float(data.get("confidence", 0.0))
    recommended_action = str(data.get("recommended_action", "block"))

    # Minimum confidence gate — skip very uncertain predictions
    MIN_CIC_CONF = float(os.environ.get("CIC_BLOCK_MIN_CONFIDENCE", "0.60"))
    if confidence < MIN_CIC_CONF:
        logger.info(
            "[CIC-ML] %s below confidence threshold (%.2f < %.2f) — skipped",
            source_ip, confidence, MIN_CIC_CONF,
        )
        return jsonify({
            "status":   "skipped",
            "reason":   f"confidence {confidence:.2f} < threshold {MIN_CIC_CONF:.2f}",
            "agent_id": AGENT_ID,
        }), 200

    # Dispatch to the correct enforcement function based on recommended_action.
    # PortScan → honeypot; Infiltration → quarantine; everything else → block.
    if recommended_action == "redirect_to_honeypot":
        success = redirect_to_honeypot(source_ip)
        action  = "redirect_to_honeypot"
    elif recommended_action == "quarantine":
        success = quarantine_host(source_ip)
        action  = "quarantine"
    else:
        success = block_ip(source_ip)
        action  = "block"

    logger.info(
        "[CIC-ML] %s on %s — label=%s conf=%.2f success=%s",
        action, source_ip, cic_label, confidence, success,
    )
    return jsonify({
        "status":       action if success else "failed",
        "source_ip":    source_ip,
        "cic_label":    cic_label,
        "action_taken": action,
        "confidence":   confidence,
        "success":      success,
        "agent_id":     AGENT_ID,
        "timestamp":    _now_iso(),
    }), 200


@app.route("/health", methods=["GET"])
def health():
    """Liveness probe."""
    return jsonify({"status": "alive", "agent_id": AGENT_ID}), 200


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    # Optional: initialise LLM action validation when a Grok key is present.
    if _LLMClient is not None:
        try:
            _model = (os.environ.get("LLM_MODEL") or "grok-2-1212").strip()
            _temp  = float((os.environ.get("LLM_TEMPERATURE") or "0.0").strip())
            _client = _LLMClient(model=_model, temperature=_temp)
            if getattr(_client, "available", False):
                init_responder_llm(_client)
        except Exception as _exc:  # noqa: BLE001
            logger.info("Responder LLM init skipped: %s", _exc)

    start_auto_unblock_thread()
    app.run(host="0.0.0.0", port=RESPONDER_PORT)
