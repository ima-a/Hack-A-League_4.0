"""
Responder Agent — SwarmShield

Receives verdict payloads from the Analyzer/Evolver agents and takes
defensive actions: IP blocking, honeypot redirection, host quarantine,
and monitoring.  Reports every action back to the Coordinator and Dashboard.
"""

import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone

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
AGENT_ID         = "responder-1"

# Paths (project root = four levels up from this file)
_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", "..", ".."))
BLOCKED_IPS_FILE   = os.path.join(PROJECT_ROOT, "blocked_ips.txt")
ACTIONS_LOG_FILE   = os.path.join(PROJECT_ROOT, "responder_actions.log")

# Auto-unblock window (seconds)
AUTO_UNBLOCK_SECONDS = 5 * 60   # 5 minutes

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

    # Priority: explicit recommended_action first, then attack_type fallback
    if recommended == "block" or attack_type == "DDoS":
        success = block_ip(ip)
        action  = "block"

    elif recommended == "redirect_to_honeypot" or attack_type == "PortScan":
        success = redirect_to_honeypot(ip)
        action  = "redirect_to_honeypot"

    elif recommended == "quarantine" or attack_type == "Ransomware":
        success = quarantine_host(ip)
        action  = "quarantine"

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

            # Only act on active blocking/redirect states
            if last_action not in ("block", "redirect_to_honeypot"):
                continue

            # Parse timestamp
            try:
                last_ts = datetime.fromisoformat(last_ts_str)
            except ValueError:
                continue

            age_seconds = (now - last_ts).total_seconds()
            if age_seconds >= AUTO_UNBLOCK_SECONDS:
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


def start_auto_unblock_thread() -> None:
    """Start the background auto-unblock thread (daemon)."""
    t = threading.Thread(target=_auto_unblock_loop, name="auto-unblock", daemon=True)
    t.start()
    logger.info("Auto-unblock thread started (interval: %ds).", AUTO_UNBLOCK_SECONDS)


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

    return jsonify({
        "status":       "ok",
        "action_taken": action,
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
    start_auto_unblock_thread()
    app.run(host="0.0.0.0", port=RESPONDER_PORT)
