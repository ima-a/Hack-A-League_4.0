"""
Responder CrewAI Tools
=======================
Wraps responder module functions as CrewAI @tool functions so the Responder
CrewAI Agent can call them during orchestrated task execution.

SAFETY: All destructive iptables operations are skipped unless
  LIVE_MODE=true  is set in the environment.
  In dry-run / demo mode the action is logged and tracked but no real
  firewall rule is modified.

All tools:
- Accept/return plain strings (JSON-encoded where needed)
- Catch all exceptions and return a JSON error dict instead of raising
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

LIVE_MODE: bool = os.environ.get("LIVE_MODE", "false").lower() == "true"

# Human approval gate. Set HUMAN_APPROVAL=true to require confirmation before
# each defense action. Safe to toggle at runtime via os.environ.
def _human_approval_required() -> bool:
    return os.environ.get("HUMAN_APPROVAL", "false").lower() == "true"


def _request_human_approval(ip: str, action: str, threat_type: str,
                             confidence: float) -> bool:
    """
    Print a pending-action notice and wait for operator confirmation.

    Returns True to proceed with the action, False to skip it.

    Accepts: y or yes or enter to approve,
             n or no to reject,
             a or abort to cancel ALL remaining actions (raises SystemExit).
    """
    _C = lambda code: code if sys.stdout.isatty() else ""
    _YELLOW = _C("\033[33m")
    _RED    = _C("\033[31m")
    _BOLD   = _C("\033[1m")
    _RST    = _C("\033[0m")

    print(f"\n{_YELLOW}{_BOLD}[HUMAN APPROVAL REQUIRED]{_RST}")
    print(f"  IP         : {ip}")
    print(f"  Action     : {_RED}{_BOLD}{action}{_RST}")
    print(f"  Threat type: {threat_type}")
    print(f"  Confidence : {confidence:.0%}")
    print(f"  Mode       : {'LIVE - real iptables' if LIVE_MODE else 'DRY-RUN'}")
    try:
        ans = input("  Approve? [Y/n/abort]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n[Interrupted - skipping action]")
        return False

    if ans in ("a", "abort"):
        print("[ABORT - all remaining actions cancelled]")
        raise SystemExit("abort")
    return ans in ("", "y", "yes")

# A2A bus helper — never raises
def _bus_publish(topic: str, message: dict) -> None:
    """Publish to the A2A message bus, silently ignoring any errors."""
    try:
        from ..utils.message_bus import get_bus
        get_bus().publish(topic, message)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Bus publish failed for topic '%s': %s", topic, exc)

try:
    from crewai.tools import tool as crewai_tool
    _CREWAI_AVAILABLE = True
except ImportError:
    logger.warning("crewai not installed — responder tools will not be registered as CrewAI tools.")
    _CREWAI_AVAILABLE = False

    def crewai_tool(name=None, description=None):  # type: ignore[misc]
        """Fallback no-op decorator when crewai is unavailable."""
        def decorator(fn):
            return fn
        return decorator


# ---------------------------------------------------------------------------
# Dry-run action registry (simulated actions for demo / test mode)
# ---------------------------------------------------------------------------

_DRY_RUN_ACTIONS: list = []


def _record_dry_run(ip: str, action: str, reason: str) -> dict:
    entry = {
        "ip": ip,
        "action": action,
        "reason": reason,
        "mode": "dry_run",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    _DRY_RUN_ACTIONS.append(entry)
    logger.info("[DRY RUN] Would %s %s - reason: %s", action, ip, reason)
    return entry


# ---------------------------------------------------------------------------
# Tool: apply_defense_actions
# ---------------------------------------------------------------------------

@crewai_tool("apply_defense_actions")
def apply_defense_actions(analyzer_report_json: str) -> str:
    """
    Apply defense actions based on an analyzer risk report.

    Accepts the JSON output of full_threat_analysis or run_propagation_simulation.
    Reads the "risk_assessment.recommendations" list and the
    "risk_assessment.top_threats" list to determine which IPs to act on.

    In LIVE_MODE=true: executes real iptables rules via the responder module.
    In LIVE_MODE=false (default/demo): simulates and logs all actions without
    touching the firewall.

    Returns a JSON summary of all actions applied.
    """
    try:
        report = json.loads(analyzer_report_json)
        if not isinstance(report, dict):
            return json.dumps({"error": "analyzer_report_json must be a JSON object"})

        # Navigate both flat and nested structures
        risk_assessment = report.get("risk_assessment", report)
        top_threats = risk_assessment.get("top_threats", [])
        risk_level = risk_assessment.get("risk_level", "none")

        actions_applied = []

        if not top_threats:
            return json.dumps({
                "actions_applied": [],
                "summary": "No threats found - no actions needed.",
                "risk_level": risk_level,
                "timestamp": _now_iso(),
            })

        for threat in top_threats:
            ip = threat.get("ip", "")
            threat_type = threat.get("threat_type", "Unknown").lower()
            confidence = float(threat.get("confidence", 0.0))

            if not ip:
                continue

            # Choose action based on threat type and confidence
            if confidence < 0.40:
                action = "monitor"
            elif "ddos" in threat_type or "syn" in threat_type:
                action = "block"
            elif "port_scan" in threat_type or "portscan" in threat_type or "scan" in threat_type:
                action = "redirect_to_honeypot"
            elif "exfil" in threat_type:
                action = "quarantine"
            elif confidence >= 0.60:
                action = "block"
            else:
                action = "rate_limit"

            # Human approval gate
            if _human_approval_required() and action != "monitor":
                try:
                    approved = _request_human_approval(ip, action, threat_type, confidence)
                except SystemExit:
                    break
                if not approved:
                    logger.info("[HUMAN] Vetoed: %s on %s", action, ip)
                    continue
                logger.info("[HUMAN] Approved: %s on %s", action, ip)

            result = _execute_action(ip, action, threat_type, confidence)
            actions_applied.append(result)

        # A2A publish one event per action
        from ..utils.message_bus import TOPIC_RESPONDER_ACTION
        for act in actions_applied:
            _bus_publish(TOPIC_RESPONDER_ACTION, {
                "source_ip": act.get("ip", ""),
                "action": act.get("action", ""),
                "requester": "responder-crewai",
                "success": act.get("success", True),
                "timestamp": act.get("timestamp", _now_iso()),
                "agent_id": "responder-crewai",
            })
        return json.dumps({
            "actions_applied": actions_applied,
            "summary": f"{len(actions_applied)} action(s) applied for {risk_level} risk level.",
            "risk_level": risk_level,
            "live_mode": LIVE_MODE,
            "timestamp": _now_iso(),
        }, default=str)

    except Exception as exc:  # noqa: BLE001
        logger.exception("apply_defense_actions error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Tool: block_ip_address
# ---------------------------------------------------------------------------

@crewai_tool("block_ip_address")
def block_ip_address(ip_address: str, reason: str = "manual_block") -> str:
    """
    Block all traffic from an IP address.

    In LIVE_MODE=true: adds iptables DROP rule and persists to blocked_ips.txt.
    In LIVE_MODE=false: simulates and logs the block without iptables.

    Returns a JSON result dict with keys: ip, action, success, mode, timestamp.
    """
    try:
        ip_address = ip_address.strip()
        if not ip_address:
            return json.dumps({"error": "ip_address must not be empty"})

        result = _execute_action(ip_address, "block", "manual", 1.0)
        result["reason"] = reason
        # ── A2A publish ────────────────────────────────────────────────
        from ..utils.message_bus import TOPIC_RESPONDER_ACTION
        _bus_publish(TOPIC_RESPONDER_ACTION, {
            "source_ip": ip_address,
            "action": "block",
            "requester": "responder-crewai",
            "success": result.get("success", True),
            "timestamp": result.get("timestamp", _now_iso()),
            "agent_id": "responder-crewai",
        })
        return json.dumps(result, default=str)

    except Exception as exc:  # noqa: BLE001
        logger.exception("block_ip_address error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Tool: get_active_blocks
# ---------------------------------------------------------------------------

@crewai_tool("get_active_blocks")
def get_active_blocks() -> str:
    """
    Return the current list of blocked IP addresses.

    In LIVE_MODE=true: reads from blocked_ips.txt on disk.
    In LIVE_MODE=false: returns the dry-run log of actions taken this session.

    Returns a JSON object:
      {"blocked_ips": [...], "dry_run_actions": [...], "mode": "live|dry_run"}
    """
    try:
        if LIVE_MODE:
            from ..agents.responder import BLOCKED_IPS_FILE
            from ..tools.response_tool import load_blocked_ips
            blocked = list(load_blocked_ips(BLOCKED_IPS_FILE))
            return json.dumps({
                "blocked_ips": blocked,
                "dry_run_actions": [],
                "mode": "live",
                "timestamp": _now_iso(),
            })
        else:
            # Return the in-memory dry-run log
            blocked_ips = [
                a["ip"] for a in _DRY_RUN_ACTIONS if a.get("action") == "block"
            ]
            return json.dumps({
                "blocked_ips": list(set(blocked_ips)),
                "dry_run_actions": _DRY_RUN_ACTIONS,
                "mode": "dry_run",
                "timestamp": _now_iso(),
            })
    except Exception as exc:  # noqa: BLE001
        logger.exception("get_active_blocks error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Internal: execute an action (live or dry-run)
# ---------------------------------------------------------------------------

def _execute_action(ip: str, action: str, threat_type: str, confidence: float) -> dict:
    """Execute a defense action - live or dry-run depending on LIVE_MODE."""
    if not LIVE_MODE:
        return _record_dry_run(ip, action, f"{threat_type} (confidence={confidence:.2f})")

    # Live mode - call real responder functions
    try:
        from ..agents import responder as _resp

        success = False
        if action == "block":
            success = _resp.block_ip(ip)
        elif action == "redirect_to_honeypot":
            success = _resp.redirect_to_honeypot(ip)
        elif action == "quarantine":
            success = _resp.quarantine_host(ip)
        elif action == "rate_limit":
            success = _resp.rate_limit_ip(ip)
        elif action == "monitor":
            _resp.log_action(ip, "monitor", "responder-crewai", True)
            success = True
        else:
            _resp.log_action(ip, action, "responder-crewai", True)
            success = True

        return {
            "ip": ip,
            "action": action,
            "threat_type": threat_type,
            "confidence": confidence,
            "success": success,
            "mode": "live",
            "timestamp": _now_iso(),
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("Live action %s on %s failed: %s", action, ip, exc)
        return {
            "ip": ip,
            "action": action,
            "success": False,
            "error": str(exc),
            "mode": "live",
            "timestamp": _now_iso(),
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
