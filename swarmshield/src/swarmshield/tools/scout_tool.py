"""
Scout CrewAI Tools
==================
Wraps ScoutAgent methods as CrewAI @tool functions so the Scout
CrewAI Agent can call them during orchestrated task execution.

All tools:
- Accept/return plain strings (JSON-encoded where needed)
- Catch all exceptions and return a JSON error dict instead of raising
- Work without real network traffic (ScoutAgent falls back to synthetic data)
"""

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

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
    logger.warning("crewai not installed — scout tools will not be registered as CrewAI tools.")
    _CREWAI_AVAILABLE = False

    def crewai_tool(name=None, description=None):  # type: ignore[misc]
        """Fallback no-op decorator when crewai is unavailable."""
        def decorator(fn):
            return fn
        return decorator


# ---------------------------------------------------------------------------
# Tool: run_monte_carlo_analysis
# ---------------------------------------------------------------------------

@crewai_tool("run_monte_carlo_analysis")
def run_monte_carlo_analysis(packets_json: str) -> str:
    """
    Analyse a JSON-encoded list of network packet dicts using the Scout
    agent's Monte Carlo engine.

    Input format (JSON array of packet dicts):
      [{"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": 80,
        "protocol": "TCP", "size": 60, "timestamp": 1700000000.0, "is_syn": true}, ...]

    Returns a JSON object with per-source-IP threat findings:
      {"source_ips": [...], "threats": [...], "scan_summary": {...}, "timestamp": "..."}
    """
    try:
        from ..agents.scout import ScoutAgent, _get_all_source_ips, _compute_stats, _monte_carlo_estimate, CONFIDENCE_THRESHOLD, WINDOW_SECONDS

        packets = json.loads(packets_json)
        if not isinstance(packets, list):
            return json.dumps({"error": "packets_json must be a JSON array"})

        scout = ScoutAgent(name="Scout", agent_id="scout-crewai")
        threats = []
        scan_summary = {}
        src_ips = _get_all_source_ips(packets)

        for ip in src_ips:
            stats = _compute_stats(packets, ip, WINDOW_SECONDS)
            mc = _monte_carlo_estimate(stats, thresholds=scout.thresholds)
            confidence = mc.get("top_confidence", 0.0)
            threat_type = mc.get("top_threat", "normal")
            level = (
                "high"   if confidence >= 0.75 else
                "medium" if confidence >= 0.50 else
                "low"    if confidence >= 0.25 else
                "normal"
            )
            scan_summary[ip] = {
                "stats": stats,
                "monte_carlo": mc,
                "threat_level": level,
            }
            if confidence > CONFIDENCE_THRESHOLD and threat_type != "normal":
                from ..agents.scout import _format_report
                report = _format_report(ip, stats, mc, scout.agent_id)
                threats.append(report)

        return json.dumps({
            "source_ips": src_ips,
            "threats": threats,
            "scan_summary": scan_summary,
            "timestamp": _now_iso(),
        }, default=str)

    except Exception as exc:  # noqa: BLE001
        logger.exception("run_monte_carlo_analysis error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Tool: scan_network_for_threats
# ---------------------------------------------------------------------------

@crewai_tool("scan_network_for_threats")
def scan_network_for_threats(window_seconds: str = "10") -> str:
    """
    Run a full Scout detection cycle using synthetic (or live, if configured)
    network traffic data.  Returns a JSON list of detected threat reports.

    Each threat report has keys:
      agent_id, event, source_ip, attack_type, confidence,
      stats, monte_carlo, timestamp

    Pass window_seconds as a string (e.g. "10") to control the analysis window.
    """
    try:
        from ..agents.scout import ScoutAgent
        ws = int(window_seconds) if str(window_seconds).isdigit() else 10
        scout = ScoutAgent(name="Scout", agent_id="scout-crewai")
        threats = scout.detect_anomalies(window_seconds=ws)
        result = json.dumps({
            "threats_detected": len(threats),
            "threats": threats,
            "timestamp": _now_iso(),
        }, default=str)
        # A2A publish
        from ..utils.message_bus import TOPIC_SCOUT_TICK
        _bus_publish(TOPIC_SCOUT_TICK, {
            "buffer_size": len(threats),
            "confirmed_threats": [t.get("source_ip", "") for t in threats],
            "early_warnings": [],
            "per_ip": {t.get("source_ip", ""): t for t in threats},
            "tick_time": _now_iso(),
            "source": "crewai:scan_network_for_threats",
        })
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("scan_network_for_threats error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Tool: simulate_attack_traffic
# ---------------------------------------------------------------------------

@crewai_tool("simulate_attack_traffic")
def simulate_attack_traffic(attack_type: str = "ddos") -> str:
    """
    Generate synthetic attack traffic of the specified type and analyse it
    via the Scout Monte Carlo engine.

    Supported attack_type values:
      "ddos"      — SYN-flood / DDoS pattern from 10.0.0.1
      "port_scan" — horizontal port scan from 10.0.0.2
      "mixed"     — both ddos and port_scan sources (default simulation)
      "normal"    — only benign traffic from 10.0.0.3

    Returns the Monte Carlo analysis results as JSON.
    """
    try:
        from ..agents.scout import (
            ScoutAgent, _simulate_packets, _get_all_source_ips,
            _compute_stats, _monte_carlo_estimate, _format_report,
            CONFIDENCE_THRESHOLD, WINDOW_SECONDS,
        )

        attack_type = (attack_type or "mixed").lower().strip()
        packets = _simulate_packets(WINDOW_SECONDS)

        # Filter to requested traffic type
        if attack_type == "ddos":
            packets = [p for p in packets if p.get("src_ip") in ("10.0.0.1", "10.0.0.3")]
        elif attack_type == "port_scan":
            packets = [p for p in packets if p.get("src_ip") in ("10.0.0.2", "10.0.0.3")]
        elif attack_type == "normal":
            packets = [p for p in packets if p.get("src_ip") == "10.0.0.3"]
        # "mixed" → keep all

        scout = ScoutAgent(name="Scout", agent_id="scout-crewai")
        src_ips = _get_all_source_ips(packets)
        threats = []

        for ip in src_ips:
            stats = _compute_stats(packets, ip, WINDOW_SECONDS)
            mc = _monte_carlo_estimate(stats, thresholds=scout.thresholds)
            if mc.get("top_confidence", 0.0) > CONFIDENCE_THRESHOLD and mc.get("top_threat") != "normal":
                report = _format_report(ip, stats, mc, scout.agent_id)
                threats.append(report)

        result = json.dumps({
            "attack_type_simulated": attack_type,
            "packets_generated": len(packets),
            "threats_detected": len(threats),
            "threats": threats,
            "timestamp": _now_iso(),
        }, default=str)
        # A2A publish
        from ..utils.message_bus import TOPIC_SCOUT_TICK, TOPIC_SCOUT_EARLY_WARNING
        _bus_publish(TOPIC_SCOUT_TICK, {
            "buffer_size": len(packets),
            "confirmed_threats": [t.get("source_ip", "") for t in threats],
            "early_warnings": [],
            "per_ip": {t.get("source_ip", ""): t for t in threats},
            "tick_time": _now_iso(),
            "source": "crewai:simulate_attack_traffic",
        })
        if threats:
            _bus_publish(TOPIC_SCOUT_EARLY_WARNING, {
                "ips": [t.get("source_ip", "") for t in threats],
                "per_ip": {t.get("source_ip", ""): t for t in threats},
                "tick_time": _now_iso(),
            })
        return result

    except Exception as exc:  # noqa: BLE001
        logger.exception("simulate_attack_traffic error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
