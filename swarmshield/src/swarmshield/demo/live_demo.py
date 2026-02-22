"""
SwarmShield Live Demo
=====================
Real-time DDoS / threat detection demo driven by live network traffic.

This is the **single entry point** for the demo.  Run it on the machine
that is receiving the simulated attack traffic:

    # Requires root for live packet capture
    sudo python -m swarmshield.demo.live_demo

    # Custom interface and tick interval
    sudo python -m swarmshield.demo.live_demo --interface eth0 --tick 5

    # No live capture — use synthetic traffic (dev/test mode, no root needed)
    python -m swarmshield.demo.live_demo --simulate

Press Ctrl-C to stop everything cleanly.

Architecture
------------
::

    LivePacketCapture (scapy, background thread)
          │  drain(window_seconds) → list[dict]
          ▼
    ScoutAgent.run_rolling_inference()
          │  on_tick callback  → pretty-prints tick summary to console
          │  on_early_warning  → calls Analyzer.pre_assess_risk()
          │                        → POST /preemptive_action  (Responder)
          │  rolling_tick confirms → POST /verdict            (Responder)
          ▼
    ResponderAgent Flask server (background thread, localhost:5000)
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

# ---------------------------------------------------------------------------
# Logging — pretty console output for demo
# ---------------------------------------------------------------------------
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt = "%H:%M:%S",
)
logger = logging.getLogger("swarmshield.demo")

# ---------------------------------------------------------------------------
# Suppress noisy sub-module loggers during demo (keep it readable)
# ---------------------------------------------------------------------------
for _noisy in ("scapy.runtime", "scapy.loading", "urllib3", "werkzeug"):
    logging.getLogger(_noisy).setLevel(logging.ERROR)


# ===========================================================================
# Banner
# ===========================================================================

_BANNER = r"""
  ____                              ____  _     _      _     _
 / ___|_      ____ _ _ __ _ __ ___|  _ \| |__ (_) ___| | __| |
 \___ \ \ /\ / / _` | '__| '_ ` _ \ |_) | '_ \| |/ _ \ |/ _` |
  ___) \ V  V / (_| | |  | | | | | |  __/| | | | |  __/ | (_| |
 |____/ \_/\_/ \__,_|_|  |_| |_| |_|_|   |_| |_|_|\___|_|\__,_|

              Multi-Agent Cybersecurity Defense System
         [ LIVE DEMO — press Ctrl-C to stop everything ]
"""


# ===========================================================================
# Responder Flask server (background thread)
# ===========================================================================

def _start_responder(host: str = "127.0.0.1", port: int = 5000) -> threading.Thread:
    """Start the Responder Flask app in a background daemon thread."""
    # Import here to avoid circular issues at module level
    from swarmshield.agents.responder import app  # type: ignore[import]

    def _run():
        app.run(host=host, port=port, use_reloader=False, threaded=True)

    t = threading.Thread(target=_run, name="swarmshield-responder", daemon=True)
    t.start()
    logger.info("Responder Flask server starting on http://%s:%d", host, port)
    # Give Flask a moment to bind
    time.sleep(1.0)
    return t


# ===========================================================================
# Anticipatory callback
# ===========================================================================

def _build_early_warning_handler(
    analyzer,
    responder_url: str,
) -> Any:
    """
    Returns the ``on_early_warning`` callback for Scout's rolling inference.

    When Scout fires this, every early-warning IP goes through:
      1. Analyzer.pre_assess_risk()
      2. POST /preemptive_action on the Responder (with safety gate)
    """

    def _on_early_warning(ips: List[str], per_ip: Dict) -> None:
        if not ips:
            return
        logger.info(
            "⚡ EARLY WARNING — %d IP(s): %s",
            len(ips), ", ".join(ips),
        )

        # Build a minimal tick_result subset containing ONLY the early-warning
        # IPs so Analyzer doesn't process already-confirmed threats here.
        synthetic_tick = {
            "tick_time":         datetime.now(timezone.utc).isoformat(),
            "per_ip":            {ip: per_ip[ip] for ip in ips if ip in per_ip},
            "early_warnings":    ips,
            "confirmed_threats": [],
        }

        try:
            pre = analyzer.pre_assess_risk(synthetic_tick)
        except Exception as exc:
            logger.error("Analyzer.pre_assess_risk failed: %s", exc)
            return

        for action in pre.get("preemptive_actions", []):
            payload = {
                "source_ip":          action["source_ip"],
                "alert_level":        action["alert_level"],
                "current_confidence": action["current_confidence"],
                "predicted_confidence": action["predicted_confidence"],
                "recommended_action": action["recommended_action"],
                "threat_type":        action.get("threat_type", "unknown"),
                "trend_direction":    action.get("trend_direction", "stable"),
                "reasoning":          action.get("reasoning", ""),
                "agent_id":           action.get("agent_id", "analyzer-1"),
            }
            try:
                resp = requests.post(
                    f"{responder_url}/preemptive_action",
                    json    = payload,
                    timeout = 15,
                )
                result = resp.json()
                status = result.get("status", "?")
                if status == "ok":
                    logger.info(
                        "  ✅ pre-emptive %s applied to %s",
                        result.get("action_taken"), action["source_ip"],
                    )
                elif status == "gate_rejected":
                    logger.info(
                        "  🛡  gate rejected %s → %s",
                        action["source_ip"], result.get("reason", ""),
                    )
                else:
                    logger.warning(
                        "  ⚠  unexpected responder status '%s' for %s",
                        status, action["source_ip"],
                    )
            except requests.RequestException as exc:
                logger.error(
                    "  POST /preemptive_action failed for %s: %s",
                    action["source_ip"], exc,
                )

    return _on_early_warning


# ===========================================================================
# Tick summary callback
# ===========================================================================

def _build_tick_handler(responder_url: str) -> Any:
    """
    Returns the ``on_tick`` callback.

    For confirmed threats, posts a ``/verdict`` to the Responder so the
    full reactive pipeline still runs alongside the anticipatory branch.
    """

    def _on_tick(result: Dict) -> None:
        ew = len(result.get("early_warnings", []))
        ct = len(result.get("confirmed_threats", []))
        buf = result.get("buffer_size", 0)
        logger.info(
            "── TICK ──  buffer=%d pkts  early_warnings=%d  confirmed=%d",
            buf, ew, ct,
        )

        for ip in result.get("confirmed_threats", []):
            data = result["per_ip"].get(ip, {})
            mc   = data.get("monte_carlo", {})
            # Map rolling_tick MC keys to the verdict endpoint contract
            threat_type = mc.get("top_threat", "DDoS")
            confidence  = mc.get("top_confidence", 1.0)
            # Build a minimal SHAP-style explanation from the stats we have
            stats   = data.get("stats", {})
            shap_ex = (
                f"pps={stats.get('packets_per_second', 0):.0f}  "
                f"bps={stats.get('bytes_per_second', 0):.0f}  "
                f"syn={stats.get('syn_count', 0)}  "
                f"conf={confidence:.2f}"
            )
            payload = {
                "source_ip":            ip,
                "predicted_attack_type": threat_type,
                "confidence":           confidence,
                "shap_explanation":     shap_ex,
                "recommended_action":   mc.get("recommended_action", "block"),
                "agent_id":             "scout-1",
            }
            try:
                resp = requests.post(
                    f"{responder_url}/verdict",
                    json    = payload,
                    timeout = 15,
                )
                r = resp.json()
                logger.info(
                    "  🚨 CONFIRMED %s → action=%s  success=%s",
                    ip, r.get("action_taken"), r.get("success"),
                )
            except requests.RequestException as exc:
                logger.error("POST /verdict failed for %s: %s", ip, exc)

    return _on_tick


# ===========================================================================
# Main entry point
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SwarmShield live demo — real-time DDoS detection and response",
    )
    parser.add_argument(
        "--interface", "-i",
        default = None,
        help    = "Network interface to sniff (e.g. eth0, lo). "
                  "Default: all interfaces.",
    )
    parser.add_argument(
        "--filter", "-f",
        default = "ip",
        help    = "BPF capture filter (default: 'ip').",
    )
    parser.add_argument(
        "--tick", "-t",
        type    = float,
        default = 5.0,
        help    = "Seconds between Scout inference ticks (default: 5).",
    )
    parser.add_argument(
        "--horizon",
        type    = float,
        default = 60.0,
        help    = "Rolling window width in seconds (default: 60).",
    )
    parser.add_argument(
        "--responder-host",
        default = "127.0.0.1",
        help    = "Host to bind Responder Flask server on (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--responder-port",
        type    = int,
        default = 5000,
        help    = "Port for Responder Flask server (default: 5000).",
    )
    parser.add_argument(
        "--simulate",
        action  = "store_true",
        help    = "Use synthetic (simulated) traffic instead of live capture. "
                  "No root or Scapy required.",
    )
    args = parser.parse_args()

    print(_BANNER)

    # ----------------------------------------------------------------
    # 1. Start Responder Flask server
    # ----------------------------------------------------------------
    responder_url = f"http://{args.responder_host}:{args.responder_port}"
    _start_responder(host=args.responder_host, port=args.responder_port)

    # ----------------------------------------------------------------
    # 2. Optionally start live packet capture
    # ----------------------------------------------------------------
    cap = None
    packet_source = None

    if args.simulate:
        logger.info(
            "Running in SIMULATE mode — Scout will generate synthetic traffic."
        )
    else:
        try:
            from swarmshield.tools.packet_capture_tool import LivePacketCapture
            cap = LivePacketCapture(
                interface  = args.interface,
                bpf_filter = args.filter,
            )
            cap.start()
            packet_source = cap.drain
            logger.info(
                "Live capture active on interface=%s",
                args.interface or "ALL",
            )
        except RuntimeError as exc:
            logger.error(
                "Cannot start live capture: %s\n"
                "Hint: re-run with sudo, or use --simulate for synthetic traffic.",
                exc,
            )
            sys.exit(1)

    # ----------------------------------------------------------------
    # 3. Initialise agents
    # ----------------------------------------------------------------
    from swarmshield.agents.scout    import ScoutAgent
    from swarmshield.agents.analyzer import AnalyzerAgent

    scout    = ScoutAgent(packet_source=packet_source)
    analyzer = AnalyzerAgent()

    # ----------------------------------------------------------------
    # 4. Wire callbacks
    # ----------------------------------------------------------------
    on_early_warning = _build_early_warning_handler(analyzer, responder_url)
    on_tick          = _build_tick_handler(responder_url)

    # ----------------------------------------------------------------
    # 5. Run rolling inference (blocks until Ctrl-C)
    # ----------------------------------------------------------------
    logger.info(
        "Starting rolling inference: tick=%.1fs  horizon=%.1fs",
        args.tick, args.horizon,
    )
    logger.info("Press Ctrl-C to stop.")

    try:
        scout.run_rolling_inference(
            tick_seconds     = args.tick,
            horizon_seconds  = args.horizon,
            on_tick          = on_tick,
            on_early_warning = on_early_warning,
        )
    except KeyboardInterrupt:
        pass  # run_rolling_inference handles this internally too

    # ----------------------------------------------------------------
    # 6. Clean shutdown
    # ----------------------------------------------------------------
    logger.info("Shutting down SwarmShield demo…")
    if cap is not None:
        cap.stop()
    logger.info("Done. Goodbye.")


if __name__ == "__main__":
    main()
