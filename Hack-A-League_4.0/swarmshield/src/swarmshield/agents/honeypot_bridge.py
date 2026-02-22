"""
HoneypotBridge
==============
Lightweight HTTP receiver that closes the attacker-feedback loop between
your friend's honeypot and SwarmShield's Mahoraga evolution engine.

How it fits in the overall architecture
----------------------------------------
::

    Attacker Machine
         │
         │  (redirected by Responder DNAT rule)
         ▼
    Friend's Honeypot  ──POST /honeypot_event──►  HoneypotBridge (this file)
                                                         │
                                              Mahoraga.record_outcome()
                                                         │
                                              mahoraga_outcomes.jsonl
                                                         │
                                              Mahoraga.evolve()  (periodic)
                                                         │
                                           Scout thresholds auto-updated

What the friend's honeypot must do
------------------------------------
After it captures an attacker session, it makes ONE HTTP POST:

    POST http://<swarmshield-machine-ip>:5001/honeypot_event
    Content-Type: application/json

    {
        "source_ip":    "203.0.113.50",       # attacker IP (required)
        "attack_type":  "DDoS",               # DDoS | PortScan | Exfiltration | Other
        "confidence":   0.95,                 # how sure the honeypot is (0–1, default 0.9)
        "action_taken": "redirect_to_honeypot",  # what SwarmShield did

        # Optional traffic stats — used by Mahoraga for richer evolution.
        # Fill in as many as the honeypot can observe.
        "stats": {
            "packets_per_second": 1200,
            "bytes_per_second":   600000,
            "unique_dest_ips":    2,
            "syn_count":          800,
            "port_entropy":       0.5,
            "window_seconds":     10
        }
    }

Endpoints
---------
POST /honeypot_event   Receive one attacker observation (described above)
GET  /honeypot_events  List recent events (last N, default 50)
GET  /honeypot_health  Liveness probe

Running standalone (for testing the bridge alone)
--------------------------------------------------
    PYTHONPATH=src python -m swarmshield.agents.honeypot_bridge

In normal use the bridge is started by live_demo.py automatically.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (all overridable via env vars)
# ---------------------------------------------------------------------------
BRIDGE_HOST     = os.environ.get("HONEYPOT_BRIDGE_HOST", "0.0.0.0")
BRIDGE_PORT     = int(os.environ.get("HONEYPOT_BRIDGE_PORT", "5001"))
BRIDGE_AGENT_ID = os.environ.get("HONEYPOT_BRIDGE_ID",   "honeypot-bridge-1")

# Keep the last N events in memory for the /honeypot_events endpoint
_MEMORY_BUFFER_SIZE = int(os.environ.get("HONEYPOT_MEMORY_EVENTS", "500"))

# Project root storage (same convention as the rest of SwarmShield)
_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", "..", ".."))
HP_LOG_FILE  = os.path.join(PROJECT_ROOT, "honeypot_events.jsonl")

# ---------------------------------------------------------------------------
# In-memory event buffer (thread-safe deque)
# ---------------------------------------------------------------------------
_event_buffer: deque = deque(maxlen=_MEMORY_BUFFER_SIZE)
_buffer_lock  = threading.Lock()

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_stats() -> Dict[str, Any]:
    """Minimal stats dict used when the honeypot doesn't send detailed stats."""
    return {
        "packets_per_second": 0,
        "bytes_per_second":   0,
        "unique_dest_ips":    1,
        "syn_count":          0,
        "port_entropy":       0.0,
        "window_seconds":     10,
    }


def _record_to_mahoraga(event: Dict[str, Any]) -> None:
    """
    Feed an observed honeypot event to Mahoraga's outcome recorder.

    This is the core of the feedback loop: every time an attacker is
    observed in the honeypot, Mahoraga gets a confirmed ground-truth label
    to use in the next evolution run.

    Import is deferred to avoid circular dependencies at module load.
    """
    try:
        from swarmshield.agents.evolver import Mahoraga  # type: ignore[import]
        m = Mahoraga()
        m.record_outcome(
            source_ip           = event["source_ip"],
            stats               = event.get("stats") or _default_stats(),
            attack_type         = event.get("attack_type", "Unknown"),
            confidence          = float(event.get("confidence", 0.90)),
            action_taken        = event.get("action_taken", "redirect_to_honeypot"),
            enforcement_success = True,
        )
        logger.info(
            "Mahoraga outcome recorded: %s  attack=%s  conf=%.2f",
            event["source_ip"],
            event.get("attack_type", "Unknown"),
            float(event.get("confidence", 0.90)),
        )
    except Exception as exc:
        logger.error("Failed to record outcome to Mahoraga: %s", exc)


def _persist_event(event: Dict[str, Any]) -> None:
    """Append event to the persistent JSONL log on disk."""
    try:
        with open(HP_LOG_FILE, "a") as fh:
            fh.write(json.dumps(event) + "\n")
    except OSError as exc:
        logger.error("Could not write honeypot event to disk: %s", exc)


# ===========================================================================
# Flask routes
# ===========================================================================

@app.route("/honeypot_event", methods=["POST"])
def receive_honeypot_event():
    """
    Receive an attacker observation from the honeypot.

    Required field: ``source_ip``
    Recommended:    ``attack_type``, ``confidence``, ``action_taken``
    Optional:       ``stats`` (dict of traffic metrics)

    Returns 200 on success, 400 on missing/invalid payload.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    if "source_ip" not in data:
        return jsonify({"error": "Missing required field: source_ip"}), 400

    # Enrich with timestamp and bridge metadata
    event: Dict[str, Any] = {
        **data,
        "received_at": _now_iso(),
        "bridge_id":   BRIDGE_AGENT_ID,
    }

    # Buffer in memory
    with _buffer_lock:
        _event_buffer.append(event)

    # Persist to disk
    _persist_event(event)

    # Feed Mahoraga's evolution loop (non-blocking)
    t = threading.Thread(
        target=_record_to_mahoraga,
        args=(event,),
        daemon=True,
    )
    t.start()

    logger.info(
        "Honeypot event received: %s  attack=%s  conf=%s",
        event["source_ip"],
        event.get("attack_type", "?"),
        event.get("confidence", "?"),
    )

    return jsonify({
        "status":      "recorded",
        "source_ip":   event["source_ip"],
        "received_at": event["received_at"],
        "bridge_id":   BRIDGE_AGENT_ID,
    }), 200


@app.route("/honeypot_events", methods=["GET"])
def list_honeypot_events():
    """
    Return recent honeypot events.
    Query param: ``?limit=50`` (default 50, max 500).
    """
    try:
        limit = min(int(request.args.get("limit", 50)), _MEMORY_BUFFER_SIZE)
    except ValueError:
        limit = 50

    with _buffer_lock:
        events = list(_event_buffer)[-limit:]

    return jsonify({
        "event_count": len(events),
        "events":      list(reversed(events)),   # most recent first
        "bridge_id":   BRIDGE_AGENT_ID,
    }), 200


@app.route("/honeypot_health", methods=["GET"])
def honeypot_health():
    """Liveness probe."""
    with _buffer_lock:
        buffered = len(_event_buffer)
    return jsonify({
        "status":         "alive",
        "bridge_id":      BRIDGE_AGENT_ID,
        "buffered_events": buffered,
    }), 200


# ===========================================================================
# Standalone entry point  (for testing without live_demo.py)
# ===========================================================================

def run_bridge(
    host: str = BRIDGE_HOST,
    port: int = BRIDGE_PORT,
) -> None:
    """Start the bridge server (blocking)."""
    logger.info("HoneypotBridge starting on %s:%d", host, port)
    app.run(host=host, port=port, use_reloader=False, threaded=True)


if __name__ == "__main__":
    logging.basicConfig(
        level   = logging.INFO,
        format  = "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt = "%H:%M:%S",
    )
    run_bridge()
