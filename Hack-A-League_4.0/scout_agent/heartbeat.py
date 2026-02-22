"""
heartbeat.py
------------
Periodic heartbeat sender for the SwarmShield Scout Agent.

Purpose
-------
The Scout Agent announces its liveness and current threat level to the
SwarmShield Coordinator at a configurable interval.  The Coordinator
uses missing heartbeats to detect crashed or partitioned agents and can
then reassign scanning duties.

Heartbeat Payload
-----------------
::

    {
        "schema_version": "1.0",
        "agent_id":        "<str>",
        "agent_type":      "scout",
        "timestamp":       <epoch float>,
        "timestamp_iso":   "<ISO 8601>",
        "sequence":        <int>,          # monotonically increasing counter
        "status":          "ok" | "degraded" | "stopping",
        "threat_level":    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "overall_risk":    <float 0..1>,
        "metrics": {
            "pkt_rate":        <float>,     # packets/s in current window
            "unique_src_ips":  <int>,
            "queue_size":      <int>,       # packet capture queue depth
            "reports_sent":    <int>,
            "reports_failed":  <int>,
        },
        "flask_port":      <int>,           # config-server port for discovery
    }

Transport
---------
Heartbeats are sent as HTTP POST to ``<coordinator_url>/heartbeat``.
On failure the sender logs a warning and retries on the next tick
(no back-off; heartbeats are low-value fire-and-forget).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Callable, Dict, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

HEARTBEAT_SCHEMA_VERSION = "1.0"


class HeartbeatSender:
    """
    Sends periodic heartbeat messages to the SwarmShield Coordinator.

    Parameters
    ----------
    coordinator_url : str
        Base URL of the Coordinator, e.g. ``"http://coordinator:6000"``.
    agent_id : str
        Logical name of this Scout instance.
    interval : float
        Seconds between heartbeat transmissions (default 10 s).
    timeout : float
        HTTP request timeout in seconds (default 3 s).
    flask_port : int
        Port of the Scout's Flask config server (included for discovery).
    metrics_callback : callable, optional
        Zero-argument callable that returns a ``dict`` of live metrics to
        embed in the heartbeat payload.  Called on every tick.

    Usage
    -----
    ::

        def get_metrics():
            return {
                "pkt_rate": stats.compute().pkt_rate,
                "queue_size": capture.queue_size,
                ...
            }

        hb = HeartbeatSender(
            coordinator_url="http://localhost:6000",
            agent_id="scout-1",
            interval=10,
            metrics_callback=get_metrics,
        )
        hb.start()
        ...
        hb.stop()
    """

    def __init__(
        self,
        coordinator_url: str = "http://localhost:6000",
        agent_id: str = "scout-1",
        interval: float = 10.0,
        timeout: float = 3.0,
        flask_port: int = 5100,
        metrics_callback: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> None:
        self.coordinator_url = coordinator_url.rstrip("/")
        self.agent_id = agent_id
        self.interval = interval
        self.timeout = timeout
        self.flask_port = flask_port
        self.metrics_callback = metrics_callback

        self._sequence = 0
        self._current_threat_level = "LOW"
        self._current_risk = 0.0
        self._status = "ok"

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self._stats = {
            "total_sent": 0,
            "total_failed": 0,
            "last_sent_at": None,
            "last_ack_at": None,
        }

        logger.info(
            "HeartbeatSender initialised — coordinator=%s  interval=%.1fs  agent=%s",
            self.coordinator_url,
            self.interval,
            self.agent_id,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the heartbeat background thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("HeartbeatSender.start() called but already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="scout-heartbeat"
        )
        self._thread.start()
        logger.info("Heartbeat thread started (interval=%.1fs).", self.interval)

    def stop(self) -> None:
        """Stop the heartbeat loop gracefully and send a final 'stopping' beat."""
        self._set_status("stopping")
        self._send_once()            # best-effort final beat
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info(
            "Heartbeat stopped. sent=%d  failed=%d",
            self._stats["total_sent"],
            self._stats["total_failed"],
        )

    # ------------------------------------------------------------------
    # Runtime state setters (called by scout_agent main loop)
    # ------------------------------------------------------------------

    def update_threat(self, threat_level: str, overall_risk: float) -> None:
        """Update the threat level/risk broadcasted in future heartbeats."""
        with self._lock:
            self._current_threat_level = threat_level
            self._current_risk = overall_risk

    def set_degraded(self) -> None:
        """Mark agent as degraded (e.g. capture errors, queue overflow)."""
        self._set_status("degraded")

    def set_ok(self) -> None:
        self._set_status("ok")

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_status(self, status: str) -> None:
        with self._lock:
            self._status = status

    def _run_loop(self) -> None:
        """Main heartbeat loop — sleeps between ticks."""
        while not self._stop_event.is_set():
            self._send_once()
            self._stop_event.wait(timeout=self.interval)

    def _build_payload(self) -> dict:
        with self._lock:
            seq = self._sequence
            self._sequence += 1
            threat_level = self._current_threat_level
            overall_risk = self._current_risk
            status = self._status

        now = time.time()
        metrics: dict = {}
        if self.metrics_callback:
            try:
                metrics = self.metrics_callback() or {}
            except Exception as exc:
                logger.debug("metrics_callback error: %s", exc)

        return {
            "schema_version": HEARTBEAT_SCHEMA_VERSION,
            "agent_id": self.agent_id,
            "agent_type": "scout",
            "timestamp": now,
            "timestamp_iso": _epoch_to_iso(now),
            "sequence": seq,
            "status": status,
            "threat_level": threat_level,
            "overall_risk": round(overall_risk, 4),
            "metrics": metrics,
            "flask_port": self.flask_port,
        }

    def _send_once(self) -> None:
        """Build and POST one heartbeat payload to the Coordinator."""
        payload = self._build_payload()
        url = self.coordinator_url + "/heartbeat"
        body = json.dumps(payload, default=str).encode("utf-8")

        try:
            req = Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Agent-Id": self.agent_id,
                    "X-Sequence": str(payload["sequence"]),
                },
                method="POST",
            )
            with urlopen(req, timeout=self.timeout) as resp:
                _ = resp.read()   # drain response body

            with self._lock:
                self._stats["total_sent"] += 1
                self._stats["last_sent_at"] = time.time()
                self._stats["last_ack_at"] = time.time()

            logger.debug(
                "Heartbeat #%d sent — threat=%s  risk=%.3f",
                payload["sequence"],
                payload["threat_level"],
                payload["overall_risk"],
            )

        except (URLError, OSError, TimeoutError) as exc:
            with self._lock:
                self._stats["total_failed"] += 1
                self._stats["last_sent_at"] = time.time()

            logger.warning(
                "Heartbeat #%d failed (coordinator unreachable): %s",
                payload["sequence"],
                exc,
            )

        except Exception as exc:
            with self._lock:
                self._stats["total_failed"] += 1
            logger.error("Unexpected heartbeat error: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _epoch_to_iso(ts: float) -> str:
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")
