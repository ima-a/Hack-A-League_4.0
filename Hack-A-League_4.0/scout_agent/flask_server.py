"""
flask_server.py
---------------
Flask HTTP server embedded in the Scout Agent for receiving runtime
configuration updates from the SwarmShield Coordinator or Evolver Agent.

Endpoints
---------
GET  /health
    Liveness / readiness probe.
    Response: {"status": "ok", "agent_id": str, "uptime_seconds": float}

GET  /status
    Return current Scout Agent operational statistics.
    Response: {snapshot of agent stats, reporter stats, capture stats}

POST /config
    Push a partial config update (JSON body). Supported keys:

    ``capture.interface``      – change capture NIC
    ``capture.bpf_filter``     – change BPF filter expression
    ``stats.window_seconds``   – resize sliding window
    ``monte_carlo.n_simulations``   – change MC trial count
    ``monte_carlo.pattern.<name>.<field>``  – update a pattern weight
    ``reporter.analyzer_url``  – change Analyzer endpoint
    ``agent.report_interval``  – how often (s) to generate reports
    ``agent.alert_threshold``  – risk score that triggers immediate alert
    Response: {"status": "ok", "applied": [<keys>], "ignored": [<keys>]}

POST /reset
    Reset traffic stats window (useful after a config change).
    Response: {"status": "ok"}

Design Notes
------------
- Runs in a background daemon thread; the main agent loop is unaffected.
- All shared objects are injected at construction time via ``context``.
- Thread-safe config mutation is done through the objects' own locks.
- Depends only on Flask (``pip install flask``); no Scapy or ML libs needed.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    from flask import Flask, jsonify, request  # type: ignore
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    logger.warning(
        "Flask is not installed. FlaskServer will be disabled. "
        "Install with: pip install flask"
    )


class FlaskServer:
    """
    Lightweight Flask HTTP server that accepts runtime configuration pushes
    for all components of the Scout Agent.

    Parameters
    ----------
    host : str
        Bind address (default ``"0.0.0.0"`` to accept external connections).
    port : int
        TCP port to listen on (default ``5100``).
    context : dict
        Shared references to live agent components, keyed by component name.
        Expected keys (all optional):

        - ``"capture"``     – :class:`~packet_capture.PacketCapture` instance
        - ``"stats"``       – :class:`~traffic_stats.TrafficStats` instance
        - ``"mc"``          – :class:`~monte_carlo.MonteCarloEstimator` instance
        - ``"reporter"``    – :class:`~reporter.Reporter` instance
        - ``"agent_config"`` – mutable :class:`AgentConfig` dataclass / dict

    agent_id : str
        Identifier embedded in health-check responses.
    start_time : float
        Unix timestamp at which the agent started (for uptime calculation).
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5100,
        context: Optional[Dict[str, Any]] = None,
        agent_id: str = "scout-1",
        start_time: Optional[float] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.context = context or {}
        self.agent_id = agent_id
        self.start_time = start_time or time.time()

        self._thread: Optional[threading.Thread] = None
        self._app: Optional[Any] = None   # Flask app
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the Flask server in a background daemon thread."""
        if not FLASK_AVAILABLE:
            logger.warning("Flask unavailable — config server disabled.")
            return

        self._app = self._build_app()
        self._running = True
        self._thread = threading.Thread(
            target=self._run_server, daemon=True, name="scout-flask"
        )
        self._thread.start()
        logger.info(
            "Scout config server started on http://%s:%d", self.host, self.port
        )

    def stop(self) -> None:
        """Signal the server to stop (best-effort; relies on werkzeug shutdown)."""
        self._running = False
        logger.info("Scout config server stopping.")

    # ------------------------------------------------------------------
    # Flask app construction
    # ------------------------------------------------------------------

    def _build_app(self) -> "Flask":
        app = Flask(__name__)
        app.logger.setLevel(logging.WARNING)   # suppress Flask's noisy HTTP log

        # Silence Werkzeug request logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        # ----------------------------------------------------------------
        # GET /health
        # ----------------------------------------------------------------
        @app.route("/health", methods=["GET"])
        def health():
            return jsonify({
                "status": "ok",
                "agent_id": self.agent_id,
                "uptime_seconds": round(time.time() - self.start_time, 2),
            })

        # ----------------------------------------------------------------
        # GET /status
        # ----------------------------------------------------------------
        @app.route("/status", methods=["GET"])
        def status():
            payload: dict = {
                "agent_id": self.agent_id,
                "uptime_seconds": round(time.time() - self.start_time, 2),
            }

            cap = self.context.get("capture")
            if cap:
                payload["capture"] = cap.get_stats()

            rep = self.context.get("reporter")
            if rep:
                payload["reporter"] = rep.get_stats()

            agent_cfg = self.context.get("agent_config")
            if agent_cfg:
                payload["agent_config"] = (
                    agent_cfg if isinstance(agent_cfg, dict) else vars(agent_cfg)
                )

            mc = self.context.get("mc")
            if mc:
                payload["monte_carlo"] = {
                    "n_simulations": mc.n_simulations,
                    "pattern_count": len(mc.patterns),
                }

            return jsonify(payload)

        # ----------------------------------------------------------------
        # POST /config
        # ----------------------------------------------------------------
        @app.route("/config", methods=["POST"])
        def update_config():
            if not request.is_json:
                return jsonify({"error": "Content-Type must be application/json"}), 400

            updates: dict = request.get_json(force=True)
            applied: list = []
            ignored: list = []

            for key, value in updates.items():
                parts = key.split(".")
                handled = self._apply_config_key(parts, value)
                if handled:
                    applied.append(key)
                    logger.info("Config update applied: %s = %r", key, value)
                else:
                    ignored.append(key)
                    logger.warning("Config update ignored (unknown key): %s", key)

            return jsonify({"status": "ok", "applied": applied, "ignored": ignored})

        # ----------------------------------------------------------------
        # POST /reset
        # ----------------------------------------------------------------
        @app.route("/reset", methods=["POST"])
        def reset_stats():
            stats = self.context.get("stats")
            if stats and hasattr(stats, "reset"):
                stats.reset()
                logger.info("TrafficStats window reset via /reset endpoint.")
                return jsonify({"status": "ok", "message": "Traffic stats window cleared."})
            return jsonify({"status": "ok", "message": "No stats component found."}), 200

        return app

    # ------------------------------------------------------------------
    # Config key dispatcher
    # ------------------------------------------------------------------

    def _apply_config_key(self, parts: list, value: Any) -> bool:
        """
        Dispatch a dotted config key to the appropriate component.
        Returns True if the key was recognised and applied.
        """
        if not parts:
            return False

        namespace = parts[0]

        # ------ capture.* ------
        if namespace == "capture" and len(parts) == 2:
            cap = self.context.get("capture")
            if cap is None:
                return False
            attr = parts[1]
            if attr == "interface":
                cap.interface = str(value)
                return True
            if attr == "bpf_filter":
                cap.bpf_filter = str(value)
                return True

        # ------ stats.* ------
        elif namespace == "stats" and len(parts) == 2:
            stats = self.context.get("stats")
            if stats is None:
                return False
            attr = parts[1]
            if attr == "window_seconds":
                try:
                    stats.window_seconds = float(value)
                    return True
                except (TypeError, ValueError):
                    return False

        # ------ monte_carlo.* ------
        elif namespace == "monte_carlo" and len(parts) >= 2:
            mc = self.context.get("mc")
            if mc is None:
                return False

            sub = parts[1]
            if sub == "n_simulations" and len(parts) == 2:
                try:
                    mc.n_simulations = int(value)
                    return True
                except (TypeError, ValueError):
                    return False

            # monte_carlo.pattern.<name>.<field>
            if sub == "pattern" and len(parts) == 4:
                pattern_name = parts[2]
                field_name = parts[3]
                try:
                    val = float(value)
                except (TypeError, ValueError):
                    val = value
                return mc.update_pattern(pattern_name, **{field_name: val})

        # ------ reporter.* ------
        elif namespace == "reporter" and len(parts) == 2:
            rep = self.context.get("reporter")
            if rep is None:
                return False
            attr = parts[1]
            if attr in ("analyzer_url", "timeout", "max_retries", "log_reports"):
                try:
                    if attr == "analyzer_url":
                        rep.analyzer_url = str(value).rstrip("/")
                    elif attr in ("timeout", "retry_base_delay"):
                        setattr(rep, attr, float(value))
                    elif attr == "max_retries":
                        rep.max_retries = int(value)
                    elif attr == "log_reports":
                        rep.log_reports = bool(value)
                    return True
                except (TypeError, ValueError):
                    return False

        # ------ agent.* ------
        elif namespace == "agent" and len(parts) == 2:
            cfg = self.context.get("agent_config")
            if cfg is None:
                return False
            attr = parts[1]
            try:
                if isinstance(cfg, dict):
                    cfg[attr] = float(value) if "." in str(value) else value
                else:
                    setattr(cfg, attr, value)
                return True
            except (TypeError, AttributeError):
                return False

        return False

    # ------------------------------------------------------------------
    # Runner
    # ------------------------------------------------------------------

    def _run_server(self) -> None:
        try:
            self._app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True,
            )
        except Exception as exc:
            logger.error("Flask server error: %s", exc)
