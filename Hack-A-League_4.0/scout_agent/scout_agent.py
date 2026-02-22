"""
scout_agent.py
--------------
SwarmShield Scout Agent — all-in-one entry point.

Architecture
------------

                ┌──────────────────────────────────────────────┐
                │              Scout Agent Process             │
                │                                              │
                │  ┌─────────────┐   frames    ┌───────────┐  │
                │  │PacketCapture│ ──────────► │TrafficStat│  │
                │  │  (Scapy)    │             │  s Window │  │
                │  └─────────────┘             └─────┬─────┘  │
                │                                    │snapshot │
                │                             ┌──────▼──────┐  │
                │                             │Monte Carlo  │  │
                │                             │ Estimator   │  │
                │                             └──────┬──────┘  │
                │                                    │estimate │
                │  ┌─────────────┐             ┌──────▼──────┐  │
                │  │HeartbeatSndr│             │  Reporter   │  │
                │  │  (10s tick) │             │  (HTTP POST)│  │
                │  └─────────────┘             └─────────────┘  │
                │  ┌─────────────┐                              │
                │  │Flask Config │ ◄── Coordinator / Evolver   │
                │  │   Server    │                              │
                │  └─────────────┘                              │
                └──────────────────────────────────────────────┘

Main Loop
---------
Every ``report_interval`` seconds the agent:
1.  Drains the :class:`~packet_capture.PacketCapture` queue.
2.  Ingests packets into the :class:`~traffic_stats.TrafficStats` engine.
3.  Computes a :class:`~traffic_stats.TrafficSnapshot`.
4.  Runs the :class:`~monte_carlo.MonteCarloEstimator` to produce a
    :class:`~monte_carlo.ThreatEstimate`.
5.  Sends the report to the Analyzer via :class:`~reporter.Reporter`.
6.  Updates the heartbeat sender with the latest threat level.
7.  Logs key metrics to ``scout_log.txt``.

If ``overall_risk`` crosses ``alert_threshold`` between scheduled report
cycles, an immediate lightweight alert is sent to the Analyzer.

Usage
-----
::

    # Default run (uses env vars or built-in defaults)
    python scout_agent.py

    # With explicit config
    python scout_agent.py --interface eth0 \\
                          --analyzer-url http://analyzer:5001 \\
                          --coordinator-url http://coordinator:6000 \\
                          --report-interval 15 \\
                          --flask-port 5100

Environment Variables
---------------------
SCOUT_AGENT_ID          Logical agent name              (default "scout-1")
SCOUT_INTERFACE         Network interface to sniff      (default "eth0")
SCOUT_BPF_FILTER        BPF capture filter              (default "ip or arp")
SCOUT_ANALYZER_URL      Analyzer base URL               (default "http://localhost:5001")
SCOUT_COORDINATOR_URL   Coordinator base URL            (default "http://localhost:6000")
SCOUT_FLASK_PORT        Config server port              (default 5100)
SCOUT_REPORT_INTERVAL   Report cycle in seconds         (default 30)
SCOUT_ALERT_THRESHOLD   Risk score for instant alert    (default 0.75)
SCOUT_MC_SIMULATIONS    Monte Carlo trial count         (default 500)
SCOUT_WINDOW_SECONDS    Sliding window width in seconds (default 30)
SCOUT_LOG_PATH          Path to log file                (default "scout_log.txt")
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Local module imports
# ---------------------------------------------------------------------------
from packet_capture import PacketCapture
from traffic_stats import TrafficStats
from monte_carlo import MonteCarloEstimator
from reporter import Reporter
from flask_server import FlaskServer
from heartbeat import HeartbeatSender

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

PATTERN_VERSION = "1.0"   # increment when attack_patterns.md is updated

_LOG_FORMAT = "%(asctime)s  [%(levelname)s]  %(name)s — %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


def _configure_logging(log_path: str, level: int = logging.INFO) -> None:
    root = logging.getLogger()
    root.setLevel(level)

    fmt = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # File handler
    try:
        fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError as exc:
        logging.warning("Could not open log file %s: %s", log_path, exc)


logger = logging.getLogger("scout_agent")


# ---------------------------------------------------------------------------
# Agent configuration
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    agent_id: str = "scout-1"
    interface: str = "eth0"
    bpf_filter: str = "ip or arp"
    analyzer_url: str = "http://localhost:5001"
    coordinator_url: str = "http://localhost:6000"
    flask_port: int = 5100
    report_interval: float = 30.0
    alert_threshold: float = 0.75
    n_simulations: int = 500
    window_seconds: float = 30.0
    log_path: str = "scout_log.txt"
    verbose: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _load_config_from_env(cfg: AgentConfig) -> AgentConfig:
    """Override config fields from environment variables."""
    mappings = {
        "SCOUT_AGENT_ID":         ("agent_id",        str),
        "SCOUT_INTERFACE":        ("interface",        str),
        "SCOUT_BPF_FILTER":       ("bpf_filter",       str),
        "SCOUT_ANALYZER_URL":     ("analyzer_url",     str),
        "SCOUT_COORDINATOR_URL":  ("coordinator_url",  str),
        "SCOUT_FLASK_PORT":       ("flask_port",       int),
        "SCOUT_REPORT_INTERVAL":  ("report_interval",  float),
        "SCOUT_ALERT_THRESHOLD":  ("alert_threshold",  float),
        "SCOUT_MC_SIMULATIONS":   ("n_simulations",    int),
        "SCOUT_WINDOW_SECONDS":   ("window_seconds",   float),
        "SCOUT_LOG_PATH":         ("log_path",         str),
    }
    for env_var, (attr, cast) in mappings.items():
        val = os.environ.get(env_var)
        if val is not None:
            try:
                setattr(cfg, attr, cast(val))
            except (TypeError, ValueError) as exc:
                logger.warning("Invalid env %s=%r: %s", env_var, val, exc)
    return cfg


# ---------------------------------------------------------------------------
# Core agent class
# ---------------------------------------------------------------------------

class ScoutAgent:
    """
    Orchestrates all Scout Agent subsystems:
    PacketCapture → TrafficStats → MonteCarloEstimator → Reporter
    plus HeartbeatSender and FlaskServer running as sidecar threads.
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._start_time = time.time()
        self._running = False
        self._last_alert_threat = "LOW"

        # ---- Subsystems ----
        self.capture = PacketCapture(
            interface=config.interface,
            bpf_filter=config.bpf_filter,
        )

        self.stats = TrafficStats(
            window_seconds=config.window_seconds,
        )

        self.mc = MonteCarloEstimator(
            n_simulations=config.n_simulations,
        )

        self.reporter = Reporter(
            analyzer_url=config.analyzer_url,
            agent_id=config.agent_id,
            log_path=config.log_path,
        )

        def _live_metrics() -> dict:
            return {
                "pkt_rate": getattr(self, "_last_pkt_rate", 0.0),
                "unique_src_ips": getattr(self, "_last_unique_src", 0),
                "queue_size": self.capture.queue_size,
                "reports_sent": self.reporter.get_stats().get("total_sent", 0),
                "reports_failed": self.reporter.get_stats().get("total_failed", 0),
            }

        self.heartbeat = HeartbeatSender(
            coordinator_url=config.coordinator_url,
            agent_id=config.agent_id,
            interval=10.0,
            flask_port=config.flask_port,
            metrics_callback=_live_metrics,
        )

        # Shared context for Flask config server
        _context = {
            "capture": self.capture,
            "stats": self.stats,
            "mc": self.mc,
            "reporter": self.reporter,
            "agent_config": config.to_dict(),
        }

        self.flask_server = FlaskServer(
            port=config.flask_port,
            context=_context,
            agent_id=config.agent_id,
            start_time=self._start_time,
        )

        # Internal state for heartbeat metrics callback
        self._last_pkt_rate: float = 0.0
        self._last_unique_src: int = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start all subsystems and enter the main monitoring loop.
        Blocks until :meth:`stop` is called or a signal is received.
        """
        logger.info(
            "=== SwarmShield Scout Agent starting ==="
            "  id=%s  interface=%s  pattern_version=%s",
            self.config.agent_id,
            self.config.interface,
            PATTERN_VERSION,
        )

        self.capture.start()
        self.heartbeat.start()
        self.flask_server.start()
        self._running = True

        logger.info(
            "Scout Agent ready — report_interval=%.0fs  alert_threshold=%.2f"
            "  analyzer=%s  coordinator=%s",
            self.config.report_interval,
            self.config.alert_threshold,
            self.config.analyzer_url,
            self.config.coordinator_url,
        )

        self._main_loop()

    def stop(self) -> None:
        """Gracefully shut down all subsystems."""
        if not self._running:
            return
        logger.info("Scout Agent shutting down…")
        self._running = False
        self.heartbeat.stop()
        self.capture.stop()
        self.flask_server.stop()
        logger.info("Scout Agent stopped.")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _main_loop(self) -> None:
        """Execute the continuous sense-estimate-report cycle."""
        next_report_time = time.monotonic() + self.config.report_interval

        while self._running:
            loop_start = time.monotonic()

            # 1. Drain packet capture queue
            packets = self.capture.drain()
            if packets:
                self.stats.ingest_many(packets)
                logger.debug("Ingested %d packets.", len(packets))

            # 2. Compute snapshot
            snapshot = self.stats.compute()
            self._last_pkt_rate = snapshot.pkt_rate
            self._last_unique_src = snapshot.unique_src_ips

            # 3. Run Monte Carlo estimation
            snap_dict = snapshot.to_dict()
            threat = self.mc.estimate(snap_dict)
            threat_dict = threat.to_dict()

            # 4. Update heartbeat with latest threat level
            self.heartbeat.update_threat(threat.threat_level, threat.overall_risk)

            # 5. Immediate alert if risk spikes past threshold between cycles
            if (
                threat.overall_risk >= self.config.alert_threshold
                and threat.threat_level != self._last_alert_threat
            ):
                logger.warning(
                    "ALERT — risk=%.3f  level=%s  top=%s",
                    threat.overall_risk,
                    threat.threat_level,
                    threat.top_threat,
                )
                self.reporter.send_alert(
                    threat_level=threat.threat_level,
                    top_threat=threat.top_threat,
                    overall_risk=threat.overall_risk,
                )
                self._last_alert_threat = threat.threat_level
            elif threat.overall_risk < self.config.alert_threshold * 0.8:
                # Only reset once risk drops comfortably below threshold
                self._last_alert_threat = "LOW"

            # 6. Scheduled full report
            now_mono = time.monotonic()
            if now_mono >= next_report_time:
                extra = {
                    "capture_stats": self.capture.get_stats(),
                    "pattern_version": PATTERN_VERSION,
                }
                result = self.reporter.send(snap_dict, threat_dict, extra=extra)
                if result["success"]:
                    logger.info(
                        "Report sent — risk=%.3f  level=%s  top=%s  id=%s",
                        threat.overall_risk,
                        threat.threat_level,
                        threat.top_threat,
                        result["report_id"],
                    )
                else:
                    logger.error(
                        "Report delivery failed — %s", result.get("error")
                    )
                next_report_time = now_mono + self.config.report_interval

            # 7. Sleep for remainder of a 1-second tick (prevents CPU spin)
            elapsed = time.monotonic() - loop_start
            sleep_time = max(0.0, 1.0 - elapsed)
            time.sleep(sleep_time)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SwarmShield Scout Agent",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--agent-id", default=None,
                   help="Logical agent ID (overrides SCOUT_AGENT_ID)")
    p.add_argument("--interface", "-i", default=None,
                   help="Network interface to sniff")
    p.add_argument("--bpf-filter", default=None,
                   help="BPF capture filter expression")
    p.add_argument("--analyzer-url", default=None,
                   help="Analyzer Agent base URL")
    p.add_argument("--coordinator-url", default=None,
                   help="Coordinator base URL")
    p.add_argument("--flask-port", type=int, default=None,
                   help="Config server port")
    p.add_argument("--report-interval", type=float, default=None,
                   help="Seconds between full report cycles")
    p.add_argument("--alert-threshold", type=float, default=None,
                   help="Risk score that triggers an immediate alert")
    p.add_argument("--n-simulations", type=int, default=None,
                   help="Monte Carlo trial count per cycle")
    p.add_argument("--window-seconds", type=float, default=None,
                   help="Sliding window width in seconds")
    p.add_argument("--log-path", default=None,
                   help="Path to the scout log file")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable DEBUG-level logging")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    # Build config: defaults → env vars → CLI args
    cfg = AgentConfig()
    cfg = _load_config_from_env(cfg)

    overrides = {
        "agent_id":        args.agent_id,
        "interface":       args.interface,
        "bpf_filter":      args.bpf_filter,
        "analyzer_url":    args.analyzer_url,
        "coordinator_url": args.coordinator_url,
        "flask_port":      args.flask_port,
        "report_interval": args.report_interval,
        "alert_threshold": args.alert_threshold,
        "n_simulations":   args.n_simulations,
        "window_seconds":  args.window_seconds,
        "log_path":        args.log_path,
        "verbose":         args.verbose if args.verbose else None,
    }
    for attr, val in overrides.items():
        if val is not None:
            setattr(cfg, attr, val)

    log_level = logging.DEBUG if cfg.verbose else logging.INFO
    _configure_logging(cfg.log_path, level=log_level)

    agent = ScoutAgent(cfg)

    # Graceful shutdown on SIGINT / SIGTERM
    def _shutdown(signum, frame):
        logger.info("Signal %d received — stopping agent.", signum)
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    agent.start()


if __name__ == "__main__":
    main()
