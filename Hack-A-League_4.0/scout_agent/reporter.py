"""
reporter.py
-----------
JSON report builder and HTTP dispatcher for the SwarmShield Scout Agent.

Responsibilities
----------------
- Assemble a structured JSON payload from a :class:`~traffic_stats.TrafficSnapshot`
  and a :class:`~monte_carlo.ThreatEstimate`.
- POST the payload to the Analyzer Agent's HTTP endpoint.
- Support optional local-disk logging of all outbound reports.
- Implement exponential back-off retry on transient HTTP failures.
- Thread-safe: all public methods may be called from the main agent loop.

Endpoint Contract
-----------------
The Analyzer Agent is expected to expose:

    POST  <analyzer_url>/report
    Content-Type: application/json
    Body: ScoutReport (see schema below)

    Response 200: {"status": "ok", "report_id": "<uuid>"}
    Response 4xx: {"error": "<message>"}
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Report schema
# ---------------------------------------------------------------------------

REPORT_SCHEMA_VERSION = "1.0"


def build_report(
    snapshot: dict,
    threat_estimate: dict,
    agent_id: str = "scout-1",
    extra: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    Assemble a complete Scout Report dictionary.

    Parameters
    ----------
    snapshot : dict
        Output of :meth:`TrafficSnapshot.to_dict`.
    threat_estimate : dict
        Output of :meth:`ThreatEstimate.to_dict`.
    agent_id : str
        Identifier of the Scout Agent instance that produced this report.
    extra : dict, optional
        Arbitrary extra metadata to embed in the report.

    Returns
    -------
    dict
        Fully formed report ready for JSON serialisation.
    """
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "generated_at": time.time(),
        "generated_at_iso": _epoch_to_iso(time.time()),
        "traffic_window": snapshot,
        "threat_estimate": threat_estimate,
        "metadata": extra or {},
    }
    return report


def _epoch_to_iso(ts: float) -> str:
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class Reporter:
    """
    Builds Scout reports and dispatches them to the Analyzer Agent.

    Parameters
    ----------
    analyzer_url : str
        Base URL of the Analyzer Agent, e.g. ``"http://localhost:5001"``.
    agent_id : str
        Logical identifier for this Scout instance (included in every report).
    report_endpoint : str
        Path appended to ``analyzer_url`` for report submission.
    timeout : float
        HTTP request timeout in seconds.
    max_retries : int
        Maximum number of retry attempts on transient failure.
    retry_base_delay : float
        Base delay (seconds) for exponential back-off: delay = base * 2^attempt.
    log_reports : bool
        If True, every outbound report is appended to ``log_path``.
    log_path : str
        Path to the JSONL file where reports are logged locally.
    """

    def __init__(
        self,
        analyzer_url: str = "http://localhost:5001",
        agent_id: str = "scout-1",
        report_endpoint: str = "/report",
        timeout: float = 5.0,
        max_retries: int = 3,
        retry_base_delay: float = 1.0,
        log_reports: bool = True,
        log_path: str = "scout_log.txt",
    ) -> None:
        self.analyzer_url = analyzer_url.rstrip("/")
        self.agent_id = agent_id
        self.report_endpoint = report_endpoint
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_base_delay = retry_base_delay
        self.log_reports = log_reports
        self.log_path = log_path

        self._lock = threading.Lock()
        self._stats = {
            "total_sent": 0,
            "total_failed": 0,
            "last_sent_at": None,
            "last_status": None,
        }

        logger.info(
            "Reporter initialised — analyzer=%s  agent_id=%s  retries=%d  log=%s",
            self.analyzer_url,
            self.agent_id,
            self.max_retries,
            self.log_path if self.log_reports else "disabled",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(
        self,
        snapshot: dict,
        threat_estimate: dict,
        extra: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """
        Build a report from *snapshot* + *threat_estimate* and POST it
        to the Analyzer Agent.  Retries on transient failures.

        Returns
        -------
        dict
            ``{"success": bool, "report_id": str, "http_status": int|None,
               "error": str|None, "attempts": int}``
        """
        report = build_report(snapshot, threat_estimate, self.agent_id, extra)

        if self.log_reports:
            self._log_to_disk(report)

        result = self._post_with_retry(report)

        with self._lock:
            if result["success"]:
                self._stats["total_sent"] += 1
            else:
                self._stats["total_failed"] += 1
            self._stats["last_sent_at"] = time.time()
            self._stats["last_status"] = result.get("http_status")

        return result

    def send_alert(
        self,
        threat_level: str,
        top_threat: str,
        overall_risk: float,
        details: Optional[dict] = None,
    ) -> dict:
        """
        Send a lightweight alert (without full traffic stats) when threat
        level crosses a threshold mid-cycle.
        """
        alert_payload = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "report_id": str(uuid.uuid4()),
            "agent_id": self.agent_id,
            "generated_at": time.time(),
            "type": "ALERT",
            "threat_level": threat_level,
            "top_threat": top_threat,
            "overall_risk": overall_risk,
            "details": details or {},
        }
        if self.log_reports:
            self._log_to_disk(alert_payload)
        return self._post_with_retry(alert_payload, endpoint="/alert")

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def format_report_json(
        self, snapshot: dict, threat_estimate: dict, indent: int = 2
    ) -> str:
        """Return a pretty-printed JSON string of the report (no HTTP call)."""
        report = build_report(snapshot, threat_estimate, self.agent_id)
        return json.dumps(report, indent=indent, default=str)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post_with_retry(
        self, payload: dict, endpoint: Optional[str] = None
    ) -> dict:
        url = self.analyzer_url + (endpoint or self.report_endpoint)
        report_id = payload.get("report_id", "?")
        body = json.dumps(payload, default=str).encode("utf-8")

        for attempt in range(1, self.max_retries + 1):
            try:
                req = Request(
                    url,
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Scout-Agent": self.agent_id,
                        "X-Report-Id": report_id,
                    },
                    method="POST",
                )
                with urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    status = resp.status
                    try:
                        response_body = json.loads(raw)
                    except json.JSONDecodeError:
                        response_body = {"raw": raw.decode("utf-8", errors="replace")}

                logger.info(
                    "Report %s delivered — HTTP %d (attempt %d)",
                    report_id,
                    status,
                    attempt,
                )
                return {
                    "success": True,
                    "report_id": report_id,
                    "http_status": status,
                    "response": response_body,
                    "attempts": attempt,
                    "error": None,
                }

            except HTTPError as exc:
                logger.warning(
                    "HTTP %d sending report %s (attempt %d/%d): %s",
                    exc.code,
                    report_id,
                    attempt,
                    self.max_retries,
                    exc.reason,
                )
                # 4xx: don't retry (client-side error)
                if 400 <= exc.code < 500:
                    return {
                        "success": False,
                        "report_id": report_id,
                        "http_status": exc.code,
                        "response": None,
                        "attempts": attempt,
                        "error": f"HTTP {exc.code}: {exc.reason}",
                    }

            except (URLError, OSError, TimeoutError) as exc:
                logger.warning(
                    "Network error sending report %s (attempt %d/%d): %s",
                    report_id,
                    attempt,
                    self.max_retries,
                    exc,
                )

            # Exponential back-off before retry
            if attempt < self.max_retries:
                delay = self.retry_base_delay * (2 ** (attempt - 1))
                logger.debug("Retrying in %.1f s ...", delay)
                time.sleep(delay)

        logger.error(
            "Failed to deliver report %s after %d attempts.",
            report_id,
            self.max_retries,
        )
        return {
            "success": False,
            "report_id": report_id,
            "http_status": None,
            "response": None,
            "attempts": self.max_retries,
            "error": "Max retries exceeded",
        }

    def _log_to_disk(self, payload: dict) -> None:
        """Append the payload as a single JSON line to ``self.log_path``."""
        try:
            line = json.dumps(payload, default=str) + "\n"
            with self._lock:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError as exc:
            logger.warning("Could not write report to disk: %s", exc)
