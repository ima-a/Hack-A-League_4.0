import logging
import math
import os
import random
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection thresholds (can be overridden per-instance)
# ---------------------------------------------------------------------------
_DEFAULT_THRESHOLDS = {
    "ddos_pps_threshold":          500,     # packets/sec from single source
    "ddos_syn_threshold":          300,     # SYN packets in window
    "port_scan_unique_ip_thresh":  20,      # unique dest IPs in window
    "port_scan_entropy_threshold": 3.5,     # Shannon entropy of dest ports
    "exfil_bps_threshold":         500_000, # bytes/sec
}

CONFIDENCE_THRESHOLD = 0.60   # report only if top_confidence > this
WINDOW_SECONDS       = 10     # sliding window width
N_SIMULATIONS        = 1000   # Monte Carlo trials per IP
LOG_FILE             = "scout_detections.log"


# ===========================================================================
# Internal helpers
# ===========================================================================

def _shannon_entropy(values: list) -> float:
    """Shannon entropy (bits) of a list of values."""
    if not values:
        return 0.0
    total = len(values)
    counts = Counter(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _compute_stats(packets: list, source_ip: str, window_seconds: int = 10) -> dict:
    """
    Compute per-source traffic statistics over a sliding window.

    Parameters
    ----------
    packets : list of dict
        Each dict: src_ip, dst_ip, dst_port, protocol, size, timestamp, is_syn
    source_ip : str
        Source IP to filter on.
    window_seconds : int
        Width of the analysis window.

    Returns
    -------
    dict with keys:
        packets_per_second, bytes_per_second, unique_dest_ips,
        syn_count, port_entropy, window_seconds
    """
    filtered = [p for p in packets if p.get("src_ip") == source_ip]
    if not filtered:
        return {
            "packets_per_second": 0.0,
            "bytes_per_second":   0.0,
            "unique_dest_ips":    0,
            "syn_count":          0,
            "port_entropy":       0.0,
            "window_seconds":     window_seconds,
        }
    n            = len(filtered)
    total_bytes  = sum(p.get("size", 0) for p in filtered)
    unique_dsts  = len({p.get("dst_ip") for p in filtered})
    syn_count    = sum(1 for p in filtered if p.get("is_syn", False))
    port_entropy = _shannon_entropy([p.get("dst_port", 0) for p in filtered])
    return {
        "packets_per_second": n / window_seconds,
        "bytes_per_second":   total_bytes / window_seconds,
        "unique_dest_ips":    unique_dsts,
        "syn_count":          syn_count,
        "port_entropy":       port_entropy,
        "window_seconds":     window_seconds,
    }


def _get_all_source_ips(packets: list) -> List[str]:
    """Return deduplicated list of source IPs seen in packets."""
    return list({p.get("src_ip") for p in packets if p.get("src_ip")})


def _monte_carlo_estimate(
    stats: dict,
    n_simulations: int = N_SIMULATIONS,
    thresholds: Optional[dict] = None,
) -> dict:
    """
    Probabilistic threat estimator using Monte Carlo simulation.

    For each trial, Gaussian noise (σ=10%) is applied to every metric and
    the noisy values are matched against threat rules.  The fraction of
    trials that trigger each rule is the confidence score.

    Returns
    -------
    dict with keys:
        ddos_confidence, port_scan_confidence, exfiltration_confidence,
        top_threat, top_confidence
    """
    th = {**_DEFAULT_THRESHOLDS, **(thresholds or {})}

    pps    = stats.get("packets_per_second", 0.0)
    bps    = stats.get("bytes_per_second",   0.0)
    unique = stats.get("unique_dest_ips",    0)
    syns   = stats.get("syn_count",          0)
    ent    = stats.get("port_entropy",        0.0)

    ddos_hits  = 0
    scan_hits  = 0
    exfil_hits = 0

    rng = random.Random()   # local RNG — reproducible per call if needed

    for _ in range(n_simulations):
        def noisy(v: float) -> float:
            return max(0.0, v + v * rng.gauss(0, 0.10))

        n_pps    = noisy(pps)
        n_bps    = noisy(bps)
        n_unique = noisy(float(unique))
        n_syns   = noisy(float(syns))
        n_ent    = noisy(ent)

        if n_pps >= th["ddos_pps_threshold"] or n_syns >= th["ddos_syn_threshold"]:
            ddos_hits += 1
        if n_unique >= th["port_scan_unique_ip_thresh"] or n_ent >= th["port_scan_entropy_threshold"]:
            scan_hits += 1
        if n_bps >= th["exfil_bps_threshold"]:
            exfil_hits += 1

    ddos_conf  = ddos_hits  / n_simulations
    scan_conf  = scan_hits  / n_simulations
    exfil_conf = exfil_hits / n_simulations

    scores = {
        "ddos":         ddos_conf,
        "port_scan":    scan_conf,
        "exfiltration": exfil_conf,
    }
    top_threat = max(scores, key=scores.get)
    top_conf   = scores[top_threat]

    if top_conf < 0.10:
        top_threat = "normal"
        top_conf   = 0.0

    return {
        "ddos_confidence":         ddos_conf,
        "port_scan_confidence":    scan_conf,
        "exfiltration_confidence": exfil_conf,
        "top_threat":              top_threat,
        "top_confidence":          top_conf,
    }


def _capitalise_attack(top_threat: str) -> str:
    mapping = {
        "ddos":         "DDoS",
        "port_scan":    "PortScan",
        "exfiltration": "Exfiltration",
        "normal":       "Normal",
    }
    return mapping.get(top_threat.lower(), top_threat.title())


def _format_report(
    source_ip: str,
    stats: dict,
    mc_result: dict,
    agent_id: str = "scout-1",
) -> dict:
    """Build a structured threat report dict."""
    attack_type = _capitalise_attack(mc_result.get("top_threat", "normal"))
    return {
        "agent_id":    agent_id,
        "event":       "threat_detected",
        "source_ip":   source_ip,
        "attack_type": attack_type,
        "confidence":  mc_result.get("top_confidence", 0.0),
        "stats":       stats,
        "monte_carlo": mc_result,
        "timestamp":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _log_detection(
    source_ip: str,
    attack_type: str,
    confidence: float,
    log_file: str = LOG_FILE,
) -> None:
    """Append a one-line detection record to log_file."""
    ts   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = (
        f"{ts} | source_ip={source_ip} | "
        f"attack={attack_type} | confidence={confidence:.4f}\n"
    )
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as exc:
        logger.warning("Could not write to %s: %s", log_file, exc)


def _simulate_packets(window_seconds: int = WINDOW_SECONDS) -> list:
    """
    Generate a realistic mix of synthetic packet metadata for one analysis
    window.  Produces three source IPs:
        - 10.0.0.1  — SYN-flood attacker (DDoS pattern)
        - 10.0.0.2  — port scanner (PortScan pattern)
        - 10.0.0.3  — normal host
    """
    now = time.time()
    packets: list = []
    rng = random.Random(42)

    # DDoS attacker — 600 SYN packets in 10 s → 60 pps (above threshold when
    # combined with high SYN count over the window)
    for i in range(600):
        packets.append({
            "src_ip":    "10.0.0.1",
            "dst_ip":    "192.168.1.100",
            "dst_port":  80,
            "protocol":  "TCP",
            "size":      60,
            "timestamp": now - rng.uniform(0, window_seconds),
            "is_syn":    True,
        })

    # Port scanner — 50 packets to 40 different destination IPs
    for i in range(50):
        packets.append({
            "src_ip":    "10.0.0.2",
            "dst_ip":    f"192.168.1.{rng.randint(1, 254)}",
            "dst_port":  rng.randint(1, 65535),
            "protocol":  "TCP",
            "size":      64,
            "timestamp": now - rng.uniform(0, window_seconds),
            "is_syn":    True,
        })

    # Normal host — 10 regular HTTP packets
    for i in range(10):
        packets.append({
            "src_ip":    "10.0.0.3",
            "dst_ip":    "8.8.8.8",
            "dst_port":  443,
            "protocol":  "TCP",
            "size":      rng.randint(200, 1400),
            "timestamp": now - rng.uniform(0, window_seconds),
            "is_syn":    False,
        })

    return packets


# ===========================================================================
# ScoutAgent
# ===========================================================================

class ScoutAgent:
    """
    Network Scout Agent

    Responsibilities:
    - Capture (or simulate) packet metadata in a sliding window
    - Compute per-source traffic statistics
    - Run Monte Carlo threat estimation
    - Surface anomalies and format threat reports
    - Log detections to file
    """

    def __init__(self, name: str = "Scout", agent_id: str = "scout-1",
                 log_file: str = LOG_FILE, thresholds: Optional[dict] = None):
        self.name       = name
        self.agent_id   = agent_id
        self.log_file   = log_file
        self.thresholds = thresholds or {}
        self.logger     = logging.getLogger(f"{__name__}.{name}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture_packets(self, window_seconds: int = WINDOW_SECONDS) -> List[Dict]:
        """
        Return a list of packet-metadata dicts representing one analysis window.

        In production this reads from a live Scapy buffer; here it generates
        a realistic synthetic window so the pipeline works without root /
        Scapy / a live interface.

        Each dict keys: src_ip, dst_ip, dst_port, protocol, size,
                        timestamp, is_syn
        """
        self.logger.info("Capturing packets (window=%ds)…", window_seconds)
        packets = _simulate_packets(window_seconds)
        self.logger.info("Captured %d packets from %d source IPs.",
                         len(packets), len(_get_all_source_ips(packets)))
        return packets

    def scan_network(self, window_seconds: int = WINDOW_SECONDS) -> Dict[str, Any]:
        """
        Perform a complete network scan cycle.

        Steps:
          1. Capture one window of packets.
          2. Compute traffic statistics per source IP.
          3. Run Monte Carlo estimation per source IP.
          4. Return a summary dict with per-IP findings.

        Returns
        -------
        dict
            {
              "source_ips": [...],
              "findings": {
                  "<ip>": {
                      "stats": {...},
                      "monte_carlo": {...},
                      "threat_level": "high" | "medium" | "low" | "normal"
                  }, ...
              },
              "timestamp": "<ISO-8601>"
            }
        """
        self.logger.info("Scanning network…")
        packets  = self.capture_packets(window_seconds)
        src_ips  = _get_all_source_ips(packets)
        findings: Dict[str, Any] = {}

        for ip in src_ips:
            stats  = _compute_stats(packets, ip, window_seconds)
            mc     = _monte_carlo_estimate(stats, thresholds=self.thresholds)
            conf   = mc["top_confidence"]
            level  = (
                "high"   if conf >= 0.75 else
                "medium" if conf >= 0.50 else
                "low"    if conf >= 0.25 else
                "normal"
            )
            findings[ip] = {
                "stats":        stats,
                "monte_carlo":  mc,
                "threat_level": level,
            }
            self.logger.info(
                "  %s  →  %s (conf=%.2f, level=%s)",
                ip, mc["top_threat"], conf, level,
            )

        return {
            "source_ips": src_ips,
            "findings":   findings,
            "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def detect_anomalies(
        self,
        window_seconds: int = WINDOW_SECONDS,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
    ) -> List[Dict[str, Any]]:
        """
        Run one detection cycle and return formatted threat reports for every
        source IP whose Monte Carlo confidence exceeds *confidence_threshold*.

        Returns
        -------
        list of dict
            Each item is a full threat report (same schema as
            _format_report()).  Empty list means no threats detected.
        """
        self.logger.info(
            "Detecting anomalies (threshold=%.2f)…", confidence_threshold
        )
        packets  = self.capture_packets(window_seconds)
        src_ips  = _get_all_source_ips(packets)
        threats: List[Dict[str, Any]] = []

        for ip in src_ips:
            stats = _compute_stats(packets, ip, window_seconds)
            mc    = _monte_carlo_estimate(stats, thresholds=self.thresholds)

            if mc["top_confidence"] > confidence_threshold and mc["top_threat"] != "normal":
                report = _format_report(ip, stats, mc, self.agent_id)
                _log_detection(ip, report["attack_type"], mc["top_confidence"],
                               self.log_file)
                threats.append(report)
                self.logger.info(
                    "ANOMALY: %s  →  %s (conf=%.2f)",
                    ip, report["attack_type"], mc["top_confidence"],
                )

        self.logger.info("Detection cycle complete: %d threat(s) found.", len(threats))
        return threats

    # ------------------------------------------------------------------
    # Expose internal utilities so tests / downstream code can call them
    # ------------------------------------------------------------------

    @staticmethod
    def compute_stats(packets: list, source_ip: str,
                      window_seconds: int = WINDOW_SECONDS) -> dict:
        """Per-source traffic statistics over a sliding window."""
        return _compute_stats(packets, source_ip, window_seconds)

    @staticmethod
    def get_all_source_ips(packets: list) -> List[str]:
        """Deduplicated list of source IPs from a packet list."""
        return _get_all_source_ips(packets)

    @staticmethod
    def monte_carlo_estimate(stats: dict,
                             n_simulations: int = N_SIMULATIONS,
                             thresholds: Optional[dict] = None) -> dict:
        """Probabilistic threat estimator."""
        return _monte_carlo_estimate(stats, n_simulations, thresholds)

    @staticmethod
    def format_report(source_ip: str, stats: dict, mc_result: dict,
                      agent_id: str = "scout-1") -> dict:
        """Build a structured threat-report dict."""
        return _format_report(source_ip, stats, mc_result, agent_id)

    @staticmethod
    def log_detection(source_ip: str, attack_type: str, confidence: float,
                      log_file: str = LOG_FILE) -> None:
        """Append a detection record to the log file."""
        _log_detection(source_ip, attack_type, confidence, log_file)
