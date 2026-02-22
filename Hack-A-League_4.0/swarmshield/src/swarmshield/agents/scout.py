import logging
import math
import os
import random
import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from .llm_client import LLMClient
except ImportError:
    LLMClient = None  # type: ignore[assignment,misc]

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

# ---------------------------------------------------------------------------
# Rolling inference configuration
# ---------------------------------------------------------------------------
ROLLING_HORIZON_SECONDS  = 60    # seconds of packets kept in the rolling buffer
ROLLING_HISTORY_SIZE     = 10    # number of past MC snapshots tracked per IP
ROLLING_TICK_SECONDS     = 5     # default interval for run_rolling_inference
EARLY_WARNING_THRESHOLD  = 0.40  # predicted confidence above this → early_warning


# ===========================================================================
# LLM prompt engineering (Scout)
# ===========================================================================

_SCOUT_SYSTEM_PROMPT = (
    "You are a network threat classification assistant embedded in SwarmShield, "
    "an autonomous cybersecurity defense system.\n\n"
    "Your ONLY task: given pre-computed statistical anomaly data, return structured "
    "threat intelligence in the exact JSON schema specified below.\n\n"
    "CRITICAL CONSTRAINTS — violation will cause system failures:\n"
    "1. The numerical metrics and Monte Carlo confidence scores in INPUT DATA are "
    "GROUND TRUTH produced by deterministic algorithms. "
    "Do NOT contradict, downplay, or inflate any of them.\n"
    "2. Respond with valid JSON containing ONLY the OUTPUT SCHEMA fields. "
    "No prose, no markdown, no extra keys.\n"
    "3. Every enumerated field must use ONLY a value listed in this prompt.\n"
    "4. When data is ambiguous choose the conservative option "
    "(lower urgency; 'monitor' over 'block').\n"
    "5. Do not invent IOCs not directly supported by the observed statistics.\n\n"
    "ATTACK TAXONOMY — \"attack_subtype\" must be exactly one of:\n"
    "  SYN_Flood              — elevated pps + elevated syn_count, single destination\n"
    "  UDP_Flood              — high bps, low syn_count, high pps\n"
    "  HTTP_Flood             — high pps to port 80/443, low port entropy\n"
    "  PortScan_Horizontal    — high unique_dest_ips + high port_entropy (>=3.5)\n"
    "  PortScan_Vertical      — high pps to single IP, sequential ports\n"
    "  Data_Exfiltration_Bulk — sustained bps >=500000, moderate pps\n"
    "  Data_Exfiltration_Slow — low bps, anomalously persistent, low pps\n"
    "  Reconnaissance_ICMP    — low confidence, low pps, ICMP protocol\n"
    "  Normal                 — no anomalous pattern detected\n\n"
    "KILL CHAIN STAGES — \"kill_chain_stage\" must be exactly one of:\n"
    "  Reconnaissance         — scanning or enumeration (PortScan, ICMP sweep)\n"
    "  Delivery               — sending attack traffic (DDoS / SYN flood onset)\n"
    "  Exploitation           — actively disrupting service (DDoS at peak)\n"
    "  Actions_on_Objectives  — exfiltrating or encrypting data\n\n"
    "RESPONSE ACTIONS — \"recommended_action\" must be exactly one of:\n"
    "  block                  — immediately drop all traffic from source IP\n"
    "  rate_limit             — throttle source traffic below safe threshold\n"
    "  redirect_to_honeypot   — DNAT source traffic to honeypot for analysis\n"
    "  quarantine             — isolate source from forwarding (both directions)\n"
    "  monitor                — no enforcement yet; collect more data\n"
    "  escalate               — action unclear; flag for human review\n\n"
    "URGENCY SCALE — \"urgency\" must be an integer 1–5:\n"
    "  5 = Active DDoS or confirmed exfiltration; act immediately\n"
    "  4 = High-confidence threat; act within 1 minute\n"
    "  3 = Medium-confidence or early-stage threat; act within 5 minutes\n"
    "  2 = Low-confidence or ambiguous; add to watchlist\n"
    "  1 = Normal traffic; no action needed\n\n"
    "OUTPUT SCHEMA — respond with ONLY this JSON object, no other text:\n"
    '{\n'
    '  "attack_subtype":     "<value from taxonomy>",\n'
    '  "kill_chain_stage":   "<value from stages>",\n'
    '  "recommended_action": "<value from actions>",\n'
    '  "urgency":            <int 1-5>,\n'
    '  "iocs":               ["<indicator>", "<indicator>"],\n'
    '  "rationale":          "<1-2 sentences based strictly on observed metrics>"\n'
    '}'
)


def _build_scout_user_message(
    source_ip:   str,
    stats:       dict,
    mc_result:   dict,
    attack_type: str,
    agent_id:    str,
) -> str:
    """Build the grounded user message fed to the Scout LLM call."""
    return (
        f"DETECTED ANOMALY\n"
        f"source_ip   : {source_ip}\n"
        f"agent_id    : {agent_id}\n"
        f"attack_type : {attack_type}  (computed by deterministic algorithm)\n"
        f"\n"
        f"TRAFFIC STATISTICS (ground truth — do not contradict):\n"
        f"  packets_per_second : {stats.get('packets_per_second', 0.0):.2f}\n"
        f"  bytes_per_second   : {stats.get('bytes_per_second', 0.0):.2f}\n"
        f"  unique_dest_ips    : {stats.get('unique_dest_ips', 0)}\n"
        f"  syn_count          : {stats.get('syn_count', 0)}\n"
        f"  port_entropy       : {stats.get('port_entropy', 0.0):.4f}\n"
        f"  window_seconds     : {stats.get('window_seconds', 0)}\n"
        f"\n"
        f"MONTE CARLO CONFIDENCE SCORES (ground truth — do not contradict):\n"
        f"  ddos_confidence         : {mc_result.get('ddos_confidence', 0.0):.4f}\n"
        f"  port_scan_confidence    : {mc_result.get('port_scan_confidence', 0.0):.4f}\n"
        f"  exfiltration_confidence : {mc_result.get('exfiltration_confidence', 0.0):.4f}\n"
        f"  top_threat              : {mc_result.get('top_threat', 'unknown')}\n"
        f"  top_confidence          : {mc_result.get('top_confidence', 0.0):.4f}\n"
        f"\n"
        f"Provide structured threat intelligence for this anomaly."
    )


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

    # Map threat type to the semantically correct response action.
    # This is the single source of truth consumed by live_demo /verdict payloads.
    _THREAT_ACTIONS: Dict[str, str] = {
        "ddos":         "block",
        "port_scan":    "redirect_to_honeypot",
        "exfiltration": "quarantine",
        "normal":       "monitor",
    }
    recommended_action = _THREAT_ACTIONS.get(top_threat, "monitor")

    return {
        "ddos_confidence":         ddos_conf,
        "port_scan_confidence":    scan_conf,
        "exfiltration_confidence": exfil_conf,
        "top_threat":              top_threat,
        "top_confidence":          top_conf,
        "recommended_action":      recommended_action,
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


def _compute_trend(history: List[dict]) -> dict:
    """
    Compute the confidence trend from a list of per-tick MC snapshot dicts.
    Each dict must have ``top_confidence`` (float) and ``tick_time`` (epoch float).

    Uses simple linear regression over the history to estimate the rate of change
    and extrapolate one tick into the future.

    Returns
    -------
    dict with keys:
        trend_direction      : "rising" | "falling" | "stable"
        confidence_slope     : change in confidence per second (float)
        predicted_confidence : extrapolated confidence at the next tick (float [0,1])
    """
    if not history:
        return {"trend_direction": "stable", "confidence_slope": 0.0,
                "predicted_confidence": 0.0}
    if len(history) == 1:
        return {"trend_direction": "stable", "confidence_slope": 0.0,
                "predicted_confidence": history[0]["top_confidence"]}

    xs = [h["tick_time"]      for h in history]
    ys = [h["top_confidence"] for h in history]
    n  = len(xs)
    xm = sum(xs) / n
    ym = sum(ys) / n

    denom = sum((x - xm) ** 2 for x in xs)
    slope = (
        sum((xs[i] - xm) * (ys[i] - ym) for i in range(n)) / denom
        if denom != 0.0 else 0.0
    )

    # Estimate the gap between ticks and project one step ahead
    tick_gap  = (xs[-1] - xs[0]) / max(n - 1, 1)
    next_tick = xs[-1] + tick_gap
    predicted = max(0.0, min(1.0, ym + slope * (next_tick - xm)))

    direction = (
        "rising"  if slope >  0.005 else
        "falling" if slope < -0.005 else
        "stable"
    )
    return {
        "trend_direction":      direction,
        "confidence_slope":     round(slope, 6),
        "predicted_confidence": round(predicted, 4),
    }


def _rolling_alert_level(
    current_conf: float,
    predicted_conf: float,
    confirmed_threshold: float = CONFIDENCE_THRESHOLD,
    early_warning_threshold: float = EARLY_WARNING_THRESHOLD,
) -> str:
    """
    Map (current, predicted) confidence to an alert level.

    Returns
    -------
    str
        "confirmed"     — current confidence already at or above detection threshold.
        "early_warning" — not yet confirmed but projected to cross in next tick.
        "elevated"      — projected above early-warning threshold but not confirmed.
        "normal"        — no immediate concern.
    """
    if current_conf >= confirmed_threshold:
        return "confirmed"
    if predicted_conf >= confirmed_threshold:
        return "early_warning"
    if predicted_conf >= early_warning_threshold:
        return "elevated"
    return "normal"


def _llm_enrich_detection(
    source_ip:   str,
    stats:       dict,
    mc_result:   dict,
    attack_type: str,
    agent_id:    str,
    llm_client,          # Optional[LLMClient] — avoid forward-ref issues
) -> Optional[dict]:
    """
    Call the LLM to enrich a detected anomaly with structured threat intelligence.

    Returns None (silently) if the LLM client is unavailable or the API call
    fails.  Never raises.
    """
    if llm_client is None or not llm_client.available:
        return None
    user_msg = _build_scout_user_message(
        source_ip, stats, mc_result, attack_type, agent_id
    )
    return llm_client.complete(_SCOUT_SYSTEM_PROMPT, user_msg)


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
    - Continuous rolling inference: maintain a time-bounded packet buffer,
      track per-IP confidence history, compute trends, and issue early
      warnings before a threat crosses the hard detection threshold
    """

    def __init__(self, name: str = "Scout", agent_id: str = "scout-1",
                 log_file: str = LOG_FILE, thresholds: Optional[dict] = None,
                 llm_client: Optional["LLMClient"] = None,
                 packet_source: Optional[Any] = None):
        self.name        = name
        self.agent_id    = agent_id
        self.log_file    = log_file
        self.thresholds  = thresholds or {}
        self.logger      = logging.getLogger(f"{__name__}.{name}")
        self._llm_client = llm_client          # Optional LLM enrichment layer
        # If provided, packet_source(window_seconds) is called instead of the
        # built-in synthetic generator.  LivePacketCapture.drain() satisfies
        # this interface for live demo use.
        self._packet_source = packet_source
        # Rolling inference state
        self._packet_buffer:  deque = deque()   # time-bounded packet buffer
        self._belief_history: Dict[str, deque] = {}  # per-IP MC snapshot history

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture_packets(self, window_seconds: int = WINDOW_SECONDS) -> List[Dict]:
        """
        Return a list of packet-metadata dicts representing one analysis window.

        If a ``packet_source`` callable was supplied at construction time
        (e.g. ``LivePacketCapture.drain`` from the live demo), that callable
        is invoked with ``window_seconds`` and its return value is used
        directly — giving Scout genuine live network traffic.

        Otherwise the built-in synthetic generator is used so the pipeline
        works without root / Scapy / a live interface (dev/test mode).

        Each dict keys: src_ip, dst_ip, dst_port, protocol, size,
                        timestamp, is_syn
        """
        self.logger.info("Capturing packets (window=%ds)…", window_seconds)
        if self._packet_source is not None:
            packets = self._packet_source(window_seconds)
            self.logger.info(
                "Live capture: %d packets from %d source IPs.",
                len(packets), len(_get_all_source_ips(packets)),
            )
        else:
            packets = _simulate_packets(window_seconds)
            self.logger.info(
                "Synthetic capture: %d packets from %d source IPs.",
                len(packets), len(_get_all_source_ips(packets)),
            )
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
                llm_insight = _llm_enrich_detection(
                    ip, stats, mc, report["attack_type"],
                    self.agent_id, self._llm_client,
                )
                if llm_insight:
                    report["llm_insight"] = llm_insight
                threats.append(report)
                self.logger.info(
                    "ANOMALY: %s  →  %s (conf=%.2f)%s",
                    ip, report["attack_type"], mc["top_confidence"],
                    "  [LLM enriched]" if llm_insight else "",
                )

        self.logger.info("Detection cycle complete: %d threat(s) found.", len(threats))
        return threats

    def rolling_tick(
        self,
        new_packets: List[Dict],
        horizon_seconds: float = ROLLING_HORIZON_SECONDS,
    ) -> Dict[str, Any]:
        """
        Single-step rolling inference update.

        Adds *new_packets* to the internal rolling buffer, trims packets older
        than *horizon_seconds*, recomputes per-IP stats and Monte Carlo scores,
        updates per-IP belief history, derives confidence trends, and raises
        early warnings before the hard detection threshold is crossed.

        This is the anticipatory core: even if a source IP has not yet
        crossed CONFIDENCE_THRESHOLD, a rising trend whose extrapolated
        confidence will cross it triggers an ``'early_warning'`` alert.

        Parameters
        ----------
        new_packets : list of dict
            Fresh packet metadata (same schema as capture_packets()).
        horizon_seconds : float
            Width of the rolling time window to retain in the buffer.

        Returns
        -------
        dict
            {
              "tick_time"        : float (epoch seconds),
              "buffer_size"      : int   (packets currently in buffer),
              "per_ip"           : {
                  "<ip>": {
                      "stats":                {...},
                      "monte_carlo":          {...},
                      "trend":                {trend_direction, confidence_slope,
                                               predicted_confidence},
                      "alert_level":          "confirmed"|"early_warning"|"elevated"|"normal",
                      "current_confidence":   float,
                      "predicted_confidence": float,
                  }, ...
              },
              "early_warnings"   : [list of IPs at alert_level 'early_warning'],
              "confirmed_threats": [list of IPs at alert_level 'confirmed'],
            }
        """
        tick_time = time.time()
        cutoff    = tick_time - horizon_seconds

        # Extend buffer, drop stale packets
        self._packet_buffer.extend(new_packets)
        while self._packet_buffer and self._packet_buffer[0].get("timestamp", 0) < cutoff:
            self._packet_buffer.popleft()

        buffered = list(self._packet_buffer)
        src_ips  = _get_all_source_ips(buffered) if buffered else []

        per_ip:            Dict[str, Any] = {}
        early_warnings:    List[str]      = []
        confirmed_threats: List[str]      = []

        for ip in src_ips:
            stats = _compute_stats(buffered, ip, int(max(horizon_seconds, 1)))
            mc    = _monte_carlo_estimate(stats, thresholds=self.thresholds)

            # Update per-IP belief history
            if ip not in self._belief_history:
                self._belief_history[ip] = deque(maxlen=ROLLING_HISTORY_SIZE)
            self._belief_history[ip].append({
                "top_confidence": mc["top_confidence"],
                "top_threat":     mc["top_threat"],
                "tick_time":      tick_time,
            })

            trend     = _compute_trend(list(self._belief_history[ip]))
            cur_conf  = mc["top_confidence"]
            pred_conf = trend["predicted_confidence"]
            level     = _rolling_alert_level(cur_conf, pred_conf)

            per_ip[ip] = {
                "stats":                stats,
                "monte_carlo":          mc,
                "trend":                trend,
                "alert_level":          level,
                "current_confidence":   round(cur_conf,  4),
                "predicted_confidence": round(pred_conf, 4),
            }

            # LLM enrichment for actionable alert levels (early_warning / confirmed)
            if level in ("early_warning", "confirmed"):
                llm_insight = _llm_enrich_detection(
                    ip, stats, mc, mc["top_threat"],
                    self.agent_id, self._llm_client,
                )
                if llm_insight:
                    per_ip[ip]["llm_insight"] = llm_insight

            if level == "early_warning":
                early_warnings.append(ip)
                self.logger.warning(
                    "EARLY WARNING: %s  →  %s  current=%.2f  predicted=%.2f  trend=%s",
                    ip, mc["top_threat"], cur_conf, pred_conf, trend["trend_direction"],
                )
            elif level == "confirmed":
                confirmed_threats.append(ip)
                self.logger.warning(
                    "CONFIRMED THREAT: %s  →  %s  confidence=%.2f",
                    ip, mc["top_threat"], cur_conf,
                )
            else:
                self.logger.debug(
                    "rolling_tick: %s  level=%s  conf=%.2f  predicted=%.2f",
                    ip, level, cur_conf, pred_conf,
                )

        tick_result = {
            "tick_time":         tick_time,
            "buffer_size":       len(buffered),
            "per_ip":            per_ip,
            "early_warnings":    early_warnings,
            "confirmed_threats": confirmed_threats,
        }
        # Publish to A2A bus (non-blocking; failures are silently swallowed)
        try:
            from ..utils.message_bus import (
                get_bus, TOPIC_SCOUT_TICK, TOPIC_SCOUT_EARLY_WARNING,
            )
            _bus = get_bus()
            _bus.publish(TOPIC_SCOUT_TICK, {
                "tick_time":         tick_result["tick_time"],
                "buffer_size":       tick_result["buffer_size"],
                "early_warnings":    tick_result["early_warnings"],
                "confirmed_threats": tick_result["confirmed_threats"],
                "agent_id":          self.agent_id,
            })
            if tick_result["early_warnings"]:
                _bus.publish(TOPIC_SCOUT_EARLY_WARNING, {
                    "ips":      tick_result["early_warnings"],
                    "per_ip":   {
                        ip: tick_result["per_ip"][ip]
                        for ip in tick_result["early_warnings"]
                        if ip in tick_result["per_ip"]
                    },
                    "tick_time": tick_result["tick_time"],
                    "agent_id":  self.agent_id,
                })
        except Exception:  # noqa: BLE001
            pass
        return tick_result

    def run_rolling_inference(
        self,
        tick_seconds:      float = ROLLING_TICK_SECONDS,
        horizon_seconds:   float = ROLLING_HORIZON_SECONDS,
        n_ticks:           Optional[int] = None,
        on_tick:           Optional[Any] = None,
        on_early_warning:  Optional[Any] = None,
    ) -> None:
        """
        Continuous rolling inference loop.

        Every *tick_seconds*, captures a fresh packet window and calls
        ``rolling_tick()`` to update beliefs, compute trends, and surface
        early warnings *before* confidence fully crosses the hard threshold.

        Parameters
        ----------
        tick_seconds : float
            Interval between inference ticks (default: 5 s).
        horizon_seconds : float
            Rolling buffer width (default: 60 s).
        n_ticks : int or None
            Stop after this many ticks; ``None`` runs indefinitely until
            interrupted by KeyboardInterrupt.
        on_tick : callable or None
            Optional callback invoked with the full ``rolling_tick()`` result
            dict after every tick.  Signature: ``on_tick(result: dict) -> None``.
        on_early_warning : callable or None
            Anticipatory callback invoked ONLY when one or more IPs are at
            ``early_warning`` alert level.  Fires before the full
            ``CONFIDENCE_THRESHOLD`` is crossed, giving the system a window
            to apply pre-emptive, low-impact countermeasures.
            Signature: ``on_early_warning(ips: list[str], per_ip: dict) -> None``.
        """
        self.logger.info(
            "Starting rolling inference (tick=%.1fs, horizon=%.1fs)…",
            tick_seconds, horizon_seconds,
        )
        tick = 0
        try:
            while n_ticks is None or tick < n_ticks:
                new_packets = self.capture_packets(window_seconds=int(tick_seconds))
                result      = self.rolling_tick(new_packets,
                                               horizon_seconds=horizon_seconds)
                ew = len(result["early_warnings"])
                ct = len(result["confirmed_threats"])
                self.logger.info(
                    "Tick %d — buffer=%d pkts  early_warnings=%d  confirmed=%d",
                    tick + 1, result["buffer_size"], ew, ct,
                )
                if on_tick is not None:
                    on_tick(result)
                # Anticipatory path: fire on_early_warning ONLY when IPs are
                # in the early-warning zone (not yet confirmed threats).
                if on_early_warning is not None and ew > 0:
                    on_early_warning(result["early_warnings"], result["per_ip"])
                tick += 1
                if n_ticks is None or tick < n_ticks:
                    time.sleep(tick_seconds)
        except KeyboardInterrupt:
            self.logger.info("Rolling inference interrupted by user.")
        self.logger.info("Rolling inference stopped after %d tick(s).", tick)

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

    @staticmethod
    def compute_trend(history: List[dict]) -> dict:
        """Confidence trend from a list of per-tick MC snapshot dicts."""
        return _compute_trend(history)

    @staticmethod
    def rolling_alert_level(
        current_conf: float,
        predicted_conf: float,
        confirmed_threshold: float = CONFIDENCE_THRESHOLD,
        early_warning_threshold: float = EARLY_WARNING_THRESHOLD,
    ) -> str:
        """Map (current, predicted) confidence to an alert level string."""
        return _rolling_alert_level(
            current_conf, predicted_conf,
            confirmed_threshold, early_warning_threshold,
        )

    @staticmethod
    def get_preemptive_candidates(
        tick_result: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Extract IPs at ``early_warning`` alert level from a ``rolling_tick()``
        result and return them as structured dicts ready to feed directly into
        ``AnalyzerAgent.pre_assess_risk()`` or the Responder's
        ``/preemptive_action`` endpoint.

        This is the **anticipatory bridge**: it converts a raw tick result
        into a prioritised list of pre-emptive action candidates without
        committing any enforcement action itself.

        Parameters
        ----------
        tick_result : dict
            Direct output of ``ScoutAgent.rolling_tick()``.

        Returns
        -------
        list of dict
            Each entry contains:
            source_ip, alert_level, current_confidence, predicted_confidence,
            threat_type, trend_direction, stats, trend.
        """
        per_ip = tick_result.get("per_ip", {})
        return [
            {
                "source_ip":            ip,
                "alert_level":          data["alert_level"],
                "current_confidence":   data["current_confidence"],
                "predicted_confidence": data["predicted_confidence"],
                "threat_type":          data["monte_carlo"].get("top_threat", "unknown"),
                "stats":                data["stats"],
                "trend_direction":      data["trend"].get("trend_direction", "stable"),
                "trend":                data["trend"],
            }
            for ip, data in per_ip.items()
            if data.get("alert_level") == "early_warning"
        ]
