"""
traffic_stats.py
----------------
Sliding-window traffic statistics engine for the SwarmShield Scout Agent.

Responsibilities
----------------
- Ingest a stream of :class:`~packet_capture.CapturedPacket` objects.
- Maintain a configurable time-based sliding window (default 30 s).
- Compute per-protocol packet rates, byte rates, connection counts, and
  anomaly-indicator sub-scores that feed the Monte Carlo estimator.
- Expose snapshots as plain dictionaries so they are JSON-serialisable and
  can be forwarded to the Analyzer Agent without additional transformation.

Key Metrics Produced
--------------------
``pkt_rate``        – packets per second (whole window)
``byte_rate``       – bytes per second
``proto_dist``      – fraction of traffic per protocol {TCP, UDP, ICMP, …}
``syn_ratio``       – SYN / total-TCP ratio (SYN flood indicator)
``port_spread``     – unique destination ports contacted within window
``unique_src_ips``  – unique source IPs
``arp_reply_rate``  – ARP replies per second (ARP spoofing indicator)
``dns_amp_score``   – fraction of large DNS responses (> 512 bytes)
``top_src_ips``     – top-5 source IPs by packet count
``top_dst_ports``   – top-5 destination ports by packet count
"""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List

logger = logging.getLogger(__name__)

# Local import – kept as string reference so the module is importable
# without packet_capture when running tests in isolation.
try:
    from packet_capture import CapturedPacket  # type: ignore
except ImportError:
    # Allow import when packet_capture is not on sys.path
    CapturedPacket = None  # type: ignore


# ---------------------------------------------------------------------------
# Internal helper: timestamped observation
# ---------------------------------------------------------------------------

@dataclass
class _FrameEntry:
    """One packet observation stored inside the sliding window."""
    ts: float
    protocol: str
    length: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    tcp_flags: str
    arp_op: int
    dns_qtype: str
    payload_size: int


# ---------------------------------------------------------------------------
# Stats snapshot
# ---------------------------------------------------------------------------

@dataclass
class TrafficSnapshot:
    """
    Computed statistics over the current sliding window.
    All rate fields are *per-second* values.
    """
    window_seconds: float
    timestamp: float

    # Volume
    pkt_count: int = 0
    byte_count: int = 0
    pkt_rate: float = 0.0
    byte_rate: float = 0.0

    # Protocol distribution  {protocol: fraction}
    proto_dist: Dict[str, float] = field(default_factory=dict)

    # TCP internals
    tcp_syn_count: int = 0
    tcp_total_count: int = 0
    syn_ratio: float = 0.0         # SYN / total-TCP   (0 → 1)

    # Spread indicators
    port_spread: int = 0           # unique dst ports
    unique_src_ips: int = 0
    unique_dst_ips: int = 0

    # ARP
    arp_reply_count: int = 0
    arp_reply_rate: float = 0.0

    # ICMP
    icmp_pkt_count: int = 0
    icmp_rate: float = 0.0

    # DNS amplification proxy
    large_dns_resp_count: int = 0
    dns_amp_score: float = 0.0     # fraction of UDP53 pkts that are "large"

    # Top talkers / targets
    top_src_ips: List[tuple] = field(default_factory=list)   # [(ip, count), …]
    top_dst_ports: List[tuple] = field(default_factory=list)  # [(port, count), …]

    # Composite anomaly sub-scores (0 → 1)
    syn_flood_score: float = 0.0
    port_scan_score: float = 0.0
    arp_spoof_score: float = 0.0
    dns_amp_indicator: float = 0.0

    def to_dict(self) -> dict:
        return {
            "window_seconds": self.window_seconds,
            "timestamp": self.timestamp,
            "pkt_count": self.pkt_count,
            "byte_count": self.byte_count,
            "pkt_rate": round(self.pkt_rate, 4),
            "byte_rate": round(self.byte_rate, 2),
            "proto_dist": {k: round(v, 4) for k, v in self.proto_dist.items()},
            "syn_ratio": round(self.syn_ratio, 4),
            "port_spread": self.port_spread,
            "unique_src_ips": self.unique_src_ips,
            "unique_dst_ips": self.unique_dst_ips,
            "arp_reply_rate": round(self.arp_reply_rate, 4),
            "icmp_rate": round(self.icmp_rate, 4),
            "dns_amp_score": round(self.dns_amp_score, 4),
            "top_src_ips": self.top_src_ips,
            "top_dst_ports": self.top_dst_ports,
            "syn_flood_score": round(self.syn_flood_score, 4),
            "port_scan_score": round(self.port_scan_score, 4),
            "arp_spoof_score": round(self.arp_spoof_score, 4),
            "dns_amp_indicator": round(self.dns_amp_indicator, 4),
        }


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class TrafficStats:
    """
    Thread-safe sliding-window traffic statistics engine.

    Parameters
    ----------
    window_seconds : float
        Width of the sliding time window. Packets older than this
        are automatically evicted on each :meth:`compute` call.
    syn_flood_threshold : float
        SYN ratio above which ``syn_flood_score`` starts to climb.
    port_scan_threshold : int
        Unique destination ports from a single source within the window
        above which ``port_scan_score`` starts to climb.
    arp_reply_threshold : float
        ARP replies-per-second above which ``arp_spoof_score`` climbs.

    Usage
    -----
    ::

        stats = TrafficStats(window_seconds=30)
        for pkt in packet_capture.drain():
            stats.ingest(pkt)
        snapshot = stats.compute()
        print(snapshot.to_dict())
    """

    def __init__(
        self,
        window_seconds: float = 30.0,
        syn_flood_threshold: float = 0.70,
        port_scan_threshold: int = 25,
        arp_reply_threshold: float = 3.0,
        dns_large_threshold: int = 512,
    ) -> None:
        self.window_seconds = window_seconds
        self.syn_flood_threshold = syn_flood_threshold
        self.port_scan_threshold = port_scan_threshold
        self.arp_reply_threshold = arp_reply_threshold
        self.dns_large_threshold = dns_large_threshold

        self._lock = threading.Lock()
        self._window: Deque[_FrameEntry] = deque()
        self._total_ingested = 0

        logger.info(
            "TrafficStats initialised — window=%.0fs  syn_thr=%.2f  "
            "port_scan_thr=%d  arp_thr=%.1f",
            window_seconds,
            syn_flood_threshold,
            port_scan_threshold,
            arp_reply_threshold,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, pkt) -> None:
        """
        Add a single packet observation to the window.

        Accepts either a :class:`~packet_capture.CapturedPacket` instance
        or a plain dict with the same keys.
        """
        if isinstance(pkt, dict):
            entry = _FrameEntry(
                ts=pkt.get("timestamp", time.time()),
                protocol=pkt.get("protocol", "OTHER"),
                length=pkt.get("length", 0),
                src_ip=pkt.get("src_ip", "0.0.0.0"),
                dst_ip=pkt.get("dst_ip", "0.0.0.0"),
                src_port=pkt.get("src_port", 0),
                dst_port=pkt.get("dst_port", 0),
                tcp_flags=pkt.get("flags", ""),
                arp_op=pkt.get("arp_op", 0),
                dns_qtype=pkt.get("dns_qtype", ""),
                payload_size=pkt.get("payload_size", 0),
            )
        else:
            entry = _FrameEntry(
                ts=pkt.timestamp,
                protocol=pkt.protocol,
                length=pkt.length,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                tcp_flags=pkt.flags,
                arp_op=pkt.arp_op,
                dns_qtype=pkt.dns_qtype,
                payload_size=pkt.payload_size,
            )

        with self._lock:
            self._window.append(entry)
            self._total_ingested += 1

    def ingest_many(self, packets: list) -> None:
        """Ingest a batch of packets (more efficient than repeated :meth:`ingest`)."""
        entries = []
        for pkt in packets:
            if isinstance(pkt, dict):
                entries.append(_FrameEntry(
                    ts=pkt.get("timestamp", time.time()),
                    protocol=pkt.get("protocol", "OTHER"),
                    length=pkt.get("length", 0),
                    src_ip=pkt.get("src_ip", "0.0.0.0"),
                    dst_ip=pkt.get("dst_ip", "0.0.0.0"),
                    src_port=pkt.get("src_port", 0),
                    dst_port=pkt.get("dst_port", 0),
                    tcp_flags=pkt.get("flags", ""),
                    arp_op=pkt.get("arp_op", 0),
                    dns_qtype=pkt.get("dns_qtype", ""),
                    payload_size=pkt.get("payload_size", 0),
                ))
            else:
                entries.append(_FrameEntry(
                    ts=pkt.timestamp,
                    protocol=pkt.protocol,
                    length=pkt.length,
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    tcp_flags=pkt.flags,
                    arp_op=pkt.arp_op,
                    dns_qtype=pkt.dns_qtype,
                    payload_size=pkt.payload_size,
                ))
        with self._lock:
            self._window.extend(entries)
            self._total_ingested += len(entries)

    def compute(self) -> "TrafficSnapshot":
        """
        Evict stale entries, then compute and return a :class:`TrafficSnapshot`
        representing the current window state.  Thread-safe.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            # Evict expired packets (deque is time-ordered)
            while self._window and self._window[0].ts < cutoff:
                self._window.popleft()

            entries = list(self._window)   # snapshot for computation

        return self._compute_from_entries(entries, now)

    @property
    def total_ingested(self) -> int:
        return self._total_ingested

    def reset(self) -> None:
        """Clear the window and reset counters."""
        with self._lock:
            self._window.clear()
            self._total_ingested = 0

    # ------------------------------------------------------------------
    # Internal computation
    # ------------------------------------------------------------------

    def _compute_from_entries(
        self, entries: list[_FrameEntry], now: float
    ) -> "TrafficSnapshot":
        snap = TrafficSnapshot(window_seconds=self.window_seconds, timestamp=now)

        if not entries:
            return snap

        # Determine actual window duration from oldest entry
        oldest_ts = entries[0].ts
        elapsed = max(now - oldest_ts, 1e-6)

        # Aggregation counters
        proto_counter: Counter = Counter()
        src_ip_counter: Counter = Counter()
        dst_port_counter: Counter = Counter()
        src_ports_per_ip: Dict[str, set] = defaultdict(set)
        dst_ips: set = set()
        src_ips: set = set()

        syn_count = 0
        tcp_total = 0
        arp_reply = 0
        icmp_count = 0
        dns_large = 0
        dns_total_udp53 = 0
        total_bytes = 0

        for e in entries:
            total_bytes += e.length
            proto_counter[e.protocol] += 1
            src_ip_counter[e.src_ip] += 1
            src_ips.add(e.src_ip)
            dst_ips.add(e.dst_ip)

            if e.dst_port > 0:
                dst_port_counter[e.dst_port] += 1
                src_ports_per_ip[e.src_ip].add(e.dst_port)

            if e.protocol == "TCP":
                tcp_total += 1
                if "S" in e.tcp_flags and "A" not in e.tcp_flags:
                    syn_count += 1

            elif e.protocol == "ICMP":
                icmp_count += 1

            elif e.protocol == "ARP":
                if e.arp_op == 2:
                    arp_reply += 1

            if e.protocol == "UDP" and e.dst_port == 53:
                dns_total_udp53 += 1
                if e.payload_size > self.dns_large_threshold:
                    dns_large += 1

        # Totals
        n = len(entries)
        snap.pkt_count = n
        snap.byte_count = total_bytes
        snap.pkt_rate = n / elapsed
        snap.byte_rate = total_bytes / elapsed

        # Protocol distribution
        snap.proto_dist = {p: c / n for p, c in proto_counter.items()}

        # TCP SYN
        snap.tcp_syn_count = syn_count
        snap.tcp_total_count = tcp_total
        snap.syn_ratio = (syn_count / tcp_total) if tcp_total > 0 else 0.0

        # Spread
        snap.port_spread = len(dst_port_counter)
        snap.unique_src_ips = len(src_ips)
        snap.unique_dst_ips = len(dst_ips)

        # ARP
        snap.arp_reply_count = arp_reply
        snap.arp_reply_rate = arp_reply / elapsed

        # ICMP
        snap.icmp_pkt_count = icmp_count
        snap.icmp_rate = icmp_count / elapsed

        # DNS amplification
        snap.large_dns_resp_count = dns_large
        snap.dns_amp_score = (dns_large / dns_total_udp53) if dns_total_udp53 > 0 else 0.0

        # Top talkers
        snap.top_src_ips = src_ip_counter.most_common(5)
        snap.top_dst_ports = dst_port_counter.most_common(5)

        # ----- Composite anomaly sub-scores (0..1) -------------------------

        # SYN flood: SYN ratio climbing above threshold
        if snap.syn_ratio >= self.syn_flood_threshold:
            snap.syn_flood_score = min(
                1.0,
                (snap.syn_ratio - self.syn_flood_threshold)
                / (1.0 - self.syn_flood_threshold + 1e-9)
            )
        else:
            snap.syn_flood_score = snap.syn_ratio / max(self.syn_flood_threshold, 1e-9) * 0.4

        # Port scan: max unique dst ports contacted by any single src IP
        max_port_spread = max(
            (len(ports) for ports in src_ports_per_ip.values()), default=0
        )
        snap.port_scan_score = min(
            1.0, max_port_spread / max(self.port_scan_threshold, 1)
        )

        # ARP spoof: ARP reply rate vs threshold
        snap.arp_spoof_score = min(
            1.0, snap.arp_reply_rate / max(self.arp_reply_threshold, 1e-9)
        )

        # DNS amplification indicator
        snap.dns_amp_indicator = min(1.0, snap.dns_amp_score * 2.0)

        return snap
