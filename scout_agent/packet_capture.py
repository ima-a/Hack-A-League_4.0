"""
packet_capture.py
-----------------
Scapy-based live packet sniffer for the SwarmShield Scout Agent.

Responsibilities
----------------
- Capture packets on a configurable interface using Scapy's AsyncSniffer.
- Decode each packet into a structured dictionary suitable for downstream
  processing by traffic_stats.py and the Monte Carlo estimator.
- Support BPF filter expressions so only relevant traffic is captured.
- Expose a thread-safe queue from which scout_agent.py drains packets.
- Handle Scapy import errors gracefully so the module can still be imported
  on machines where Scapy is not yet installed (unit-test mode).

Dependencies
------------
    pip install scapy
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Graceful Scapy import
# ---------------------------------------------------------------------------
try:
    from scapy.all import AsyncSniffer, Packet  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
    from scapy.layers.l2 import ARP, Ether  # type: ignore
    from scapy.layers.dns import DNS  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    SCAPY_AVAILABLE = False
    logger.warning(
        "Scapy is not installed. PacketCapture will run in simulation mode. "
        "Install with: pip install scapy"
    )


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CapturedPacket:
    """Normalised representation of a single captured network packet."""

    timestamp: float                  # epoch seconds (float)
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "UNKNOWN"         # TCP / UDP / ICMP / ARP / OTHER
    flags: str = ""                   # TCP flag string e.g. 'S', 'SA', 'F'
    length: int = 0                   # total packet length in bytes
    ttl: int = 0
    payload_size: int = 0
    # ARP-specific
    arp_op: int = 0                   # 1 = request, 2 = reply
    src_mac: str = ""
    dst_mac: str = ""
    # DNS-specific
    dns_qtype: str = ""
    dns_qname: str = ""
    # Raw summary for debugging
    summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# TCP flag decoder
# ---------------------------------------------------------------------------

_TCP_FLAG_BITS = {
    0x001: "F",   # FIN
    0x002: "S",   # SYN
    0x004: "R",   # RST
    0x008: "P",   # PSH
    0x010: "A",   # ACK
    0x020: "U",   # URG
}


def _decode_tcp_flags(flag_int: int) -> str:
    return "".join(v for k, v in _TCP_FLAG_BITS.items() if flag_int & k)


# ---------------------------------------------------------------------------
# Packet parser
# ---------------------------------------------------------------------------

def _parse_packet(pkt) -> Optional[CapturedPacket]:
    """
    Convert a raw Scapy packet into a :class:`CapturedPacket`.
    Returns ``None`` if the packet cannot be meaningfully decoded.
    """
    try:
        cp = CapturedPacket(timestamp=time.time())

        # Ethernet / MAC
        if pkt.haslayer(Ether):
            cp.src_mac = pkt[Ether].src
            cp.dst_mac = pkt[Ether].dst

        # IP layer
        if pkt.haslayer(IP):
            ip = pkt[IP]
            cp.src_ip = ip.src
            cp.dst_ip = ip.dst
            cp.ttl = ip.ttl
            cp.length = ip.len

        # Transport layer
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            cp.src_port = tcp.sport
            cp.dst_port = tcp.dport
            cp.flags = _decode_tcp_flags(int(tcp.flags))
            cp.protocol = "TCP"
            cp.payload_size = len(bytes(tcp.payload))

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            cp.src_port = udp.sport
            cp.dst_port = udp.dport
            cp.protocol = "UDP"
            cp.payload_size = len(bytes(udp.payload))

        elif pkt.haslayer(ICMP):
            cp.protocol = "ICMP"
            cp.payload_size = len(bytes(pkt[ICMP].payload))

        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            cp.protocol = "ARP"
            cp.src_ip = arp.psrc
            cp.dst_ip = arp.pdst
            cp.src_mac = arp.hwsrc
            cp.dst_mac = arp.hwdst
            cp.arp_op = arp.op

        else:
            cp.protocol = "OTHER"

        # DNS (layered on UDP)
        if pkt.haslayer(DNS) and pkt[DNS].qd:
            try:
                cp.dns_qname = pkt[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
                cp.dns_qtype = str(pkt[DNS].qd.qtype)
            except Exception:
                pass

        cp.summary = pkt.summary()
        return cp

    except Exception as exc:
        logger.debug("Failed to parse packet: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Packet Capture engine
# ---------------------------------------------------------------------------

class PacketCapture:
    """
    Asynchronous packet capture using Scapy's ``AsyncSniffer``.

    Usage
    -----
    ::

        capture = PacketCapture(interface="eth0", bpf_filter="tcp or udp")
        capture.start()
        ...
        packets = capture.drain()   # returns list[CapturedPacket]
        capture.stop()

    Thread safety
    -------------
    :meth:`drain` is thread-safe; it atomically returns and clears the
    internal queue so multiple consumers do not race.
    """

    def __init__(
        self,
        interface: str = "eth0",
        bpf_filter: str = "ip or arp",
        max_queue: int = 10_000,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._queue: queue.Queue[CapturedPacket] = queue.Queue(maxsize=max_queue)
        self._sniffer = None
        self._running = False
        self._lock = threading.Lock()
        self._stats = {
            "total_captured": 0,
            "total_dropped": 0,
            "start_time": None,
        }
        logger.info(
            "PacketCapture initialised — interface=%s  filter='%s'  max_queue=%d",
            interface,
            bpf_filter,
            max_queue,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin capturing packets in the background."""
        if self._running:
            logger.warning("PacketCapture.start() called but already running.")
            return

        if not SCAPY_AVAILABLE:
            logger.warning("Scapy unavailable — using simulated packet stream.")
            self._running = True
            self._stats["start_time"] = time.time()
            self._sim_thread = threading.Thread(
                target=self._simulate_packets, daemon=True
            )
            self._sim_thread.start()
            return

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._handle_packet,
            store=False,
        )
        self._sniffer.start()
        self._running = True
        self._stats["start_time"] = time.time()
        logger.info("Live packet capture started on interface '%s'.", self.interface)

    def stop(self) -> None:
        """Stop capturing packets."""
        if not self._running:
            return
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.debug("Sniffer stop error: %s", exc)
            self._sniffer = None
        logger.info(
            "PacketCapture stopped. captured=%d  dropped=%d  uptime=%.1fs",
            self._stats["total_captured"],
            self._stats["total_dropped"],
            time.time() - (self._stats["start_time"] or time.time()),
        )

    def drain(self) -> list[CapturedPacket]:
        """
        Atomically remove and return all packets currently in the queue.

        Returns an empty list if the queue is empty.
        """
        packets: list[CapturedPacket] = []
        try:
            while True:
                packets.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        return packets

    @property
    def queue_size(self) -> int:
        """Current number of packets waiting to be drained."""
        return self._queue.qsize()

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        uptime = (
            time.time() - self._stats["start_time"]
            if self._stats["start_time"]
            else 0.0
        )
        return {
            "total_captured": self._stats["total_captured"],
            "total_dropped": self._stats["total_dropped"],
            "queue_size": self.queue_size,
            "uptime_seconds": round(uptime, 2),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_packet(self, pkt) -> None:
        """Callback invoked by Scapy for each captured packet."""
        cp = _parse_packet(pkt)
        if cp is None:
            return
        with self._lock:
            self._stats["total_captured"] += 1
        try:
            self._queue.put_nowait(cp)
        except queue.Full:
            with self._lock:
                self._stats["total_dropped"] += 1
            logger.debug("Packet queue full — packet dropped.")

    def _simulate_packets(self) -> None:
        """
        Generate synthetic packets when Scapy is unavailable.
        Used for development / unit testing without raw-socket privileges.
        """
        import random
        PROBE_IPS = ["192.168.1.10", "10.0.0.55", "172.16.0.3"]
        PROTOCOLS = [
            ("TCP", 80, "S"),
            ("TCP", 22, "S"),
            ("UDP", 53, ""),
            ("ICMP", 0, ""),
            ("ARP", 0, ""),
        ]
        pkt_id = 0
        while self._running:
            proto, dport, flags = random.choice(PROTOCOLS)
            cp = CapturedPacket(
                timestamp=time.time(),
                src_ip=random.choice(PROBE_IPS),
                dst_ip="192.168.1.1",
                src_port=random.randint(1024, 65535),
                dst_port=dport,
                protocol=proto,
                flags=flags,
                length=random.randint(40, 1500),
                ttl=random.choice([64, 128, 255]),
                payload_size=random.randint(0, 1400),
                summary=f"Simulated-{proto}-pkt-{pkt_id}",
            )
            pkt_id += 1
            with self._lock:
                self._stats["total_captured"] += 1
            try:
                self._queue.put_nowait(cp)
            except queue.Full:
                with self._lock:
                    self._stats["total_dropped"] += 1
            time.sleep(random.uniform(0.05, 0.3))
