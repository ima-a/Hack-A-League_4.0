"""
Packet Capture Tool
===================
Live network traffic capture using Scapy.

Converts raw Scapy packets into the canonical Scout dict format::

    {
        "src_ip":    str,       # source IPv4 address
        "dst_ip":    str,       # destination IPv4 address
        "dst_port":  int,       # destination TCP/UDP port (0 if N/A)
        "protocol":  str,       # "TCP" | "UDP" | "ICMP" | "OTHER"
        "size":      int,       # packet length in bytes
        "timestamp": float,     # Unix epoch (time.time())
        "is_syn":    bool,      # True iff TCP SYN-only flag set
    }

Usage (typical demo path)::

    cap = LivePacketCapture(interface="eth0")
    cap.start()                          # background sniffer thread
    scout = ScoutAgent(packet_source=cap.drain)
    scout.run_rolling_inference(...)     # blocks; Ctrl-C stops it
    cap.stop()

Scapy requires root/CAP_NET_RAW on Linux.  If Scapy is unavailable or
the requested interface does not exist the class raises ``RuntimeError``
with an actionable message so the demo fails fast and clearly.
"""

import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional Scapy import (graceful error if not installed / no root)
# ---------------------------------------------------------------------------
try:
    from scapy.all import (  # type: ignore[import]
        IP, TCP, UDP, ICMP,
        sniff as scapy_sniff,
        get_if_list,
    )
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


def _pkt_to_dict(pkt) -> Optional[Dict[str, Any]]:
    """
    Convert a Scapy packet to the Scout canonical dict.
    Returns ``None`` for non-IP packets (ARP, etc.) that Scout ignores.
    """
    if IP not in pkt:
        return None

    ip  = pkt[IP]
    src = ip.src
    dst = ip.dst
    sz  = len(pkt)
    ts  = float(pkt.time) if hasattr(pkt, "time") else time.time()

    dst_port = 0
    protocol = "OTHER"
    is_syn   = False

    if TCP in pkt:
        t        = pkt[TCP]
        dst_port = t.dport
        protocol = "TCP"
        # SYN-only: flags & 0x3F == 0x02
        is_syn   = bool(t.flags & 0x02) and not bool(t.flags & 0x10)
    elif UDP in pkt:
        dst_port = pkt[UDP].dport
        protocol = "UDP"
    elif ICMP in pkt:
        protocol = "ICMP"

    return {
        "src_ip":    src,
        "dst_ip":    dst,
        "dst_port":  dst_port,
        "protocol":  protocol,
        "size":      sz,
        "timestamp": ts,
        "is_syn":    is_syn,
    }


class LivePacketCapture:
    """
    Background Scapy sniffer that pushes converted packet dicts into a
    time-bounded deque.  ``ScoutAgent`` can use ``drain()`` as its
    ``packet_source`` callable.

    Parameters
    ----------
    interface : str
        Network interface name (e.g. ``"eth0"``, ``"wlan0"``, ``"lo"``).
        Pass ``None`` to sniff on all interfaces.
    bpf_filter : str
        Optional BPF capture filter (default: ``"ip"`` — IPv4 only).
    max_buffer : int
        Maximum packets kept in the buffer (oldest discarded first).
    """

    def __init__(
        self,
        interface:  Optional[str] = None,
        bpf_filter: str           = "ip",
        max_buffer: int           = 50_000,
    ) -> None:
        if not _SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed.  Install it with:\n"
                "  pip install scapy\n"
                "and re-run the demo as root (or with CAP_NET_RAW)."
            )

        available = get_if_list()
        if interface is not None and interface not in available:
            raise RuntimeError(
                f"Interface '{interface}' not found.  "
                f"Available interfaces: {available}"
            )

        self._iface      = interface
        self._filter     = bpf_filter
        self._buf: deque = deque(maxlen=max_buffer)
        self._lock       = threading.Lock()
        self._stop_evt   = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.logger      = logging.getLogger(f"{__name__}.LivePacketCapture")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background sniffer thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._sniff_loop,
            name="swarmshield-sniffer",
            daemon=True,
        )
        self._thread.start()
        self.logger.info(
            "Live capture started on interface=%s  filter='%s'",
            self._iface or "ALL",
            self._filter,
        )

    def stop(self) -> None:
        """Signal the sniffer thread to exit and wait for it."""
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.logger.info("Live capture stopped.")

    def drain(self, window_seconds: int = 5) -> List[Dict[str, Any]]:
        """
        Return and **remove** all packets received in the last
        *window_seconds* seconds.  This is the callable injected into
        ``ScoutAgent`` as ``packet_source``.

        Parameters
        ----------
        window_seconds : int
            Only packets with ``timestamp >= now - window_seconds`` are
            returned; older ones are discarded silently.

        Returns
        -------
        list of dict
            Packets in Scout canonical format.
        """
        cutoff = time.time() - window_seconds
        with self._lock:
            fresh   = [p for p in self._buf if p["timestamp"] >= cutoff]
            stale   = [p for p in self._buf if p["timestamp"] < cutoff]
            # Remove only the fresh ones we're returning (keep nothing
            # older — shrinks the deque to avoid unbounded growth)
            self._buf.clear()
        self.logger.debug(
            "drain: returning %d packets  (discarded %d stale)",
            len(fresh), len(stale),
        )
        return fresh

    @property
    def buffer_size(self) -> int:
        """Current number of packets in the live buffer."""
        return len(self._buf)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _sniff_loop(self) -> None:
        """Scapy sniff loop — runs in a daemon thread."""
        def _process(pkt):
            if self._stop_evt.is_set():
                return
            converted = _pkt_to_dict(pkt)
            if converted is not None:
                with self._lock:
                    self._buf.append(converted)

        def _stop_filter(_pkt):
            return self._stop_evt.is_set()

        try:
            scapy_sniff(
                iface   = self._iface,
                filter  = self._filter,
                prn     = _process,
                stop_filter = _stop_filter,
                store   = False,       # do NOT keep packets in Scapy RAM
            )
        except Exception as exc:
            self.logger.error("Sniffer thread crashed: %s", exc)
            raise


# ---------------------------------------------------------------------------
# Legacy / compatibility wrapper  (keeps old execute() API intact for tests)
# ---------------------------------------------------------------------------

class PacketCaptureTool:
    """
    Compatibility wrapper kept for existing tests and crew code.

    For live demo use ``LivePacketCapture`` directly.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{__name__}.PacketCaptureTool")

    def execute(self, capture_params: Dict) -> Dict[str, Any]:
        """
        Execute a one-shot packet capture.

        If Scapy is available, starts a ``LivePacketCapture`` for
        ``capture_params["timeout"]`` seconds (default 5) on
        ``capture_params["interface"]`` (default: all) and returns the
        collected packets.

        Falls back to an empty result if Scapy is unavailable.
        """
        self.logger.info("Executing packet capture…")

        interface = capture_params.get("interface", None)
        timeout   = int(capture_params.get("timeout", 5))
        bpf       = capture_params.get("filter", "ip")

        if not _SCAPY_AVAILABLE:
            self.logger.warning(
                "Scapy not installed — returning empty capture result."
            )
            return {"packets_captured": [], "packet_count": 0, "traffic_stats": {}}

        try:
            cap = LivePacketCapture(
                interface  = interface,
                bpf_filter = bpf,
            )
            cap.start()
            time.sleep(timeout)
            packets = cap.drain(window_seconds=timeout + 1)
            cap.stop()
        except RuntimeError as exc:
            self.logger.error("Capture failed: %s", exc)
            return {"packets_captured": [], "packet_count": 0,
                    "traffic_stats": {"error": str(exc)}}

        # Count per src_ip for a quick traffic_stats summary
        from collections import Counter
        stats = dict(Counter(p["src_ip"] for p in packets))

        return {
            "packets_captured": packets,
            "packet_count":     len(packets),
            "traffic_stats":    stats,
        }
