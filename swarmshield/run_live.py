#!/usr/bin/env python3
"""
SwarmShield Live Demo Launcher
================================
Real-time threat detection & response from live network traffic.

Usage
-----
# Simulate attack traffic (no root, no Scapy needed — great for demos):
    python run_live.py --simulate

# Live capture on a specific interface (requires root / CAP_NET_RAW):
    sudo python run_live.py --interface eth0

# Full options:
    sudo python run_live.py --interface eth0 --tick 3 --horizon 60

Press Ctrl-C to stop everything cleanly (sniffer + Responder + Scout all shut down).

Options
-------
--interface  / -i   Network interface to sniff  (default: all)
--filter     / -f   BPF capture filter           (default: "ip")
--tick       / -t   Seconds between Scout ticks  (default: 5)
--horizon           Rolling window width in sec  (default: 60)
--responder-host    Bind address for Flask        (default: 127.0.0.1)
--responder-port    Port for Flask                (default: 5000)
--simulate          Use synthetic traffic (no root / Scapy needed)
"""

import sys
from pathlib import Path

# Add src/ to the Python path so 'swarmshield' is importable
sys.path.insert(0, str(Path(__file__).parent / "src"))

from swarmshield.demo.live_demo import main

if __name__ == "__main__":
    main()
