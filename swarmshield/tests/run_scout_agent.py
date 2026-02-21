"""
run_scout_agent.py — SwarmShield

Manual end-to-end smoke test for the Scout Agent pipeline.

Tests:
    1.  ScoutAgent class  (src/swarmshield/agents/scout.py)
    2.  compute_stats()   — per-source traffic statistics   (scout_agent/)
    3.  monte_carlo_threat_estimate() — probabilistic scoring (scout_agent/)
    4.  format_threat_report()        — JSON report builder  (scout_agent/)
    5.  log_detection()               — file-append logger   (scout_agent/)

Usage (from swarmshield/ directory):
    .venv/bin/python tests/run_scout_agent.py
"""

import os
import sys
import time
import tempfile

# ---------------------------------------------------------------------------
# Ensure the swarmshield project root (contains src/) is on sys.path,
# and also add the standalone scout_agent/ directory.
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

SCOUT_AGENT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "scout_agent")
)
if os.path.isdir(SCOUT_AGENT_DIR):
    sys.path.insert(0, SCOUT_AGENT_DIR)

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PASS = f"{GREEN}[PASS]{RESET}"
FAIL = f"{RED}[FAIL]{RESET}"
INFO = f"{CYAN}[INFO]{RESET}"

results = []


def check(label: str, condition: bool, detail: str = ""):
    tag = PASS if condition else FAIL
    msg = f"  {tag}  {label}"
    if detail:
        msg += f"  →  {detail}"
    print(msg)
    results.append((label, condition))


# ===========================================================================
# 1 — ScoutAgent class (swarmshield package)
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 1 — ScoutAgent (swarmshield package){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

try:
    from src.swarmshield.agents.scout import ScoutAgent

    scout = ScoutAgent()
    check("ScoutAgent instantiation", True, f"name={scout.name!r}")
    check("scout.name == 'Scout'", scout.name == "Scout")

    net = scout.scan_network()
    check("scan_network() returns dict", isinstance(net, dict), str(net))

    anomalies = scout.detect_anomalies()
    check("detect_anomalies() returns list", isinstance(anomalies, list), str(anomalies))

    pkts = scout.capture_packets()
    check("capture_packets() returns list", isinstance(pkts, list), str(pkts))

except Exception as exc:
    check("ScoutAgent import/run", False, str(exc))

# ===========================================================================
# 2 — compute_stats()  (scout_agent/)
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 2 — compute_stats() — Traffic Statistics{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

_traffic_stats_ok = False

try:
    from traffic_stats import compute_stats, get_all_source_ips

    _traffic_stats_ok = True

    # --- Simulate a SYN-flood from one attacker ---
    now = time.time()
    packets = []
    for i in range(150):
        packets.append({
            "src_ip":   "10.0.0.1",
            "dst_ip":   "192.168.1.100",
            "dst_port": 80,
            "protocol": "TCP",
            "size":     64,
            "timestamp": now - (i % 10),
            "is_syn":   True,
        })
    # Add normal traffic from a second host
    for i in range(5):
        packets.append({
            "src_ip":   "10.0.0.2",
            "dst_ip":   f"192.168.1.{10 + i}",
            "dst_port": 443 + i,
            "protocol": "TCP",
            "size":     500,
            "timestamp": now - i,
            "is_syn":   False,
        })

    # Stats for the attacker
    stats_attacker = compute_stats(packets, "10.0.0.1", window_seconds=10)
    check(
        "compute_stats for attacker: returns dict",
        isinstance(stats_attacker, dict),
        str(stats_attacker),
    )
    check(
        "packets_per_second > 0",
        stats_attacker.get("packets_per_second", 0) > 0,
        f"{stats_attacker.get('packets_per_second'):.1f} pkt/s",
    )
    check(
        "syn_count > 0",
        stats_attacker.get("syn_count", 0) > 0,
        f"syn_count={stats_attacker.get('syn_count')}",
    )

    # Stats for normal host
    stats_normal = compute_stats(packets, "10.0.0.2", window_seconds=10)
    check(
        "compute_stats for normal host: syn_count == 0",
        stats_normal.get("syn_count", -1) == 0,
        f"syn_count={stats_normal.get('syn_count')}",
    )

    # Unknown IP → all zeroes
    stats_empty = compute_stats(packets, "1.2.3.4", window_seconds=10)
    check(
        "compute_stats for unknown IP: packets_per_second == 0.0",
        stats_empty.get("packets_per_second") == 0.0,
    )

    # get_all_source_ips
    ips = get_all_source_ips(packets)
    check(
        "get_all_source_ips returns 2 unique IPs",
        set(ips) == {"10.0.0.1", "10.0.0.2"},
        str(ips),
    )

    print(f"\n  {INFO}  Attacker stats snapshot:")
    for k, v in stats_attacker.items():
        print(f"          {k:25s} = {v}")

except ImportError as exc:
    check("traffic_stats import", False, f"Not found in {SCOUT_AGENT_DIR}: {exc}")

# ===========================================================================
# 3 — monte_carlo_threat_estimate()  (scout_agent/)
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 3 — monte_carlo_threat_estimate(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

if _traffic_stats_ok:
    try:
        from monte_carlo import monte_carlo_threat_estimate

        # High-threat stats (SYN flood)
        mc_high = monte_carlo_threat_estimate(stats_attacker, n_simulations=500)
        check("monte_carlo returns dict", isinstance(mc_high, dict), str(mc_high))
        check("has 'top_threat' key", "top_threat" in mc_high)
        check("has 'top_confidence' key", "top_confidence" in mc_high)
        check(
            "top_confidence in [0, 1]",
            0.0 <= mc_high.get("top_confidence", -1) <= 1.0,
            f"{mc_high.get('top_confidence'):.4f}",
        )

        # Low-threat stats (normal host)
        mc_low = monte_carlo_threat_estimate(stats_normal, n_simulations=500)
        check("monte_carlo (normal traffic) returns dict", isinstance(mc_low, dict))

        print(f"\n  {INFO}  Monte Carlo result (SYN flood):")
        for k, v in mc_high.items():
            print(f"          {k:25s} = {v}")

    except ImportError as exc:
        check("monte_carlo import", False, str(exc))
    except Exception as exc:
        check("monte_carlo_threat_estimate run", False, str(exc))
else:
    print(f"  {YELLOW}[SKIP]{RESET}  Skipped — traffic_stats not available")

# ===========================================================================
# 4 — format_threat_report()  (scout_agent/)
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 4 — format_threat_report(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

if _traffic_stats_ok:
    try:
        from reporter import format_threat_report

        mc_result = mc_high if 'mc_high' in dir() else {"top_threat": "ddos", "top_confidence": 0.85}

        report = format_threat_report(
            source_ip        = "10.0.0.1",
            stats            = stats_attacker,
            monte_carlo_result = mc_result,
            agent_id         = "scout-test",
        )
        check("format_threat_report returns dict", isinstance(report, dict), "")
        for expected_key in ("source_ip", "agent_id", "attack_type", "confidence", "stats"):
            check(
                f"report has key '{expected_key}'",
                expected_key in report,
                f"keys present: {list(report.keys())}",
            )
        check(
            "report source_ip is correct",
            report.get("source_ip") == "10.0.0.1",
            report.get("source_ip"),
        )

        print(f"\n  {INFO}  Threat report sample:")
        import json
        print("  " + json.dumps(report, indent=4, default=str).replace("\n", "\n  "))

    except ImportError as exc:
        check("reporter import", False, str(exc))
    except Exception as exc:
        check("format_threat_report run", False, str(exc))
else:
    print(f"  {YELLOW}[SKIP]{RESET}  Skipped — traffic_stats not available")

# ===========================================================================
# 5 — log_detection()  (scout_agent/)
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 5 — log_detection(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

try:
    # Import the function directly from the module
    import importlib.util, types

    scout_agent_path = os.path.join(SCOUT_AGENT_DIR, "scout_agent.py")

    if os.path.exists(scout_agent_path):
        spec = importlib.util.spec_from_file_location(
            "scout_agent_module", scout_agent_path
        )
        mod = importlib.util.module_from_spec(spec)

        # Redirect LOG_FILE to a temp file for the test
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tf:
            tmp_log = tf.name

        # Execute the module first, then override LOG_FILE in its globals
        spec.loader.exec_module(mod)   # type: ignore[union-attr]
        mod.LOG_FILE = tmp_log  # patch after exec so our value wins

        mod.log_detection("192.168.1.55", "DDoS",     0.92)
        mod.log_detection("10.10.10.10",  "PortScan", 0.75)

        with open(tmp_log) as fh:
            lines = fh.readlines()

        check("log_detection writes 2 lines", len(lines) == 2, f"got {len(lines)} lines")
        check(
            "line 1 contains 'DDoS'",
            "DDoS" in lines[0],
            lines[0].strip(),
        )
        check(
            "line 2 contains 'PortScan'",
            "PortScan" in lines[1],
            lines[1].strip(),
        )
        check(
            "line 1 contains source IP",
            "192.168.1.55" in lines[0],
            lines[0].strip(),
        )

        print(f"\n  {INFO}  Log entries written:")
        for ln in lines:
            print(f"          {ln.rstrip()}")

        os.unlink(tmp_log)

    else:
        print(f"  {YELLOW}[SKIP]{RESET}  scout_agent.py not found at {scout_agent_path}")

except Exception as exc:
    check("log_detection run", False, str(exc))

# ===========================================================================
# Summary
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed
colour = GREEN if failed == 0 else RED
print(f"{BOLD}{colour}  Scout Agent — {passed}/{total} checks passed{RESET}")
if failed:
    print(f"\n  {RED}Failed checks:{RESET}")
    for label, ok in results:
        if not ok:
            print(f"    • {label}")
print(f"{BOLD}{'='*60}{RESET}\n")

sys.exit(0 if failed == 0 else 1)
