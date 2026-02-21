"""
run_scout_agent.py — SwarmShield

Smoke test for the Scout Agent.
All logic is exercised through ScoutAgent in
src/swarmshield/agents/scout.py — no external dependencies.

Sections:
    1. Instantiation
    2. capture_packets()       — synthetic packet window
    3. compute_stats()         — per-IP traffic statistics
    4. monte_carlo_estimate()  — probabilistic threat scoring
    5. format_report()         — threat report builder
    6. log_detection()         — file logger
    7. scan_network()          — full scan cycle
    8. detect_anomalies()      — full detection cycle

Usage (from swarmshield/ directory):
    .venv/bin/python tests/run_scout_agent.py
"""

import json
import os
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
GREEN = "\033[92m"; RED = "\033[91m"; CYAN = "\033[96m"
BOLD  = "\033[1m";  RESET = "\033[0m"
PASS  = f"{GREEN}[PASS]{RESET}"; FAIL = f"{RED}[FAIL]{RESET}"
INFO  = f"{CYAN}[INFO]{RESET}"

results = []

def check(label: str, ok: bool, detail: str = ""):
    tag = PASS if ok else FAIL
    msg = f"  {tag}  {label}"
    if detail:
        msg += f"  →  {detail}"
    print(msg)
    results.append((label, ok))

# ===========================================================================
# Import
# ===========================================================================
try:
    from src.swarmshield.agents.scout import ScoutAgent
except Exception as exc:
    print(f"{RED}  FATAL: cannot import ScoutAgent: {exc}{RESET}")
    sys.exit(1)

# ===========================================================================
# Section 1 — Instantiation
# ===========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 1 — Instantiation{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

scout = ScoutAgent()
check("ScoutAgent() instantiation",   True)
check("name == 'Scout'",              scout.name == "Scout",     repr(scout.name))
check("agent_id == 'scout-1'",        scout.agent_id == "scout-1")

scout2 = ScoutAgent(name="Scout", agent_id="scout-node-2")
check("custom agent_id accepted",     scout2.agent_id == "scout-node-2")

# ===========================================================================
# Section 2 — capture_packets()
# ===========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 2 — capture_packets(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

packets = scout.capture_packets(window_seconds=10)
check("returns a list",               isinstance(packets, list))
check("non-empty",                    len(packets) > 0,          f"{len(packets)} packets")

first = packets[0]
for key in ("src_ip", "dst_ip", "dst_port", "protocol", "size", "timestamp", "is_syn"):
    check(f"packet has key '{key}'",  key in first,              str(first.get(key, "MISSING")))

src_ips = ScoutAgent.get_all_source_ips(packets)
check(">=2 unique source IPs",        len(src_ips) >= 2,         str(src_ips))

print(f"\n  {INFO}  Packet count: {len(packets)}")
print(f"  {INFO}  Source IPs observed: {src_ips}")
print(f"  {INFO}  Sample packet: {first}")

# ===========================================================================
# Section 3 — compute_stats()
# ===========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 3 — compute_stats(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

now = time.time()
syn_packets = []
for i in range(400):
    syn_packets.append({
        "src_ip": "10.99.0.1", "dst_ip": "192.168.1.1",
        "dst_port": 80, "protocol": "TCP", "size": 60,
        "timestamp": now - (i % 10), "is_syn": True,
    })
for i in range(8):
    syn_packets.append({
        "src_ip": "10.99.0.2", "dst_ip": f"10.0.0.{i}",
        "dst_port": 443, "protocol": "TCP", "size": 800,
        "timestamp": now - i, "is_syn": False,
    })

stats_attacker = ScoutAgent.compute_stats(syn_packets, "10.99.0.1", 10)
check("returns dict",                 isinstance(stats_attacker, dict))
check("packets_per_second > 0",       stats_attacker["packets_per_second"] > 0,
      f"{stats_attacker['packets_per_second']:.1f} pkt/s")
check("syn_count > 0",                stats_attacker["syn_count"] > 0,
      f"syn_count={stats_attacker['syn_count']}")

stats_normal = ScoutAgent.compute_stats(syn_packets, "10.99.0.2", 10)
check("normal host syn_count == 0",   stats_normal["syn_count"] == 0,
      f"syn_count={stats_normal['syn_count']}")

stats_unknown = ScoutAgent.compute_stats(syn_packets, "1.2.3.4", 10)
check("unknown IP pps == 0.0",        stats_unknown["packets_per_second"] == 0.0)

print(f"\n  {INFO}  Attacker traffic stats:")
for k, v in stats_attacker.items():
    print(f"          {k:28s} = {v}")

# ===========================================================================
# Section 4 — monte_carlo_estimate()
# ===========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 4 — monte_carlo_estimate(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

mc_attack = ScoutAgent.monte_carlo_estimate(stats_attacker, n_simulations=500)
check("returns dict",                 isinstance(mc_attack, dict))
check("has 'top_threat' key",         "top_threat"      in mc_attack)
check("has 'top_confidence' key",     "top_confidence"  in mc_attack)
check("top_confidence in [0,1]",
      0.0 <= mc_attack["top_confidence"] <= 1.0,
      f"{mc_attack['top_confidence']:.4f}")
check("DDoS detected for SYN flood",
      mc_attack["top_threat"] == "ddos",
      mc_attack["top_threat"])

scan_stats = {
    "packets_per_second": 5.0, "bytes_per_second": 320.0,
    "unique_dest_ips": 45, "syn_count": 5, "port_entropy": 5.8,
    "window_seconds": 10,
}
mc_scan = ScoutAgent.monte_carlo_estimate(scan_stats, n_simulations=500)
check("PortScan detected for high-entropy stats",
      mc_scan["top_threat"] == "port_scan",
      f"top={mc_scan['top_threat']} conf={mc_scan['top_confidence']:.4f}")

print(f"\n  {INFO}  Monte Carlo (SYN flood):")
for k, v in mc_attack.items():
    print(f"          {k:28s} = {v}")

# ===========================================================================
# Section 5 — format_report()
# ===========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 5 — format_report(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

report = ScoutAgent.format_report("10.99.0.1", stats_attacker, mc_attack, "scout-1")
check("returns dict",                 isinstance(report, dict))
for key in ("source_ip","agent_id","attack_type","confidence","stats","monte_carlo","timestamp"):
    check(f"key '{key}' present",     key in report, str(report.get(key, "MISSING")))
check("source_ip correct",            report["source_ip"] == "10.99.0.1")
check("attack_type == 'DDoS'",        report["attack_type"] == "DDoS",  report["attack_type"])
check("confidence in [0,1]",          0.0 <= report["confidence"] <= 1.0)

print(f"\n  {INFO}  Threat report:")
print("  " + json.dumps(report, indent=4, default=str).replace("\n", "\n  "))

# ===========================================================================
# Section 6 — log_detection()
# ===========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 6 — log_detection(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as tf:
    tmp_log = tf.name

try:
    ScoutAgent.log_detection("192.168.1.55", "DDoS",     0.92, tmp_log)
    ScoutAgent.log_detection("10.10.10.10",  "PortScan", 0.75, tmp_log)

    with open(tmp_log) as fh:
        lines = fh.readlines()

    check("2 lines written",                  len(lines) == 2,        f"got {len(lines)}")
    check("line 1 contains 'DDoS'",           "DDoS"         in lines[0], lines[0].strip())
    check("line 1 contains source IP",        "192.168.1.55" in lines[0])
    check("line 2 contains 'PortScan'",       "PortScan"     in lines[1], lines[1].strip())
    check("line 2 contains confidence",       "0.7500"       in lines[1])

    print(f"\n  {INFO}  Log entries:")
    for ln in lines:
        print(f"          {ln.rstrip()}")
finally:
    os.unlink(tmp_log)

# ===========================================================================
# Section 7 — scan_network()
# ===========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 7 — scan_network(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

result = scout.scan_network()
check("returns dict",                 isinstance(result, dict))
check("has 'source_ips' key",         "source_ips" in result)
check("has 'findings' key",           "findings"   in result)
check("has 'timestamp' key",          "timestamp"  in result)
check("source_ips is list",           isinstance(result["source_ips"], list))
check(">=1 source IP found",          len(result["source_ips"]) >= 1,
      str(result["source_ips"]))

for ip, data in result["findings"].items():
    check(f"  {ip}: has threat_level",
          "threat_level" in data, data.get("threat_level"))

print(f"\n  {INFO}  scan_network() findings:")
for ip, data in result["findings"].items():
    mc = data["monte_carlo"]; st = data["stats"]
    print(f"          {ip:<15s}  threat={mc['top_threat']:<14s}"
          f"  conf={mc['top_confidence']:.2f}"
          f"  level={data['threat_level']}"
          f"  pps={st['packets_per_second']:.0f}")

# ===========================================================================
# Section 8 — detect_anomalies()
# ===========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 8 — detect_anomalies(){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

anomalies = scout.detect_anomalies(confidence_threshold=0.01)
check("returns list",                 isinstance(anomalies, list))
check(">=1 anomaly detected",         len(anomalies) >= 1,
      f"{len(anomalies)} anomaly/anomalies")

if anomalies:
    a = anomalies[0]
    check("anomaly has 'source_ip'",    "source_ip"   in a)
    check("anomaly has 'attack_type'",  "attack_type" in a)
    check("anomaly has 'confidence'",   "confidence"  in a)
    check("anomaly has 'stats'",        "stats"       in a)
    check("anomaly confidence > 0",     a["confidence"] > 0,
          f"{a['confidence']:.4f}")

    print(f"\n  {INFO}  Detected anomalies:")
    for threat in anomalies:
        print(f"          source={threat['source_ip']:<15s}"
              f"  attack={threat['attack_type']:<14s}"
              f"  confidence={threat['confidence']:.4f}")

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
