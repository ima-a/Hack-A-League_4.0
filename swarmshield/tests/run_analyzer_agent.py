"""
run_analyzer_agent.py — SwarmShield

Manual end-to-end smoke test for the Analyzer Agent pipeline.

Tests:
    1.  AnalyzerAgent class         — init, model_threat_graph(),
                                       simulate_attack(), assess_risk()
    2.  ThreatSimTool               — init, execute()
    3.  Full pipeline               — Scout observations → threat graph
                                       → simulation → risk assessment
    4.  Edge cases                  — empty inputs, single observation,
                                       repeated calls for idempotency

Usage (from swarmshield/ directory):
    .venv/bin/python tests/run_analyzer_agent.py
"""

import json
import os
import sys

# ---------------------------------------------------------------------------
# Ensure the swarmshield project root (contains src/) is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

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


# ---------------------------------------------------------------------------
# Sample data — realistic Scout observations fed to the Analyzer
# ---------------------------------------------------------------------------

SAMPLE_OBSERVATIONS = [
    {
        "source_ip":     "203.0.113.42",
        "agent_id":      "scout-alpha",
        "event":         "threat_detected",
        "attack_type":   "DDoS",
        "confidence":    0.94,
        "stats": {
            "packets_per_second": 1200.0,
            "bytes_per_second":   76800.0,
            "unique_dest_ips":    1,
            "syn_count":          1100,
            "port_entropy":       0.0,
            "window_seconds":     10,
        },
        "monte_carlo": {
            "ddos_confidence":         0.94,
            "port_scan_confidence":    0.02,
            "exfiltration_confidence": 0.01,
            "top_threat":              "ddos",
            "top_confidence":          0.94,
        },
        "timestamp": "2026-02-21T12:00:00Z",
    },
    {
        "source_ip":     "198.51.100.7",
        "agent_id":      "scout-alpha",
        "event":         "threat_detected",
        "attack_type":   "PortScan",
        "confidence":    0.82,
        "stats": {
            "packets_per_second": 45.0,
            "bytes_per_second":   2880.0,
            "unique_dest_ips":    38,
            "syn_count":          45,
            "port_entropy":       5.2,
            "window_seconds":     10,
        },
        "monte_carlo": {
            "ddos_confidence":         0.03,
            "port_scan_confidence":    0.82,
            "exfiltration_confidence": 0.05,
            "top_threat":              "port_scan",
            "top_confidence":          0.82,
        },
        "timestamp": "2026-02-21T12:00:05Z",
    },
    {
        "source_ip":     "172.16.0.55",
        "agent_id":      "scout-beta",
        "event":         "threat_detected",
        "attack_type":   "Exfiltration",
        "confidence":    0.71,
        "stats": {
            "packets_per_second": 8.0,
            "bytes_per_second":   620000.0,
            "unique_dest_ips":    2,
            "syn_count":          0,
            "port_entropy":       0.8,
            "window_seconds":     10,
        },
        "monte_carlo": {
            "ddos_confidence":         0.02,
            "port_scan_confidence":    0.01,
            "exfiltration_confidence": 0.71,
            "top_threat":              "exfiltration",
            "top_confidence":          0.71,
        },
        "timestamp": "2026-02-21T12:00:10Z",
    },
]

NORMAL_OBSERVATION = {
    "source_ip":     "10.0.0.5",
    "agent_id":      "scout-alpha",
    "event":         "normal",
    "attack_type":   "Normal",
    "confidence":    0.12,
    "stats": {
        "packets_per_second": 2.0,
        "bytes_per_second":   128.0,
        "unique_dest_ips":    1,
        "syn_count":          1,
        "port_entropy":       0.5,
        "window_seconds":     10,
    },
    "monte_carlo": {
        "ddos_confidence":         0.02,
        "port_scan_confidence":    0.03,
        "exfiltration_confidence": 0.01,
        "top_threat":              "normal",
        "top_confidence":          0.12,
    },
    "timestamp": "2026-02-21T12:00:15Z",
}


# ===========================================================================
# 1 — AnalyzerAgent class
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 1 — AnalyzerAgent class{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

_analyzer_ok = False
analyzer = None

try:
    from src.swarmshield.agents.analyzer import AnalyzerAgent

    # --- Instantiation -------------------------------------------------------
    analyzer = AnalyzerAgent()
    check("AnalyzerAgent instantiation", True)
    check("analyzer.name == 'Analyzer'", analyzer.name == "Analyzer", repr(analyzer.name))

    # Custom name
    custom = AnalyzerAgent(name="analyzer-node-1")
    check("custom name accepted", custom.name == "analyzer-node-1", repr(custom.name))

    _analyzer_ok = True

except Exception as exc:
    check("AnalyzerAgent import/init", False, str(exc))

# ---------------------------------------------------------------------------
# 1a — model_threat_graph()
# ---------------------------------------------------------------------------

print(f"\n  {CYAN}model_threat_graph(){RESET}")

if _analyzer_ok:
    # Multiple observations
    graph = analyzer.model_threat_graph(SAMPLE_OBSERVATIONS)
    check("returns a dict", isinstance(graph, dict), type(graph).__name__)

    # Empty observations
    empty_graph = analyzer.model_threat_graph([])
    check("empty observations → dict", isinstance(empty_graph, dict))

    # Single observation
    single_graph = analyzer.model_threat_graph([SAMPLE_OBSERVATIONS[0]])
    check("single observation → dict", isinstance(single_graph, dict))

    # Normal traffic observation
    normal_graph = analyzer.model_threat_graph([NORMAL_OBSERVATION])
    check("normal traffic observation → dict", isinstance(normal_graph, dict))

    print(f"\n  {INFO}  model_threat_graph(3 observations) → {graph}")
else:
    print(f"  {YELLOW}[SKIP]{RESET}  AnalyzerAgent not available")

# ---------------------------------------------------------------------------
# 1b — simulate_attack()
# ---------------------------------------------------------------------------

print(f"\n  {CYAN}simulate_attack(){RESET}")

if _analyzer_ok:
    threat_graph_input = graph if isinstance(graph, dict) else {}

    sim_results = analyzer.simulate_attack(threat_graph_input)
    check("returns a list", isinstance(sim_results, list), type(sim_results).__name__)

    # Empty graph input
    sim_empty = analyzer.simulate_attack({})
    check("empty graph → list", isinstance(sim_empty, list))

    # Non-empty graph (structured like a real output might look)
    mock_graph = {
        "nodes": [
            {"ip": "203.0.113.42", "threat": "DDoS",     "confidence": 0.94},
            {"ip": "198.51.100.7", "threat": "PortScan", "confidence": 0.82},
        ],
        "edges": [
            {"src": "203.0.113.42", "dst": "198.51.100.7", "weight": 0.3}
        ],
    }
    sim_mock = analyzer.simulate_attack(mock_graph)
    check("structured graph → list", isinstance(sim_mock, list))

    print(f"\n  {INFO}  simulate_attack(graph) → {sim_results}")
else:
    print(f"  {YELLOW}[SKIP]{RESET}  AnalyzerAgent not available")

# ---------------------------------------------------------------------------
# 1c — assess_risk()
# ---------------------------------------------------------------------------

print(f"\n  {CYAN}assess_risk(){RESET}")

if _analyzer_ok:
    risk = analyzer.assess_risk(sim_results)
    check("returns a dict", isinstance(risk, dict), type(risk).__name__)

    # Empty simulation results
    risk_empty = analyzer.assess_risk([])
    check("empty sim results → dict", isinstance(risk_empty, dict))

    # Realistic simulation results
    mock_sim = [
        {"scenario": 1, "attacker": "203.0.113.42", "impact": "high",   "propagation": 0.9},
        {"scenario": 2, "attacker": "198.51.100.7", "impact": "medium", "propagation": 0.4},
        {"scenario": 3, "attacker": "172.16.0.55",  "impact": "low",    "propagation": 0.2},
    ]
    risk_mock = analyzer.assess_risk(mock_sim)
    check("structured sim results → dict", isinstance(risk_mock, dict))

    print(f"\n  {INFO}  assess_risk(sim_results) → {risk}")
else:
    print(f"  {YELLOW}[SKIP]{RESET}  AnalyzerAgent not available")

# ===========================================================================
# 2 — ThreatSimTool
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 2 — ThreatSimTool{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

try:
    from src.swarmshield.tools.threat_sim_tool import ThreatSimTool

    tool = ThreatSimTool()
    check("ThreatSimTool instantiation", True)

    # --- execute() with empty input ------------------------------------------
    result_empty = tool.execute({})
    check("execute({}) → dict", isinstance(result_empty, dict), type(result_empty).__name__)
    for key in ("attack_graph", "simulation_results", "predicted_impact"):
        check(
            f"result has key '{key}'",
            key in result_empty,
            f"keys: {list(result_empty.keys())}",
        )

    # --- execute() with DDoS threat data -------------------------------------
    ddos_data = {
        "source_ip":   "203.0.113.42",
        "attack_type": "DDoS",
        "confidence":  0.94,
        "stats": SAMPLE_OBSERVATIONS[0]["stats"],
    }
    result_ddos = tool.execute(ddos_data)
    check("execute(DDoS data) → dict", isinstance(result_ddos, dict))
    check(
        "attack_graph is a dict",
        isinstance(result_ddos.get("attack_graph"), dict),
        type(result_ddos.get("attack_graph")).__name__,
    )
    check(
        "simulation_results is a list",
        isinstance(result_ddos.get("simulation_results"), list),
        type(result_ddos.get("simulation_results")).__name__,
    )
    check(
        "predicted_impact is numeric",
        isinstance(result_ddos.get("predicted_impact"), (int, float)),
        str(result_ddos.get("predicted_impact")),
    )

    # --- execute() with PortScan threat data ---------------------------------
    scan_data = {
        "source_ip":   "198.51.100.7",
        "attack_type": "PortScan",
        "confidence":  0.82,
        "stats": SAMPLE_OBSERVATIONS[1]["stats"],
    }
    result_scan = tool.execute(scan_data)
    check("execute(PortScan data) → dict", isinstance(result_scan, dict))

    print(f"\n  {INFO}  ThreatSimTool.execute() result:")
    print("  " + json.dumps(result_ddos, indent=4, default=str).replace("\n", "\n  "))

except Exception as exc:
    check("ThreatSimTool import/run", False, str(exc))

# ===========================================================================
# 3 — Full analysis pipeline
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 3 — Full pipeline (observations → assess_risk){RESET}")
print(f"{BOLD}{'='*60}{RESET}")

if _analyzer_ok:

    print(f"\n  {CYAN}Pipeline A — Multi-threat scenario (DDoS + PortScan + Exfil){RESET}")
    try:
        g   = analyzer.model_threat_graph(SAMPLE_OBSERVATIONS)
        s   = analyzer.simulate_attack(g)
        r   = analyzer.assess_risk(s)

        check("pipeline A: model_threat_graph → dict", isinstance(g, dict))
        check("pipeline A: simulate_attack → list",    isinstance(s, list))
        check("pipeline A: assess_risk → dict",        isinstance(r, dict))

        print(f"  {INFO}  threat_graph={g}")
        print(f"  {INFO}  simulations={s}")
        print(f"  {INFO}  risk_assessment={r}")

    except Exception as exc:
        check("pipeline A run", False, str(exc))

    print(f"\n  {CYAN}Pipeline B — Single high-confidence DDoS{RESET}")
    try:
        g2  = analyzer.model_threat_graph([SAMPLE_OBSERVATIONS[0]])
        s2  = analyzer.simulate_attack(g2)
        r2  = analyzer.assess_risk(s2)

        check("pipeline B: model_threat_graph → dict", isinstance(g2, dict))
        check("pipeline B: simulate_attack → list",    isinstance(s2, list))
        check("pipeline B: assess_risk → dict",        isinstance(r2, dict))

    except Exception as exc:
        check("pipeline B run", False, str(exc))

    print(f"\n  {CYAN}Pipeline C — Normal traffic (no threat){RESET}")
    try:
        g3  = analyzer.model_threat_graph([NORMAL_OBSERVATION])
        s3  = analyzer.simulate_attack(g3)
        r3  = analyzer.assess_risk(s3)

        check("pipeline C: model_threat_graph → dict", isinstance(g3, dict))
        check("pipeline C: simulate_attack → list",    isinstance(s3, list))
        check("pipeline C: assess_risk → dict",        isinstance(r3, dict))

    except Exception as exc:
        check("pipeline C run", False, str(exc))

else:
    print(f"  {YELLOW}[SKIP]{RESET}  AnalyzerAgent not available")

# ===========================================================================
# 4 — Edge cases
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 4 — Edge cases{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

if _analyzer_ok:

    # --- All-empty pipeline --------------------------------------------------
    print(f"\n  {CYAN}All-empty inputs{RESET}")
    try:
        g_e = analyzer.model_threat_graph([])
        s_e = analyzer.simulate_attack({})
        r_e = analyzer.assess_risk([])
        check("empty → model_threat_graph returns dict",  isinstance(g_e, dict))
        check("empty → simulate_attack returns list",     isinstance(s_e, list))
        check("empty → assess_risk returns dict",         isinstance(r_e, dict))
    except Exception as exc:
        check("empty inputs pipeline run", False, str(exc))

    # --- Idempotency — same input twice gives the same type(s) ---------------
    print(f"\n  {CYAN}Idempotency — two identical calls{RESET}")
    try:
        obs = [SAMPLE_OBSERVATIONS[0]]
        r_first  = analyzer.model_threat_graph(obs)
        r_second = analyzer.model_threat_graph(obs)
        check(
            "model_threat_graph is idempotent (both dicts)",
            isinstance(r_first, dict) and isinstance(r_second, dict),
        )
    except Exception as exc:
        check("idempotency check", False, str(exc))

    # --- Large observation list (stress) -------------------------------------
    print(f"\n  {CYAN}Stress — 100 observations{RESET}")
    try:
        many_obs = []
        for i in range(100):
            entry = dict(SAMPLE_OBSERVATIONS[i % len(SAMPLE_OBSERVATIONS)])
            entry["source_ip"] = f"10.{i // 256}.{i % 256}.1"
            many_obs.append(entry)

        g_stress = analyzer.model_threat_graph(many_obs)
        s_stress = analyzer.simulate_attack(g_stress)
        r_stress = analyzer.assess_risk(s_stress)

        check("stress: model_threat_graph → dict", isinstance(g_stress, dict))
        check("stress: simulate_attack → list",    isinstance(s_stress, list))
        check("stress: assess_risk → dict",        isinstance(r_stress, dict))

    except Exception as exc:
        check("stress run", False, str(exc))

    # --- Missing keys in observation -----------------------------------------
    print(f"\n  {CYAN}Malformed observation (missing keys){RESET}")
    try:
        bad_obs = [{"source_ip": "1.2.3.4"}]   # missing attack_type, stats, etc.
        g_bad = analyzer.model_threat_graph(bad_obs)
        check("malformed obs → model_threat_graph does not crash", True)
        check("malformed obs → returns dict", isinstance(g_bad, dict))
    except Exception as exc:
        # Crashing on bad input is also informative — report it clearly
        check("malformed obs → model_threat_graph does not crash", False, str(exc))

else:
    print(f"  {YELLOW}[SKIP]{RESET}  AnalyzerAgent not available")

# ===========================================================================
# Summary
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed
colour = GREEN if failed == 0 else RED
print(f"{BOLD}{colour}  Analyzer Agent — {passed}/{total} checks passed{RESET}")
if failed:
    print(f"\n  {RED}Failed checks:{RESET}")
    for label, ok in results:
        if not ok:
            print(f"    • {label}")
print(f"{BOLD}{'='*60}{RESET}\n")

sys.exit(0 if failed == 0 else 1)
