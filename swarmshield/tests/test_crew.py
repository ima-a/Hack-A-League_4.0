"""
tests/test_crew.py
==================
Unit tests for CrewAI orchestration wiring.

All tests are fully offline — no real API calls, no iptables, no network.
CrewAI Agent/LLM construction is patched so tests run without API keys.
"""

import json
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Ensure src/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_agent(**kwargs) -> MagicMock:
    """Accept all keyword args that crewai.Agent() receives."""
    a = MagicMock()
    a.role = kwargs.get("role", "unknown")
    a.tools = kwargs.get("tools", [])
    return a


# ===========================================================================
# 1. Crew structural tests
# ===========================================================================

class TestCrewStructure(unittest.TestCase):
    def setUp(self):
        self._llm_patch = patch("swarmshield.crew._build_llm", return_value=MagicMock())
        self._llm_patch.start()

        self._agent_patch = patch("swarmshield.crew.Agent", side_effect=_mock_agent)
        self._agent_patch.start()

        def _task_factory(**kwargs):
            t = MagicMock()
            t.agent = kwargs.get("agent")
            t.context = kwargs.get("context", [])
            return t

        self._task_patch = patch("swarmshield.crew.Task", side_effect=_task_factory)
        self._task_patch.start()

        def _crew_factory(**kwargs):
            c = MagicMock()
            c.agents = kwargs.get("agents", [])
            c.tasks = kwargs.get("tasks", [])
            return c

        self._crew_patch = patch("swarmshield.crew.Crew", side_effect=_crew_factory)
        self._crew_patch.start()

    def tearDown(self):
        self._crew_patch.stop()
        self._task_patch.stop()
        self._agent_patch.stop()
        self._llm_patch.stop()

    def test_crew_builds_without_error(self):
        from swarmshield.crew import SwarmShieldCrew
        self.assertIsNotNone(SwarmShieldCrew().build())

    def test_crew_has_four_agents(self):
        from swarmshield.crew import SwarmShieldCrew
        self.assertEqual(len(SwarmShieldCrew().build().agents), 4)

    def test_crew_has_four_tasks(self):
        from swarmshield.crew import SwarmShieldCrew
        self.assertEqual(len(SwarmShieldCrew().build().tasks), 4)

    def test_agent_roles(self):
        from swarmshield.crew import SwarmShieldCrew
        roles = [a.role for a in SwarmShieldCrew().build().agents]
        self.assertIn("Network Traffic Scout", roles)
        self.assertIn("Threat Graph Analyzer", roles)
        self.assertIn("Autonomous Defense Responder", roles)
        self.assertIn("Adaptive Threshold Evolver (Mahoraga)", roles)

    def test_task_sequence(self):
        from swarmshield.crew import SwarmShieldCrew
        tasks = SwarmShieldCrew().build().tasks
        self.assertEqual(tasks[0].agent.role, "Network Traffic Scout")
        self.assertEqual(tasks[1].agent.role, "Threat Graph Analyzer")
        self.assertEqual(tasks[2].agent.role, "Autonomous Defense Responder")
        self.assertEqual(tasks[3].agent.role, "Adaptive Threshold Evolver (Mahoraga)")

    def test_context_chain(self):
        from swarmshield.crew import SwarmShieldCrew
        tasks = SwarmShieldCrew().build().tasks
        self.assertIn(tasks[0], tasks[1].context)   # analyzer <- scout
        self.assertIn(tasks[1], tasks[2].context)   # responder <- analyzer
        self.assertIn(tasks[2], tasks[3].context)   # evolver <- responder


# ===========================================================================
# 2. run_demo / run_batch kickoff tests
# ===========================================================================

class TestCrewKickoff(unittest.TestCase):
    def _mock_crew(self):
        c = MagicMock()
        c.agents = [_mock_agent(role=r) for r in [
            "Network Traffic Scout", "Threat Graph Analyzer",
            "Autonomous Defense Responder", "Adaptive Threshold Evolver (Mahoraga)",
        ]]
        c.tasks = [MagicMock() for _ in range(4)]
        return c

    def test_run_demo_calls_kickoff_once(self):
        from swarmshield.crew import SwarmShieldCrew
        mc = self._mock_crew()
        with patch.object(SwarmShieldCrew, "build", return_value=mc):
            SwarmShieldCrew().run_demo(iterations=1)
        mc.kickoff.assert_called_once()

    def test_run_demo_passes_traffic_input(self):
        from swarmshield.crew import SwarmShieldCrew
        mc = self._mock_crew()
        with patch.object(SwarmShieldCrew, "build", return_value=mc):
            SwarmShieldCrew().run_demo(iterations=1)
        call_args = mc.kickoff.call_args
        inputs = call_args[1].get("inputs") or (call_args[0][0] if call_args[0] else {})
        self.assertIn("traffic_input", inputs)

    def test_run_batch_loops(self):
        from swarmshield.crew import SwarmShieldCrew
        mc = self._mock_crew()
        with patch.object(SwarmShieldCrew, "build", return_value=mc):
            SwarmShieldCrew().run_batch(iterations=3)
        self.assertEqual(mc.kickoff.call_count, 3)

    def test_run_demo_survives_kickoff_exception(self):
        from swarmshield.crew import SwarmShieldCrew
        mc = self._mock_crew()
        mc.kickoff.side_effect = RuntimeError("simulated")
        with patch.object(SwarmShieldCrew, "build", return_value=mc):
            try:
                SwarmShieldCrew().run_demo(iterations=1)
            except RuntimeError:
                self.fail("run_demo should catch exceptions, not re-raise them")


# ===========================================================================
# 3. Scout tool tests
# ===========================================================================

# ---------------------------------------------------------------------------
# Helper: call a CrewAI Tool object (crewai 1.x wraps @tool in Tool class)
# ---------------------------------------------------------------------------
def _call(tool_obj, *args):
    """Call a crewai Tool via .run() — direct __call__ is not supported."""
    return tool_obj.run(*args)


class TestScoutTool(unittest.TestCase):
    def test_simulate_mixed_returns_json(self):
        from swarmshield.tools.scout_tool import simulate_attack_traffic
        r = json.loads(_call(simulate_attack_traffic, "mixed"))
        self.assertIn("threats", r)
        self.assertIn("packets_generated", r)

    def test_simulate_ddos_detects_threats(self):
        from swarmshield.tools.scout_tool import simulate_attack_traffic
        r = json.loads(_call(simulate_attack_traffic, "ddos"))
        self.assertGreater(r.get("threats_detected", 0), 0)

    def test_scan_network_returns_json(self):
        from swarmshield.tools.scout_tool import scan_network_for_threats
        r = json.loads(_call(scan_network_for_threats, "10"))
        self.assertIn("threats_detected", r)

    def test_monte_carlo_bad_input_returns_error(self):
        from swarmshield.tools.scout_tool import run_monte_carlo_analysis
        r = json.loads(_call(run_monte_carlo_analysis, "not-json"))
        self.assertIn("error", r)


# ===========================================================================
# 4. Analyzer tool tests
# ===========================================================================

class TestAnalyzerTool(unittest.TestCase):
    SCOUT_REPORT = json.dumps({"threats": [
        {"source_ip": "10.0.0.1", "attack_type": "DDoS", "confidence": 0.88},
        {"source_ip": "10.0.0.2", "attack_type": "PortScan", "confidence": 0.72},
    ]})

    def test_build_graph_node_count(self):
        from swarmshield.tools.analyzer_tool import build_threat_graph
        r = json.loads(_call(build_threat_graph, self.SCOUT_REPORT))
        self.assertEqual(r["summary"]["node_count"], 2)

    def test_propagation_has_risk_assessment(self):
        from swarmshield.tools.analyzer_tool import build_threat_graph, run_propagation_simulation
        graph = _call(build_threat_graph, self.SCOUT_REPORT)
        r = json.loads(_call(run_propagation_simulation, graph))
        self.assertIn("risk_level", r["risk_assessment"])

    def test_full_analysis_end_to_end(self):
        from swarmshield.tools.analyzer_tool import full_threat_analysis
        r = json.loads(_call(full_threat_analysis, self.SCOUT_REPORT))
        self.assertIn("threat_graph", r)
        self.assertIn("risk_assessment", r)

    def test_empty_report_zero_nodes(self):
        from swarmshield.tools.analyzer_tool import build_threat_graph
        r = json.loads(_call(build_threat_graph, '{"threats": []}'))
        self.assertEqual(r["summary"]["node_count"], 0)


# ===========================================================================
# 5. Responder tool tests (dry-run only)
# ===========================================================================

class TestResponderTool(unittest.TestCase):
    def setUp(self):
        os.environ["LIVE_MODE"] = "false"
        from swarmshield.tools import responder_tool
        responder_tool._DRY_RUN_ACTIONS.clear()
        # Reload LIVE_MODE flag inside the module
        responder_tool.LIVE_MODE = False

    def test_apply_actions_returns_actions_list(self):
        from swarmshield.tools.responder_tool import apply_defense_actions
        r = json.loads(_call(apply_defense_actions, json.dumps({
            "risk_assessment": {
                "risk_level": "high",
                "top_threats": [
                    {"ip": "10.0.0.1", "threat_type": "DDoS", "confidence": 0.90},
                ]
            }
        })))
        self.assertIn("actions_applied", r)
        self.assertGreater(len(r["actions_applied"]), 0)

    def test_block_ip_dry_run(self):
        from swarmshield.tools.responder_tool import block_ip_address
        r = json.loads(_call(block_ip_address, "10.0.0.99", "testing"))
        self.assertEqual(r["ip"], "10.0.0.99")
        self.assertEqual(r["action"], "block")

    def test_get_blocks_tracks_blocked_ips(self):
        from swarmshield.tools.responder_tool import block_ip_address, get_active_blocks
        _call(block_ip_address, "10.0.0.55")
        r = json.loads(_call(get_active_blocks))
        self.assertIn("10.0.0.55", r["blocked_ips"])

    def test_empty_threats_no_actions(self):
        from swarmshield.tools.responder_tool import apply_defense_actions
        r = json.loads(_call(apply_defense_actions, '{"risk_assessment": {"risk_level": "none", "top_threats": []}}'))
        self.assertEqual(r["actions_applied"], [])


# ===========================================================================
# 6. Evolution tool tests
# ===========================================================================

class TestEvolutionTool(unittest.TestCase):
    def test_get_thresholds_has_keys(self):
        from swarmshield.tools.evolution_tool import get_current_thresholds
        r = json.loads(_call(get_current_thresholds))
        for k in ["ddos_pps_threshold", "ddos_syn_threshold",
                  "port_scan_unique_ip_thresh", "exfil_bps_threshold"]:
            self.assertIn(k, r["best_thresholds"])

    def test_evolve_returns_genome_or_error(self):
        from swarmshield.tools.evolution_tool import evolve_detection_thresholds
        r = json.loads(_call(evolve_detection_thresholds, "{}"))
        self.assertTrue("best_genome" in r or "error" in r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
