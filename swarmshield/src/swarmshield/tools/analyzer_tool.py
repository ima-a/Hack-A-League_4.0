"""
Analyzer CrewAI Tools
======================
Wraps AnalyzerAgent methods as CrewAI @tool functions so the Analyzer
CrewAI Agent can call them during orchestrated task execution.

All tools:
- Accept/return plain strings (JSON-encoded where needed)
- Catch all exceptions and return a JSON error dict instead of raising
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# A2A bus helper — never raises
def _bus_publish(topic: str, message: dict) -> None:
    """Publish to the A2A message bus, silently ignoring any errors."""
    try:
        from ..utils.message_bus import get_bus
        get_bus().publish(topic, message)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Bus publish failed for topic '%s': %s", topic, exc)

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

try:
    from crewai.tools import tool as crewai_tool
    _CREWAI_AVAILABLE = True
except ImportError:
    logger.warning("crewai not installed — analyzer tools will not be registered as CrewAI tools.")
    _CREWAI_AVAILABLE = False

    def crewai_tool(name=None, description=None):  # type: ignore[misc]
        """Fallback no-op decorator when crewai is unavailable."""
        def decorator(fn):
            return fn
        return decorator


# ---------------------------------------------------------------------------
# Tool: build_threat_graph
# ---------------------------------------------------------------------------

@crewai_tool("build_threat_graph")
def build_threat_graph(scout_report_json: str) -> str:
    """
    Build a threat graph from a Scout threat report JSON.

    Accepts either:
      - A JSON object with a "threats" key (output of scan_network_for_threats
        or simulate_attack_traffic)
      - A JSON array of threat observation dicts directly

    Each threat observation should have at minimum:
      source_ip, attack_type, confidence

    Returns a JSON object:
      {
        "nodes": [...],
        "edges": [...],
        "summary": {node_count, edge_count, attack_types, max_confidence}
      }
    """
    try:
        from ..agents.analyzer import AnalyzerAgent

        raw = json.loads(scout_report_json)

        # Handle both direct list and wrapper dict from scout tools
        if isinstance(raw, dict):
            observations = raw.get("threats", [])
        elif isinstance(raw, list):
            observations = raw
        else:
            return json.dumps({"error": "scout_report_json must be a JSON object or array"})

        analyzer = AnalyzerAgent(name="Analyzer")
        threat_graph = analyzer.model_threat_graph(observations)
        return json.dumps(threat_graph, default=str)

    except Exception as exc:  # noqa: BLE001
        logger.exception("build_threat_graph error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Tool: run_propagation_simulation
# ---------------------------------------------------------------------------

@crewai_tool("run_propagation_simulation")
def run_propagation_simulation(threat_graph_json: str) -> str:
    """
    Run a Monte Carlo lateral-movement propagation simulation on a threat graph.

    Input: JSON object with "nodes" and "edges" keys (output of build_threat_graph).

    Returns a JSON object:
      {
        "simulation_results": [...],   # per-trial propagation results
        "risk_assessment": {           # aggregated risk assessment
          risk_level, risk_score, avg_spread, max_spread,
          top_threats, recommendations, timestamp
        }
      }
    """
    try:
        from ..agents.analyzer import AnalyzerAgent

        threat_graph = json.loads(threat_graph_json)
        if not isinstance(threat_graph, dict):
            return json.dumps({"error": "threat_graph_json must be a JSON object"})

        analyzer = AnalyzerAgent(name="Analyzer")

        # Run Monte Carlo simulation
        simulation_results = analyzer.simulate_attack(threat_graph)

        # Assess risk enriching with node data
        risk_context = {
            "nodes": threat_graph.get("nodes", []),
            "simulation_results": simulation_results,
        }
        risk_assessment = analyzer.assess_risk(risk_context)

        result = json.dumps({
            "simulation_results": simulation_results,
            "risk_assessment": risk_assessment,
        }, default=str)
        # A2A publish
        from ..utils.message_bus import TOPIC_ANALYZER_ASSESSMENT
        _bus_publish(TOPIC_ANALYZER_ASSESSMENT, {
            "risk_level": risk_assessment.get("risk_level", "unknown"),
            "risk_score": risk_assessment.get("risk_score", 0.0),
            "recommendations": risk_assessment.get("recommendations", []),
            "timestamp": _now_iso(),
            "agent_id": "analyzer-crewai",
        })
        return result

    except Exception as exc:  # noqa: BLE001
        logger.exception("run_propagation_simulation error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Tool: full_threat_analysis
# ---------------------------------------------------------------------------

@crewai_tool("full_threat_analysis")
def full_threat_analysis(scout_report_json: str) -> str:
    """
    Convenience tool: runs build_threat_graph AND run_propagation_simulation
    in one call.

    Accepts same input as build_threat_graph (Scout report JSON).

    Returns a combined JSON object:
      {
        "threat_graph": {nodes, edges, summary},
        "simulation_results": [...],
        "risk_assessment": {risk_level, risk_score, recommendations, ...}
      }
    """
    try:
        graph_json = build_threat_graph.run(scout_report_json)
        graph = json.loads(graph_json)
        if "error" in graph:
            return graph_json

        sim_json = run_propagation_simulation.run(graph_json)
        sim = json.loads(sim_json)
        if "error" in sim:
            return sim_json

        risk_assessment = sim.get("risk_assessment", {})
        result = json.dumps({
            "threat_graph": graph,
            "simulation_results": sim.get("simulation_results", []),
            "risk_assessment": risk_assessment,
        }, default=str)
        # A2A publish
        from ..utils.message_bus import TOPIC_ANALYZER_ASSESSMENT, TOPIC_ANALYZER_PREASSESS
        _bus_publish(TOPIC_ANALYZER_PREASSESS, {
            "preemptive_actions": risk_assessment.get("recommendations", []),
            "total_early_warnings": len(graph.get("nodes", [])),
            "timestamp": _now_iso(),
            "agent_id": "analyzer-crewai",
        })
        _bus_publish(TOPIC_ANALYZER_ASSESSMENT, {
            "risk_level": risk_assessment.get("risk_level", "unknown"),
            "risk_score": risk_assessment.get("risk_score", 0.0),
            "recommendations": risk_assessment.get("recommendations", []),
            "timestamp": _now_iso(),
            "agent_id": "analyzer-crewai",
        })
        return result

    except Exception as exc:  # noqa: BLE001
        logger.exception("full_threat_analysis error: %s", exc)
        return json.dumps({"error": str(exc)})
