"""
SwarmShield MCP Server
========================
Exposes all SwarmShield tools via the Model Context Protocol (MCP) so that
any MCP-compatible host (Claude Desktop, GitHub Copilot, etc.) can call them
directly — without needing to instantiate a full CrewAI crew. 

Tool catalogue (each tool is directly callable by an MCP host):
  Scout tools:
    - run_monte_carlo_analysis     Run MC scoring on raw packet JSON
    - scan_network_for_threats     Full detection cycle (synthetic traffic)
    - simulate_attack_traffic      Generate & analyse synthetic attack traffic

  Analyzer tools:
    - build_threat_graph           Build attack graph from scout report
    - run_propagation_simulation   Monte Carlo lateral-movement simulation
    - full_threat_analysis         Scout → graph → simulation in one call

  Responder tools:
    - apply_defense_actions        Apply enforcement actions from analyzer report
    - block_ip_address             Immediately block a single IP
    - get_active_blocks            List currently blocked IPs

  Evolution tools:
    - evolve_detection_thresholds  GA-evolve Scout thresholds (Mahoraga)
    - get_current_thresholds       Fetch best saved thresholds

  Bus resource:
    - swarmshield://bus/status     A2A message bus subscriber/topic status

Transport modes:
  stdio (default) — for Claude Desktop / VS Code Copilot / local tools
  streamable-http — for networked agents (pass --transport http)

Usage:
  # stdio (default)
  python -m swarmshield.mcp_server

  # HTTP on port 8765
  python -m swarmshield.mcp_server --transport http --port 8765

  # Via run.sh
  ./run.sh --mode mcp-server [--mcp-transport http] [--mcp-port 8765]
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("swarmshield.mcp_server")

# ---------------------------------------------------------------------------
# FastMCP — already installed as a dependency of crewai / mcp package
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:
    logger.error(
        "mcp package not found. Install it with: pip install 'mcp>=1.0.0'\n"
        "Error: %s", exc
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Load .env so LIVE_MODE / API keys are available when MCP host calls tools
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Ensure src/ is on sys.path when executed directly
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(__file__)
_SRC  = os.path.join(_HERE, "..", "..")
if _SRC not in sys.path:
    sys.path.insert(0, os.path.normpath(_SRC))

# ---------------------------------------------------------------------------
# Import SwarmShield tools
# ---------------------------------------------------------------------------
try:
    from swarmshield.tools.scout_tool import (
        run_monte_carlo_analysis    as _scout_mc,
        scan_network_for_threats    as _scout_scan,
        simulate_attack_traffic     as _scout_sim,
    )
    from swarmshield.tools.analyzer_tool import (
        build_threat_graph          as _ana_graph,
        run_propagation_simulation  as _ana_sim,
        full_threat_analysis        as _ana_full,
    )
    from swarmshield.tools.responder_tool import (
        apply_defense_actions       as _resp_apply,
        block_ip_address            as _resp_block,
        get_active_blocks           as _resp_blocks,
    )
    from swarmshield.tools.evolution_tool import (
        evolve_detection_thresholds as _evo_evolve,
        get_current_thresholds      as _evo_thresholds,
    )
    _TOOLS_OK = True
except Exception as exc:  # noqa: BLE001
    logger.error("Failed to import SwarmShield tools: %s", exc)
    _TOOLS_OK = False


# ===========================================================================
# FastMCP server
# ===========================================================================

mcp = FastMCP(
    name="SwarmShield",
    instructions=(
        "Autonomous network defense AI - exposes Scout, Analyzer, Responder, "
        "and Mahoraga Evolver tools via MCP. All tools return JSON strings."
    ),
)


# ---------------------------------------------------------------------------
# Helper: call a CrewAI Tool object (they use .run(), not direct __call__)
# ---------------------------------------------------------------------------

def _call(tool_obj: Any, *args: str) -> str:
    """
    Call a CrewAI Tool instance.

    CrewAI 1.x @tool decorator produces a Pydantic BaseTool subclass.
    These are NOT directly callable with () — they must use .run().
    """
    if hasattr(tool_obj, "run"):
        return tool_obj.run(*args) if args else tool_obj.run()
    # Fallback — plain function
    return tool_obj(*args) if args else tool_obj()


# ===========================================================================
# Scout tools
# ===========================================================================

@mcp.tool()
def run_monte_carlo_analysis(packets_json: str) -> str:
    """
    Analyse a JSON-encoded list of network packet dicts using Monte Carlo scoring.

    packets_json: JSON array of packet dicts, each with keys:
      src_ip, dst_ip, dst_port, protocol, size, timestamp, is_syn

    Returns a JSON object: {source_ips, threats, scan_summary, timestamp}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load - check logs"})
    return _call(_scout_mc, packets_json)


@mcp.tool()
def scan_network_for_threats(window_seconds: str = "10") -> str:
    """
    Run a full Scout detection cycle using synthetic network traffic.

    window_seconds: analysis window width as a string (default "10").
    Returns JSON: {threats_detected, threats, timestamp}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_scout_scan, window_seconds)


@mcp.tool()
def simulate_attack_traffic(attack_type: str = "mixed") -> str:
    """
    Generate & analyse synthetic attack traffic.

    attack_type: one of "ddos", "port_scan", "mixed" (default), "normal"
    Returns JSON: {attack_type_simulated, packets_generated,
                   threats_detected, threats, timestamp}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_scout_sim, attack_type)


# ===========================================================================
# Analyzer tools
# ===========================================================================

@mcp.tool()
def build_threat_graph(scout_report_json: str) -> str:
    """
    Build an attack graph from a Scout threat report.

    scout_report_json: JSON output of scan_network_for_threats or
                       simulate_attack_traffic.
    Returns JSON: {nodes, edges, summary}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_ana_graph, scout_report_json)


@mcp.tool()
def run_propagation_simulation(threat_graph_json: str) -> str:
    """
    Run Monte Carlo lateral-movement propagation on a threat graph.

    threat_graph_json: JSON output of build_threat_graph.
    Returns JSON: {simulation_results, risk_assessment}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_ana_sim, threat_graph_json)


@mcp.tool()
def full_threat_analysis(scout_report_json: str) -> str:
    """
    One-shot: Scout report → attack graph → propagation simulation.

    Equivalent to calling build_threat_graph then run_propagation_simulation.
    Returns JSON: {threat_graph, simulation_results, risk_assessment}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_ana_full, scout_report_json)


# ===========================================================================
# Responder tools
# ===========================================================================

@mcp.tool()
def apply_defense_actions(analyzer_report_json: str) -> str:
    """
    Apply defense actions from an analyzer risk report.

    analyzer_report_json: JSON output of full_threat_analysis or
                          run_propagation_simulation.
    LIVE_MODE env var controls whether real iptables rules are applied.
    Returns JSON: {actions_applied, summary, risk_level, live_mode, timestamp}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_resp_apply, analyzer_report_json)


@mcp.tool()
def block_ip_address(ip_address: str, reason: str = "manual_block") -> str:
    """
    Block all traffic from an IP address.

    ip_address: IPv4/IPv6 address to block.
    reason: human-readable reason for the block (optional).
    In dry-run mode (LIVE_MODE != true) no iptables rule is added.
    Returns JSON: {ip, action, success, mode, reason, timestamp}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_resp_block, ip_address)


@mcp.tool()
def get_active_blocks() -> str:
    """
    Return the current list of blocked IP addresses.

    In live mode reads blocked_ips.txt.
    In dry-run mode returns the in-memory session log.
    Returns JSON: {blocked_ips, dry_run_actions, mode, timestamp}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_resp_blocks)


# ===========================================================================
# Evolution (Mahoraga) tools
# ===========================================================================

@mcp.tool()
def evolve_detection_thresholds(responder_summary_json: str = "{}") -> str:
    """
    Run the Mahoraga genetic algorithm to evolve Scout detection thresholds.

    responder_summary_json: JSON output of apply_defense_actions (optional).
    Returns JSON: {best_genome, best_thresholds, confidence_threshold,
                   best_fitness, generations_run, outcomes_used, timestamp}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_evo_evolve, responder_summary_json)


@mcp.tool()
def get_current_thresholds() -> str:
    """
    Fetch the most recently evolved Scout detection thresholds.

    Returns the best saved genome or the factory defaults if Mahoraga
    has not yet run.
    Returns JSON: {best_genome, best_thresholds, confidence_threshold,
                   best_fitness, generations_run, outcomes_used, source}
    """
    if not _TOOLS_OK:
        return json.dumps({"error": "SwarmShield tools failed to load"})
    return _call(_evo_thresholds)


# ===========================================================================
# A2A bus status resource
# ===========================================================================

@mcp.resource("swarmshield://bus/status")
def bus_status() -> str:
    """
    A2A message bus status.

    Returns a JSON object describing the current state of the in-process
    pub/sub message bus: active topics, subscriber counts, and total
    messages published since process start.
    """
    try:
        from swarmshield.utils.message_bus import get_bus, ALL_TOPICS
        bus = get_bus()
        topic_info = {}
        for topic in ALL_TOPICS:
            topic_info[topic] = {
                "subscribers": bus.subscriber_count(topic),
                "active": bus.subscriber_count(topic) > 0,
            }
        return json.dumps({
            "bus_repr": repr(bus),
            "total_messages_published": bus.message_count,
            "active_topics": bus.topics(),
            "all_topics": topic_info,
        }, indent=2)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc)})


# ===========================================================================
# CLI entry point
# ===========================================================================

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="swarmshield-mcp",
        description="SwarmShield MCP Server — exposes all tools via Model Context Protocol",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport mode: 'stdio' for local MCP hosts (default), "
             "'http' for networked agents.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="HTTP port when --transport http is used (default: 8765).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP bind address when --transport http is used (default: 127.0.0.1).",
    )
    args = parser.parse_args()

    if args.transport == "http":
        logger.info(
            "Starting SwarmShield MCP server in HTTP mode on %s:%d",
            args.host, args.port,
        )
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        logger.info("Starting SwarmShield MCP server in stdio mode")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
