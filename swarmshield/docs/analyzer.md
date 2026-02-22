# Analyzer Agent

Source: src/swarmshield/agents/analyzer.py

## What it does

The Analyzer Agent is the second stage in the SwarmShield pipeline. It takes Scout threat observation reports and:

1. Builds a threat graph (nodes are source IPs, edges are inferred coordination links).
2. Runs a Monte Carlo lateral-movement propagation simulation over the graph.
3. Produces a risk assessment with a risk level, risk score, spread metrics, and ranked action recommendations.

## Inputs

A list of Scout threat observation dicts. Common fields:

    source_ip       string
    attack_type     string (DDoS, PortScan, Exfiltration)
    confidence      float (0.0 to 1.0)
    monte_carlo     dict (optional, passthrough from Scout)
    agent_id        string (optional)
    timestamp       string (optional)

## Threat graph

### Nodes

Nodes are deduplicated by source_ip. If a source IP appears multiple times, the observation with the highest confidence is used.

Node fields: ip, threat_type, confidence, monte_carlo, agent_id, timestamp.

### Edges

An edge is inferred between two nodes when both share the same threat_type and both have confidence above 0.50. Edge weight is the average confidence of the two nodes.

## Propagation simulation

Each Monte Carlo trial:
1. Picks an entry node weighted by confidence.
2. Attempts to traverse each outbound edge with probability based on edge weight plus small Gaussian noise.
3. Records how many nodes were reached (path_length, compromised_ips).

Per-trial result keys: trial, entry_node, nodes_reached, path_length, compromised_ips.

## Risk scoring

    risk_score = min(1.0, 0.6 * max_confidence + 0.4 * avg_spread)

Risk level thresholds:
- high:   risk_score >= 0.70
- medium: risk_score >= 0.40
- low:    risk_score > 0.0
- none:   risk_score = 0.0 and no edges

## Optional LLM enrichment

If XAI_API_KEY is set and an LLMClient is passed to AnalyzerAgent(llm_client=...), assess_risk() attaches an llm_insight block with correlation type (coordinated, independent, or unclear), lateral movement risk, containment priority, and recommended actions. The LLM output is purely advisory. Deterministic scores are never changed.

## CrewAI tools

The Analyzer exposes three CrewAI @tool functions in tools/analyzer_tool.py:

    build_threat_graph(scout_report_json)         - build attack graph from Scout output
    run_propagation_simulation(threat_graph_json) - run MC propagation on the graph
    full_threat_analysis(scout_report_json)       - graph + simulation in one call

## Public API (AnalyzerAgent)

    model_threat_graph(observations) -> {nodes, edges, summary}
    simulate_attack(threat_graph) -> list of trial dicts
    assess_risk(simulation_results_or_context_dict) -> dict
