# Analyzer Agent

Source: `src/swarmshield/agents/analyzer.py`

## What it does
The Analyzer Agent takes a list of Scout threat observation reports and:
1. Builds a simple **threat graph** (nodes = source IPs, edges = inferred relationships).
2. Runs **Monte Carlo propagation** simulations across the graph.
3. Produces a **risk assessment** (risk level, score, spread metrics, and recommended actions).

The output of the Analyzer is intended to drive a response decision (e.g., block, redirect to honeypot, quarantine).

## Inputs
### Threat observation schema (from Scout)
The Analyzer expects a list of dicts; each dict typically includes:
- `source_ip`
- `attack_type`
- `confidence`
- `monte_carlo` (optional)
- `agent_id` (optional)
- `timestamp` (optional)

## Key sections in the implementation
### 1) Constants
- `N_SIM_TRIALS`: number of Monte Carlo propagation trials
- `RISK_HIGH`, `RISK_MEDIUM`: score thresholds for risk levels

### 2) Node building (`_build_nodes`)
`_build_nodes(observations)` deduplicates by `source_ip` and keeps the *highest-confidence* record per IP.

Node shape:
- `ip`
- `threat_type`
- `confidence`
- `monte_carlo`
- `agent_id`
- `timestamp`

### 3) Edge building (`_build_edges`)
Edges are inferred between pairs of nodes when:
- They share the same `threat_type`, and
- Both have `confidence > 0.50`

Edge weight is the average confidence.

Edge shape:
- `src`, `dst`
- `threat_type`
- `weight`

### 4) Graph summary (`_graph_summary`)
Provides:
- `node_count`, `edge_count`
- `attack_types`
- `max_confidence`

### 5) Propagation simulation (`_run_propagation_simulation`)
Runs Monte Carlo trials that:
1. Pick an entry node (weighted by confidence).
2. Attempt to traverse edges to neighbors with probability based on edge `weight` (plus small noise).
3. Record which nodes were reached.

Per-trial result shape:
- `trial`
- `entry_node`
- `nodes_reached`
- `path_length`
- `compromised_ips`

### 6) Risk aggregation (`_aggregate_risk`)
Computes:
- `avg_spread`: average fraction of graph reached per trial
- `max_spread`
- `risk_score`: combines max confidence and average spread
- `risk_level`: `high | medium | low | none`
- `top_threats`: sorted by confidence
- `recommendations`: human-readable strings mapping threat → action

## Public API (AnalyzerAgent)
### `AnalyzerAgent.model_threat_graph(observations) -> dict`
Returns:
```json
{ "nodes": [...], "edges": [...], "summary": {...} }
```

### `AnalyzerAgent.simulate_attack(threat_graph) -> list[dict]`
Runs `N_SIM_TRIALS` propagation trials and returns the per-trial result list.

### `AnalyzerAgent.assess_risk(simulation_results) -> dict`
Returns a structured risk assessment.

Note: This method supports two calling styles:
- Pass a **list** of simulation trial dicts.
- Pass a **dict** with `{ "nodes": ..., "simulation_results": ... }` if you want node metadata available during scoring.

## How to see it working
Run the smoke test:
- `tests/run_analyzer_agent.py`

It checks graph building, simulation output, and risk assessment formatting (and also exercises `ThreatSimTool`).
