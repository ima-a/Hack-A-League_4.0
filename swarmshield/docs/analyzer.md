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
# Analyzer Agent

Source: `src/swarmshield/agents/analyzer.py`

## What it does
The Analyzer Agent turns many Scout observations into a correlation-oriented output:
1. Build a **threat graph** (nodes = source IPs; edges = inferred coordination).
2. Run **Monte Carlo propagation simulation** over that graph.
3. Produce a **risk assessment**: severity level, risk score, spread metrics, and recommended actions.

This output is intended to drive the Responder.

## Inputs
Analyzer expects a list of Scout-style observation dicts. Common fields:
- `source_ip`
- `attack_type` (e.g. `DDoS`, `PortScan`, `Exfiltration`)
- `confidence` (0.0–1.0)
- optional: `monte_carlo`, `agent_id`, `timestamp`

## Threat graph
### Nodes
Nodes are deduplicated by `source_ip`; the highest-confidence observation for that IP wins.

Node keys:
- `ip`
- `threat_type`
- `confidence`
- `monte_carlo` (optional passthrough)
- `agent_id`, `timestamp`

### Edges
Edges are inferred when two nodes:
- share the same `threat_type`, and
- both have `confidence > 0.50`

Edge weight is the average confidence.

## Propagation simulation
Each trial:
1. Picks an entry node weighted by node confidence.
2. Attempts to traverse edges with probability based on edge weight (plus small noise).
3. Records the number of nodes reached and the compromised IP list.

Per-trial result keys: `trial`, `entry_node`, `nodes_reached`, `path_length`, `compromised_ips`.

## Risk scoring
The aggregate risk score combines confidence and spread:

$$\text{risk\_score} = \min(1, 0.6 \cdot \max\_\text{confidence} + 0.4 \cdot \text{avg\_spread})$$

Risk level thresholds are defined in-module.

## Optional LLM enrichment (Grok)
If constructed with an `LLMClient` (passed into `AnalyzerAgent(llm_client=...)`), `assess_risk()` may attach an `llm_insight` JSON object with:
- correlation type (coordinated/independent/unclear)
- lateral movement risk
- containment priority + recommended actions

This enrichment never replaces deterministic scores; it only adds structured “analyst-style” context.

## Public API
- `model_threat_graph(observations) -> {nodes, edges, summary}`
- `simulate_attack(threat_graph) -> list[trial]`
- `assess_risk(simulation_results_or_context_dict) -> dict`

## How to see it working
Run `tests/run_analyzer_agent.py`.

