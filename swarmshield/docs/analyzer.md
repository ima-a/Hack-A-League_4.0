# Analyzer Agent

Source: `src/swarmshield/agents/analyzer.py`

## What it does

The Analyzer Agent is the second stage in the SwarmShield pipeline. It takes Scout threat observation reports and:

1. Builds a threat graph (nodes = source IPs, edges = inferred coordination links).
2. Runs Monte Carlo lateral-movement propagation simulation over the graph.
3. Produces a risk assessment with a risk level, risk score, spread metrics, and ranked recommendations.
4. Handles the **anticipatory path**: processes early-warning IPs from Scout's rolling inference before a threat confirms.
5. Runs the **CIC-ML addon**: XGBoost multi-class classifier (CIC-IDS2017) as a second-opinion layer.

## Inputs

A list of Scout threat observation dicts (for `model_threat_graph()`):

    source_ip       string
    attack_type     string  (DDoS, PortScan, Exfiltration)
    confidence      float   (0.0 to 1.0)
    monte_carlo     dict    (optional passthrough from Scout)
    agent_id        string  (optional)
    timestamp       string  (optional)

## Threat graph

### Nodes

Deduplicated by `source_ip`. If a source IP appears multiple times, the observation with the highest confidence is used.

Node fields: `ip`, `threat_type`, `confidence`, `monte_carlo`, `agent_id`, `timestamp`.

### Edges

An edge is inferred between two nodes when both share the same `threat_type` AND both have `confidence > 0.50`. Edge weight = average confidence of the two.

## Propagation simulation

Each Monte Carlo trial:
1. Picks an entry node weighted by confidence.
2. Traverses each outbound edge with `Bernoulli(weight + Gaussian noise)`.
3. Records `nodes_reached`, `path_length`, `compromised_ips`.

## Risk scoring

    risk_score = min(1.0, 0.6 × max_confidence + 0.4 × avg_spread)

Risk levels:

    high:   risk_score ≥ 0.70
    medium: risk_score ≥ 0.40
    low:    risk_score > 0.0
    none:   risk_score = 0.0

## Anticipatory path: `pre_assess_risk(tick_result)`

Called by `live_demo.py` when Scout fires an `early_warning`. Processes only IPs at `early_warning` alert level and recommends only low-impact actions:

- `rate_limit` — predicted confidence ≥ 0.50 AND trend is `rising`
- `elevated_monitor` — everything else in the early-warning zone

Returns:

    {
      "preemptive_actions": [
        {source_ip, alert_level, current_confidence, predicted_confidence,
         threat_type, trend_direction, recommended_action, reasoning, agent_id}
      ],
      "total_early_warnings": int,
      "timestamp": str
    }

Also publishes to `analyzer.pre_assessment` on the A2A bus.

## CIC-ML addon: `cic_screen(per_ip)`

Runs the CIC-IDS2017 XGBoost model (78 features, 10 classes) over per-IP traffic stats. Silently skipped when the model is unavailable.

Action mapping by CIC label:

| CIC label | Action |
|---|---|
| PortScan | `redirect_to_honeypot` |
| Infiltration | `quarantine` |
| DDoS, Bot, FTP-Patator, SSH-Patator, Web attacks | `block` |

Returns:

    {
      "flagged_ips": [{source_ip, cic_label, confidence, recommended_action}],
      "screened": int,
      "available": bool
    }

## Optional LLM enrichment

If `XAI_API_KEY` is set and an `LLMClient` is passed to `AnalyzerAgent(llm_client=...)`, `assess_risk()` attaches an `llm_insight` block with:

- `threat_correlation` (coordinated / independent / unclear)
- `lateral_movement_risk` (high / medium / low / none)
- `containment_priority` (ordered IP list)
- `recommended_actions` (per-IP action + reason)

The LLM output is purely advisory. Deterministic scores are never changed.

## CrewAI tools

Three `@tool` functions in `tools/analyzer_tool.py`:

    build_threat_graph(scout_report_json)          - build attack graph from Scout output
    run_propagation_simulation(threat_graph_json)  - run MC propagation on the graph
    full_threat_analysis(scout_report_json)        - graph + simulation in one call

## Public API (AnalyzerAgent)

    model_threat_graph(observations) -> {nodes, edges, summary}
    simulate_attack(threat_graph) -> list[dict]
    assess_risk(simulation_results_or_context_dict) -> dict
    pre_assess_risk(tick_result) -> dict
    cic_screen(per_ip) -> dict
