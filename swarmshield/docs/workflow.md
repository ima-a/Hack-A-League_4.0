# SwarmShield Workflow (How Agents Help Each Other)

This document explains how each agent supports the others, where the workflow starts and ends, and why data travels through the system in that order.

## Big picture
SwarmShield is designed as a pipeline:

1. **Scout** observes network activity and produces **threat observations**.
2. **Analyzer** consumes those observations, builds an **attack graph**, simulates spread, and produces a **risk assessment + recommended actions**.
3. **Responder** consumes the verdict/recommendations and performs **enforcement actions** (block/redirect/quarantine/monitor), then logs and reports what happened.
4. **Evolver** (optional) is intended to learn from outcomes and tune strategies over time. In the current codebase it is a stub.

There is also an **optional LLM layer** (Grok via `LLMClient`) that can attach strictly-structured JSON insights/validation. The LLM never replaces deterministic scores or actions.

## Where it starts and where it ends
### Start: data creation (Scout)
The workflow starts when Scout runs a capture/detection cycle.

- In this repo, `ScoutAgent.capture_packets()` generates synthetic packet metadata so the pipeline runs without privileged live capture.
- Scout computes per-source statistics and determines whether each source IP looks malicious.

Output of this stage: a list of threat observation reports (one per suspicious source IP).

### End: enforcement + audit trail (Responder)
The workflow ends when Responder has:

- chosen an action (based on a verdict),
- executed it (or decided to monitor),
- appended an action record to `responder_actions.log`, and
- optionally reported the action to the coordinator/dashboard.

## Why the workflow travels Scout → Analyzer → Responder
This ordering is intentional:

- **Scout** is closest to raw signals (packet/flow metadata). It extracts features and detects anomalies.
- **Analyzer** performs aggregation and reasoning across multiple Scout observations (graph building + propagation simulation) to determine severity and likely impact.
- **Responder** is the actuator: it converts a verdict into a concrete mitigation action.

Keeping these concerns separated makes the system easier to test and reduces the risk of mixing detection logic with enforcement.

## What each agent gives to the next agent
### 1) Scout → Analyzer: threat observations
Typical fields:
- `source_ip`
- `attack_type` (e.g. `DDoS`, `PortScan`, `Exfiltration`)
- `confidence` (0.0–1.0)
- `stats` (pps/bps/unique destinations/SYN count/entropy)
- `monte_carlo` (per-threat confidence values + `top_threat`)
- `timestamp`
- `agent_id`
- optional: `llm_insight`

### 2) Analyzer → Responder: verdict + recommendation
Analyzer turns many observations into a decision-ready output:
- threat graph summary
- Monte Carlo propagation simulation
- risk assessment + recommendations
- optional: `llm_insight`

Responder expects a verdict payload with fields like:
- `source_ip`
- `predicted_attack_type`
- `confidence`
- `recommended_action` (e.g. `block`, `redirect_to_honeypot`, `quarantine`, `monitor`)
- `agent_id`
- `shap_explanation` (placeholder text in demos)

### 3) Responder → (optional) Evolver: outcomes
Conceptually, Evolver would consume outcomes (what action was taken, whether it worked, false positives, etc.) to adjust thresholds/strategies.

In this repository, `EvolverAgent` exists but the strategy evolution logic is not implemented.

## Practical demo workflow in this repo
Because the full orchestrator logic is minimal/stubbed, the easiest way to see the workflow is via the smoke tests:

1. `tests/run_scout_agent.py`
2. `tests/run_analyzer_agent.py`
3. `tests/run_responder_agent.py`

## Notes on orchestration
- `run.py`, `src/swarmshield/main.py`, and `src/swarmshield/crew.py` provide a CLI-style entry point and an orchestrator skeleton.
- The end-to-end always-on wiring is intentionally not implemented; smoke tests demonstrate the contracts between agents.
# SwarmShield Workflow (How Agents Help Each Other)

This document explains how each agent supports the others, where the workflow starts and ends, and why data “travels” through the system in that order.

## Big picture
SwarmShield is designed as a pipeline:

1. **Scout** observes network activity and produces **threat observations**.
2. **Analyzer** consumes those observations, builds an **attack graph**, simulates spread, and produces a **risk assessment + recommended actions**.
3. **Responder** consumes the verdict/recommendations and performs **enforcement actions** (block/redirect/quarantine/monitor), then logs and reports what happened.
4. **Evolver** (optional) is intended to learn from outcomes and tune strategies over time. In the current codebase it’s a stub.

There is also an **optional LLM layer** (Grok via `LLMClient`) that can attach strictly-structured JSON insights/validation. The LLM never replaces deterministic scores or actions.

## Where it starts and where it ends
### Start: data creation (Scout)
The workflow starts when the Scout runs a capture/detection cycle.

- In this repo, `ScoutAgent.capture_packets()` generates **synthetic packet metadata** (so the pipeline runs without privileged live capture).
- Scout then computes per-source statistics and determines whether each source IP looks malicious.

Output of this stage: a list of **threat observation reports** (one per suspicious source IP).

### End: enforcement + audit trail (Responder)
The workflow ends when the Responder has:

- chosen an action (based on a verdict),
- executed it (or decided to monitor),
- appended an action record to `responder_actions.log`, and
- optionally reported the action to the Coordinator/Dashboard.

Why this is the “end”: after enforcement, the system has taken concrete defensive steps and left an auditable trail of what it did.

## Why the workflow travels Scout → Analyzer → Responder
This ordering is intentional:

- **Scout is closest to raw signals** (packet/flow metadata). It extracts features and detects anomalies.
- **Analyzer performs aggregation and reasoning** across multiple Scout observations (graph building + propagation simulation) to determine severity and likely impact.
- **Responder is the actuator**. It takes the final decision and turns it into real-world mitigation actions.

Keeping these concerns separated makes the system easier to test (each agent has clear inputs/outputs) and reduces the risk of mixing detection logic with enforcement.

## What each agent gives to the next agent
### 1) Scout → Analyzer: “Threat observation”
Scout produces a structured report per suspicious source IP.

Typical fields (as produced by the Scout implementation):
- `source_ip`
- `attack_type` (e.g. `DDoS`, `PortScan`, `Exfiltration`)
- `confidence` (0.0–1.0)
- `stats` (pps/bps/unique destinations/SYN count/entropy)
- `monte_carlo` (per-threat confidence values + `top_threat`)
- `timestamp`
- `agent_id`

How it helps: Analyzer doesn’t need raw packets; it needs a compact, comparable “observation” format.

### 2) Analyzer → Responder: “Verdict + recommendation”
Analyzer’s job is to turn many observations into a decision-ready output:

- **Threat graph**: nodes/edges summarizing suspicious sources.
- **Simulation results**: Monte Carlo propagation trials.
- **Risk assessment**: `risk_level`, `risk_score`, spread metrics, and recommended actions.

The Responder Flask service expects a verdict payload with fields like:
- `source_ip`
- `predicted_attack_type`
- `confidence`
- `recommended_action` (e.g. `block`, `redirect_to_honeypot`, `quarantine`, `monitor`)
- `agent_id`
- `shap_explanation` (can be a placeholder string in demos)

How it helps: Responder should not do “analysis”; it should do “action”. Analyzer packages the decision into a simple contract.

### 3) Responder → (optional) Evolver: “Outcome feedback”
Conceptually, Evolver would consume outcomes (what action was taken, whether it worked, false positives, etc.) to adjust thresholds/strategies.

In the current repository:
- `EvolverAgent` exists but the genetic algorithm logic is not implemented yet.

## Agent roles in one sentence each
- **Scout**: *Feature extraction + anomaly scoring per source IP.*
- **Analyzer**: *Correlation + simulation + risk scoring + recommendations.*
- **Responder**: *Mitigation actions + logging/reporting.*
- **Evolver**: *Strategy tuning over time (planned).*

## Practical “demo” workflow in this repo
Because the full orchestrator logic is minimal/stubbed, the easiest way to see the workflow is via the smoke tests:

1. Run Scout smoke test to generate observations:
   - `tests/run_scout_agent.py`
2. Run Analyzer smoke test to build graphs and assess risk:
   - `tests/run_analyzer_agent.py`
3. Run Responder smoke test to verify verdict handling and actions:
   - `tests/run_responder_agent.py`

These scripts intentionally feed test data and print outputs to show each agent is working in isolation.

## Notes on orchestration (entry points)
- `run.py` / `src/swarmshield/main.py` / `src/swarmshield/crew.py` provide a CLI-style entry point and a crew orchestrator skeleton.
- The agent-to-agent “wiring” (feeding real Scout observations into Analyzer, then sending Analyzer verdicts to Responder over HTTP) is represented by interfaces and smoke tests, not a single always-on coordinator loop.

If you want, I can wire a minimal coordinator loop that:
- calls `ScoutAgent.detect_anomalies()`
- passes results into `AnalyzerAgent.model_threat_graph()` / `simulate_attack()` / `assess_risk()`
- POSTs a verdict to the Responder’s `/verdict` endpoint
—but I didn’t add that here since you asked only for documentation.
