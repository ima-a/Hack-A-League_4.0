# SwarmShield Workflow

This document explains how the agents work together, where data flows, and why they are ordered as they are.

## Overview

SwarmShield runs two complementary pipelines simultaneously:

**1. Reactive pipeline** (confirmed threats):

    Scout.rolling_tick() → confirmed_threats → POST /verdict → Responder.decide_and_act()

**2. Anticipatory pipeline** (rising threats, before confirmation):

    Scout.rolling_tick() → early_warnings → Analyzer.pre_assess_risk()
        → POST /preemptive_action → safety gate → rate_limit or elevated_monitor

**CIC-ML addon** (runs every tick as a second-opinion layer):

    Analyzer.cic_screen(per_ip) → POST /cic_block → dispatch by CIC label

The CrewAI crew (run.py) runs a sequential Scout → Analyzer → Responder → Evolver batch cycle as an alternative orchestration path for demo/batch/interactive mode.

## Entry points

    python run.py                     # CrewAI crew: demo/interactive/batch
    python run_live.py --simulate     # Live demo: synthetic traffic, no root
    sudo python run_live.py --interface eth0  # Live demo: real packet capture

## Data flow

### Scout output (feeds Analyzer and Responder)

One threat report per suspicious source IP (from `detect_anomalies()`):

    agent_id, event, source_ip, attack_type, confidence,
    stats: {packets_per_second, bytes_per_second, unique_dest_ips, syn_count, port_entropy},
    monte_carlo: {ddos_confidence, port_scan_confidence, exfiltration_confidence,
                  top_threat, top_confidence, recommended_action},
    timestamp

`rolling_tick()` produces a tick result consumed directly by the live demo:

    tick_time, buffer_size,
    per_ip: {<ip>: {stats, monte_carlo, trend, alert_level,
                    current_confidence, predicted_confidence}},
    early_warnings: [list of IPs at early_warning level],
    confirmed_threats: [list of IPs at confirmed level]

### Analyzer output (feeds Responder)

From `assess_risk()` (reactive):

    threat_graph: {nodes, edges, summary}
    simulation_results: list of Monte Carlo propagation trial dicts
    risk_assessment: {risk_level, risk_score, avg_spread, max_spread,
                      top_threats, recommendations, timestamp}

From `pre_assess_risk()` (anticipatory):

    preemptive_actions: [
      {source_ip, alert_level, current_confidence, predicted_confidence,
       threat_type, trend_direction, recommended_action, reasoning, agent_id}
    ],
    total_early_warnings: int,
    timestamp: str

From `cic_screen()` (addon):

    flagged_ips: [{source_ip, cic_label, confidence, recommended_action}],
    screened: int,
    available: bool

### Responder output (feeds Evolver)

    actions_applied: [{ip, action, success, mode, timestamp}]
    summary: string
    risk_level: string
    live_mode: bool
    timestamp: string

### Evolver output (end of cycle)

    best_genome: [500.0, 300.0, 20.0, 3.5, 500000.0, 0.60]  # 6 genes
    best_thresholds: {threshold_name: value, ...}
    confidence_threshold: float
    best_fitness: float
    generations_run: int
    outcomes_used: int
    timestamp: str

## Why the ordering

**Scout first**: closest to raw signals. Extracts features and assigns Monte Carlo confidence scores without making enforcement decisions.

**Analyzer second**: aggregates multiple Scout observations into a graph structure, runs propagation simulation to estimate lateral movement risk, and produces a single ranked action list. Keeps detection logic separate from enforcement logic.

**Responder third**: converts recommendations into iptables rules. Separating enforcement from detection makes the system safer to test and audit.

**Evolver last**: needs outcome data from the Responder (block/quarantine = true positive; monitor = false positive). Evolves thresholds for the next cycle.

## Pre-emptive safety gate

The anticipatory pipeline enforces four checks before any pre-emptive action executes:

1. **Action whitelist**: only `rate_limit` or `elevated_monitor` are allowed (never block/quarantine on a prediction).
2. **Alert level**: must be `early_warning`, not `confirmed` (confirmed threats use the reactive path).
3. **Predicted threshold**: predicted confidence must be ≥ `PREEMPTIVE_CONFIDENCE_GATE` (default 0.40).
4. **Not-yet-confirmed**: current confidence must be below `CONFIRMED_CONFIDENCE_GATE` (default 0.60).

A `gate_rejected` response (HTTP 200) means the gate is working correctly — it is not an error.

## A2A message bus

Agents publish events to a shared in-process pub/sub bus. No external broker is required.

Topics:

    scout.tick              - fired after each rolling_tick() call
    scout.early_warning     - fired when one or more IPs reach early_warning level
    analyzer.pre_assessment - fired after pre_assess_risk() completes
    analyzer.assessment     - fired after assess_risk() completes
    responder.action        - fired after each enforcement action
    mahoraga.evolved        - fired when an evolution run completes

The live_demo.py subscribes to all topics for console visibility. The Mahoraga auto-records confirmed Responder actions via the `responder.action` topic to feed the genetic algorithm with real training data. The SwarmShieldCrew wires lightweight log-only subscribers in `_setup_bus_subscriptions()`.

## Human approval

When `HUMAN_APPROVAL=true`:

1. `apply_defense_actions` (Responder tool) prompts the operator before each non-monitor action (y/n/abort).
2. The CrewAI Responder task has `human_input=True` — CrewAI pauses after task output and waits for operator feedback before Evolver begins.

## Transparency

When `TRANSPARENCY_CONSOLE=true` (default), the `TransparencyReporter` prints each agent thought, tool call, and result in real time. A JSON-Lines log is also written to `transparency.log` (path configurable via `TRANSPARENCY_LOG_FILE`).

## HoneypotBridge

A separate Flask server (port 5001, started when `HONEYPOT_BRIDGE_ENABLED=true`) accepts `POST /honeypot_event` callbacks from a partner honeypot. Each event is fed to Mahoraga so the genetic algorithm trains from real attacker ground-truth data rather than only from the auto-recorded Responder actions.
