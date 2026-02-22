# SwarmShield Workflow

This document explains how the four agents support each other, where the workflow starts and ends, and why data flows in that order.

## Overview

SwarmShield runs as a sequential multi-agent pipeline orchestrated by CrewAI:

1. Scout - detects network threats via Monte Carlo analysis and produces threat reports.
2. Analyzer - builds an attack graph from Scout reports, runs propagation simulation, and produces a risk assessment with ranked recommendations.
3. Responder - applies the minimum-necessary defense actions based on the Analyzer output (block, redirect to honeypot, quarantine, rate-limit, or monitor).
4. Evolver (Mahoraga) - runs a DEAP genetic algorithm after each defense cycle to evolve Scout detection thresholds, minimizing false positives and false negatives.

There is also an optional LLM layer (Grok via LLMClient) that attaches structured JSON insights to reports. The LLM never replaces deterministic scores or enforcement decisions.

## Entry points

To run the full pipeline:

    python run.py                          # demo mode, 1 iteration, dry-run
    python run.py --mode interactive       # prompt for scenario, human-in-the-loop
    python run.py --mode batch --iterations 5
    python run.py --mode mcp-server        # start MCP server for external tools

Start and end:
- Start: Scout captures (or simulates) network traffic and scores each source IP.
- End: Evolver saves updated thresholds to mahoraga_best_strategy.json and returns the evolved genome.

## Data flow between agents

### Scout output (feeds Analyzer)

One threat report per suspicious source IP:

    agent_id, event, source_ip, attack_type, confidence,
    stats (pps, bps, unique_dest_ips, syn_count, port_entropy),
    monte_carlo (per-type confidence scores, top_threat, top_confidence),
    timestamp

Optionally includes llm_insight if XAI_API_KEY is set.

### Analyzer output (feeds Responder)

    threat_graph: {nodes, edges, summary}
    simulation_results: list of Monte Carlo propagation trial dicts
    risk_assessment: {risk_level, risk_score, avg_spread, top_threats, recommendations}

### Responder output (feeds Evolver)

    actions_applied: list of {ip, action, success, mode, timestamp}
    summary: string description
    risk_level: string
    live_mode: bool
    timestamp: string

### Evolver output (end of cycle)

    best_genome: list of 6 floats
    best_thresholds: dict mapping threshold names to evolved values
    confidence_threshold: float
    best_fitness: float
    generations_run: int
    outcomes_used: int
    llm_insight: dict or null

## Why the ordering is Scout then Analyzer then Responder then Evolver

Scout is closest to raw signals (packet metadata). It extracts features and assigns confidence scores per source IP without making enforcement decisions.

Analyzer aggregates multiple Scout observations into a graph structure, runs propagation simulation to estimate lateral movement risk, and produces a single ranked action list. This keeps detection logic separate from enforcement logic.

Responder is the actuator. It converts the Analyzer's recommendations into concrete network enforcement actions. Separating this from detection makes the system safer to test and audit.

Evolver runs last because it needs outcome data from the Responder to know whether each defense action was a true positive or false positive. It evolves thresholds for the next cycle.

## A2A message bus

In addition to the CrewAI sequential task pipeline, agents publish events to a shared in-process message bus (no external broker required). Topics:

    scout.tick              - fired after each Scout detection cycle
    scout.early_warning     - fired when predicted confidence crosses early-warning threshold
    analyzer.pre_assessment - fired before full risk assessment with preliminary data
    analyzer.assessment     - fired with final risk level and score
    responder.action        - fired after each enforcement action (one per IP)
    mahoraga.evolved        - fired when Evolver completes a GA run

Subscribers (crew.py logging handlers and the TransparencyReporter) receive these events alongside the main task pipeline output.

## Human approval

When HUMAN_APPROVAL=true is set:

1. Before each enforcement action in apply_defense_actions, a prompt asks the operator to approve, reject, or abort all remaining actions.
2. After the Responder task completes, CrewAI pauses and shows the full task output to the operator before Evolver begins (Task level human_input=True).

## Transparency

When TRANSPARENCY_CONSOLE=true (default), the TransparencyReporter prints each agent thought, tool call, and result to the terminal in real time. A JSON log is also written to transparency.log (configurable via TRANSPARENCY_LOG_FILE).
