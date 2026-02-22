# What We Use and Why

This document explains every major technology, pattern, and library in SwarmShield and the reasoning behind each choice.

## Core design principles

| Principle | Implementation |
|---|---|
| Detection must be deterministic | Monte Carlo scoring: repeatable and measurable |
| LLM enrichment must be optional | Graceful fallback when XAI_API_KEY is absent |
| Enforcement must be auditable | JSON-lines action log in responder_actions.log |
| Tests must run without root | subprocess.run mocked in pytest; synthetic packet gen in Scout |
| Agents must stay decoupled | A2A message bus for cross-agent events; CrewAI handles sequential orchestration |

## Language and project layout

Python 3.9+
Chosen for its data processing ecosystem and networking libraries.

src/ layout (src/swarmshield/...)
Avoids Python import shadowing. A conftest.py at the repo root adds src/ to sys.path for tests.

## Multi-agent orchestration: CrewAI

CrewAI 1.9.3 orchestrates the four-agent sequential pipeline:
Scout -> Analyzer -> Responder -> Evolver

Each agent is a CrewAI Agent with a role, goal, backstory, and a list of tools. The four tasks are wired as a sequential Process. Context from each task is passed to the next task automatically.

Key CrewAI concepts used:
- Agent(role, goal, backstory, tools, llm, verbose, allow_delegation)
- Task(description, expected_output, agent, context, human_input)
- Crew(agents, tasks, process, step_callback, task_callback)
- Process.sequential

The crew is rebuilt on each kickoff call (not a singleton) so batch mode can run multiple iterations cleanly.

## A2A message bus

An in-process pub/sub message bus (utils/message_bus.py) allows agents to broadcast events independently of the CrewAI task pipeline. No external broker is needed.

Topics: scout.tick, scout.early_warning, analyzer.pre_assessment, analyzer.assessment, responder.action, mahoraga.evolved

Each tool publishes to the bus after completing its main work. Subscribers (crew.py logging handlers and TransparencyReporter) receive events in the same thread.

## MCP server

FastMCP (mcp 1.23.3) exposes all 11 SwarmShield tools plus the A2A bus status as a Model Context Protocol server. This lets external MCP-compatible hosts (Claude Desktop, VS Code Copilot) call the tools directly.

Transport options: stdio (default, for local hosts) or streamable-http (for networked agents).

## Agents

### Scout - src/swarmshield/agents/scout.py

| Technique | Reason |
|---|---|
| Sliding-window per-IP statistics | Fast, explainable features: pps, bps, unique_dest_ips, syn_count, port_entropy |
| Monte Carlo scoring (1000 trials per IP) | Adds robustness to metric noise without needing a trained model |
| Shannon entropy on destination ports | Compact signal for distinguishing port scans from normal traffic |
| Rolling inference and trend extrapolation | Surfaces early warnings before the hard threshold is crossed |

### Analyzer - src/swarmshield/agents/analyzer.py

| Technique | Reason |
|---|---|
| Threat graph (nodes = IPs, edges = inferred coordination) | Minimal structure for reasoning about multi-source attacks |
| Edge inference rule: shared threat type + both confidence above 0.50 | Conservative: avoids false coordination claims |
| Monte Carlo propagation simulation | Estimates worst-case lateral movement without a real network model |
| risk_score = 0.6 * max_confidence + 0.4 * avg_spread | Weights threat severity more heavily than spread |

### Responder - src/swarmshield/agents/responder.py

| Choice | Reason |
|---|---|
| iptables (DROP, DNAT, FORWARD DROP) | Native OS enforcement without extra daemons |
| JSON-lines action log | Append-only, parseable audit trail used by the auto-unblock thread |
| Auto-unblock thread | Limits impact of false positives; configurable via AUTO_UNBLOCK_SECONDS |
| subprocess.run with shell=False | Avoids shell injection; timeout prevents hanging |
| Flask service for /verdict endpoint | Clean boundary for direct HTTP verdict delivery |

### Evolver (Mahoraga) - src/swarmshield/agents/evolver.py

| Choice | Reason |
|---|---|
| DEAP genetic algorithm | Evolves 6-gene threshold chromosome against real defense-cycle outcomes |
| FP penalized 2x in fitness | Blocking legitimate traffic is more disruptive than missing a threat |
| Synthetic fallback scenarios | Allows the GA to run from day one before real outcomes exist |
| Per-gene Gaussian mutation (MUT_SIGMA) | Appropriate step sizes per threshold scale (pps vs bps have very different ranges) |
| DEFAULT_GENOME as seed individual | Gives the GA a known-good starting point |

## Transparency and human approval

TransparencyReporter (utils/transparency.py) hooks into CrewAI via step_callback and task_callback. It prints each agent thought, tool call, and result in real time. It also subscribes to all A2A bus topics.

Human approval is implemented at two layers:
1. Tool level: in apply_defense_actions, an operator prompt fires before each non-monitor action when HUMAN_APPROVAL=true.
2. Task level: Task(human_input=True) on the Responder task pauses the CrewAI pipeline after the full task output is shown, allowing operator review before Evolver begins.

## LLM integration - Grok via xAI API

Library: OpenAI Python SDK (openai>=1.0.0) with base_url=https://api.x.ai/v1.

| Design choice | Reason |
|---|---|
| temperature=0.0 | Fully deterministic |
| response_format json_object | Forces JSON output, no prose to parse |
| Grounded prompts | Agents tell the LLM the numerical values are ground truth; LLM cannot override them |
| Graceful fallback | If XAI_API_KEY absent or openai not installed, agents continue without LLM enrichment |
| LLM enriches and validates only | Keeps the core pipeline deterministic and testable |

## Flask

Flask 2.2 is used exclusively for the Responder HTTP service (/verdict, /health) and the HoneypotBridge (/honeypot_event, /honeypot_events, /honeypot_health). Lightweight enough for demos without a full WSGI setup.

## Testing

pytest runs the 24-test suite in tests/test_crew.py. All tests use mocking and synthetic data. No root, no network, no real API keys required.

conftest.py at the repo root adds src/ to sys.path.

Smoke scripts (tests/run_*_agent.py) run individual agents end-to-end with synthetic data for quick demos.

## File structure summary

    src/swarmshield/
      agents/          - Scout, Analyzer, Responder, Evolver, LLMClient, HoneypotBridge
      tools/           - CrewAI @tool wrappers for all agents (scout_tool, analyzer_tool, responder_tool, evolution_tool)
      utils/           - message_bus, ml_classifier, transparency
      crew.py          - SwarmShieldCrew orchestrator
      main.py          - main() entry point
      mcp_server.py    - FastMCP server (11 tools + bus status resource)
    tests/
      test_crew.py     - 24-test suite (all mocked, no credentials needed)
      run_*_agent.py   - smoke scripts
    docs/              - this documentation set
    run.py             - CLI launcher (demo, interactive, batch, mcp-server modes)
    run.sh             - shell launcher with auto-venv activation
    requirements.txt   - pinned dependencies
