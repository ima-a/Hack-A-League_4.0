# What We Use and Why

This document explains every major technology, pattern, and library in SwarmShield, and the reasoning behind each choice.

---

## Core design principles

| Principle | Implementation |
|---|---|
| Detection must be deterministic | Monte Carlo scoring — repeatable and measurable |
| LLM enrichment must be optional | Graceful fallback when `XAI_API_KEY` is absent |
| Enforcement must be auditable | JSON-lines action log in `responder_actions.log` |
| Tests must run without root | `subprocess.run` mocked in pytest; synthetic packet gen in Scout |

---

## Language and project layout

**Python 3.9+**
Chosen for its data processing ecosystem and straightforward networking libraries.

**`src/` layout (`src/swarmshield/...`)**
Avoids Python import shadowing (if you run `pytest` from the repo root, `import swarmshield` always resolves to the installed package rather than a local folder). A `conftest.py` at the repo root adds the `src/` directory to `sys.path` for tests.

---

## Agents

### Scout — `src/swarmshield/agents/scout.py`
**What it does**: per-IP feature extraction and anomaly scoring.

**Why these techniques:**

| Technique | Reason |
|---|---|
| Sliding-window statistics (pps, bps, port entropy, SYN count) | Fast, explainable features — no model training needed |
| Monte Carlo scoring (1 000 trials/IP) | Adds robustness to metric noise without a dedicated static threshold |
| Shannon entropy on destination ports | Compact signal for distinguishing port scans from normal traffic |
| Rolling inference + trend extrapolation | Surfaces "early warning" before hard threshold is crossed |

**Rolling inference detail**: the Scout maintains a time-bounded buffer (default 60 s) and a per-IP confidence history. A simple linear regression on recent snapshots predicts near-future confidence. If the predicted value crosses `EARLY_WARNING_THRESHOLD` (0.40) before the current value crosses `CONFIDENCE_THRESHOLD` (0.60), the alert level is `early_warning`.

### Analyzer — `src/swarmshield/agents/analyzer.py`
**What it does**: correlation + impact estimation from many Scout observations.

**Why these techniques:**

| Technique | Reason |
|---|---|
| Threat graph (nodes = IPs, edges = coordinated-attack inference) | Minimal structure needed to reason about coordinated attacks |
| Edge inference rule (shared threat type + both conf > 0.50) | Conservative: avoids false coordination claims |
| Monte Carlo propagation simulation | Estimates worst-case spread without needing a real network model |
| Risk score = 0.6 × max_confidence + 0.4 × avg_spread | Weighs severity (confidence) more heavily than spread |

### Responder — `src/swarmshield/agents/responder.py`
**What it does**: enforce mitigation actions and create an audit trail.

**Why these choices:**

| Choice | Reason |
|---|---|
| Flask service (HTTP POST `/verdict`) | Clean boundary: Analyzer/Evolver sends a verdict over HTTP; Responder stays decoupled |
| `iptables` (DROP / DNAT / FORWARD DROP) | Native OS enforcement — no additional agent/daemon needed |
| JSON-lines action log | Append-only, parseable audit trail; used by the auto-unblock background thread |
| Auto-unblock thread | Prevents permanent blocks from false positives; configurable via `AUTO_UNBLOCK_SECONDS` |
| `subprocess.run` with `shell=False` | Avoids shell injection; timeout prevents hanging |

### Evolver — `src/swarmshield/agents/evolver.py`
**Status**: planned, currently a stub.

**Intended technique**: genetic algorithm (DEAP) to evolve detection thresholds and response strategies using historical outcome data (false positive rate, block success).

---

## LLM integration — Grok (xAI)

**Library**: OpenAI Python SDK (`openai>=1.0.0`) with a custom `base_url=https://api.x.ai/v1`.
**Why compatible SDK**: xAI's Grok API is OpenAI-compatible, so we avoid needing a separate xAI-specific package.

| Design choice | Reason |
|---|---|
| `temperature=0.0` | Fully deterministic; minimizes creative drift |
| `response_format={"type": "json_object"}` | Forces JSON output; no prose to parse |
| Grounded prompts ("this value is GROUND TRUTH") | Prevents LLM from overriding computed scores |
| Graceful fallback (`LLMClient.available`) | If `XAI_API_KEY` absent or `openai` not installed, agents continue without LLM |
| LLM enriches / validates — never decides | Keeps the core pipeline deterministic and testable |

**Where LLM output appears:**
- Scout: `llm_insight` in threat reports and rolling-tick entries (attack subtype, kill-chain stage, urgency)
- Analyzer: `llm_insight` in risk assessment (correlation type, lateral movement risk)
- Responder: `llm_validation` in `/verdict` responses (action validated, collateral risk, escalation flag)

---

## Web service layer

**Flask 2.2** (`flask==2.2.3`)
Used only for the Responder's HTTP API. Lightweight enough not to require a full WSGI setup for demos.

**Requests** (`requests==2.31.0`)
Used by Responder to POST action reports to the coordinator and dashboard endpoints (fire-and-forget threads).

---

## Testing

**pytest** (`pytest==7.4.0`)
Standard Python test runner. The test suite must be run via `.venv/bin/pytest` because system Python lacks the required dependencies.

**`conftest.py`** at repo root adds `src/` to `sys.path` so `from src.swarmshield...` imports work without installing the package.

**Smoke scripts** (`tests/run_*_agent.py`)
Run each agent end-to-end with synthetic data and print outputs. Useful for quick demos and debugging without needing to run the full test suite.

---

## What is deliberately NOT installed / not used

| Package in old requirements.txt | Why removed |
|---|---|
| `crewai`, `crewai-tools` | Not actually imported anywhere in the working codebase |
| `tensorflow`, `torch`, `torch-geometric` | ML models planned for future work; no agent uses them now |
| `scapy`, `pyshark` | Planned for live packet capture; `PacketCaptureTool` is a stub |
| `deap` | Planned for genetic evolution; `EvolutionTool` and `EvolverAgent` are stubs |
| `streamlit`, `pandas`, `matplotlib`, `seaborn`, `plotly` | Dashboard planned; no dashboard code present |
| `networkx` | Threat graph uses plain lists/dicts; no `networkx` calls exist in any agent |
| `scikit-learn` | No ML model training exists in the working codebase |
| `python-dotenv`, `pydantic`, `pyyaml` | Not imported by any working agent file |
| `jupyter`, `notebook`, `ipython` | No notebook files in the repo |

---

## File structure summary

```
src/swarmshield/
  agents/        # Working implementations (scout, analyzer, responder, evolver, llm_client)
  tools/         # Stub tool classes (packet capture, patrol, threat sim, response, evolution)
  main.py        # Entry point module (skeleton)
  crew.py        # Orchestrator skeleton (TODO)
tests/
  test_*.py      # Unit tests (43 passing)
  run_*_agent.py # Smoke scripts
docs/            # This documentation set
```
