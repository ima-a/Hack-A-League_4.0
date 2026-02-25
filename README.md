# SwarmShield — Autonomous Multi-Agent Cybersecurity System

> **Hack-A-League 4.0** &nbsp;|&nbsp; Network Threat Detection · Anticipatory Analysis · Automated Response

SwarmShield is a multi-agent autonomous cybersecurity system that detects, analyses, and responds to network threats in real time. It combines Monte Carlo simulation, genetic algorithm-based threshold evolution, a CIC-IDS2017 XGBoost ML layer, and optional Grok (xAI) LLM enrichment — all orchestrated through a CrewAI sequential agent pipeline.

---

## Threat Coverage

| Category | Detection method |
|---|---|
| **DDoS / DoS** | Monte Carlo confidence, packets/bytes per second thresholds |
| **Port Scan** | Port entropy analysis, unique destination IP tracking |
| **Data Exfiltration** | Bytes-per-second anomaly, directional flow analysis |
| **Lateral Movement** | Attack-graph propagation simulation |
| **Broad Intrusion** | CIC-IDS2017 XGBoost (10-class, 78 features) second-opinion layer |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SwarmShield Pipeline                         │
│               Sequential · A2A Message Bus · LLM optional       │
└─────────────────────────────────────────────────────────────────┘

  ┌──────────────┐     ┌───────────────────┐     ┌──────────────┐    ┌──────────────┐
  │    Scout     │────▶│     Analyzer      │────▶│  Responder   │───▶│   Evolver    │
  │  (detect)    │     │  (graph + risk)   │     │  (enforce)   │    │  (Mahoraga)  │
  └──────┬───────┘     └────────┬──────────┘     └──────────────┘    └──────────────┘
         │  early_warning       │ pre_assess_risk       ▲ /preemptive_action
         └──────────────────────┴──────────────────────►┘
```

### Dual pipeline

**Reactive** (confirmed threats):  
`Scout.rolling_tick()` → confirmed → `POST /verdict` → `Responder.decide_and_act()`

**Anticipatory** (rising threats before confirmation):  
`Scout.rolling_tick()` → early_warning → `Analyzer.pre_assess_risk()` → `POST /preemptive_action` → safety gate → `rate_limit` or `elevated_monitor`

**CIC-ML addon** (XGBoost second opinion, runs every tick):  
`Analyzer.cic_screen()` → `POST /cic_block` → dispatch by CIC label

---

## Agents

| Agent | Role | Key mechanism |
|---|---|---|
| **Scout** | Packet-level detection | Monte Carlo simulation over live traffic stats; rolling early-warning trend inference |
| **Analyzer** | Threat graph + risk scoring | Attack graph construction; MC lateral-movement propagation; CIC-IDS2017 XGBoost addon |
| **Responder** | Network enforcement | Flask service (port 5003); iptables block / quarantine / redirect / rate-limit with auto-unblock |
| **Mahoraga (Evolver)** | Threshold evolution | DEAP genetic algorithm; evolves Scout detection thresholds from defence-cycle outcomes |

---

## Key Features

- Monte Carlo detection for **DDoS, PortScan, Exfiltration**
- Rolling trend analysis and **early-warning inference** — acts before confidence fully confirms
- **Four-gate pre-emptive safety system** — destructive actions blocked from early-warning path
- Attack-graph construction and MC **lateral-movement propagation simulation**
- **CIC-IDS2017 XGBoost** multi-class intrusion detection (10 classes, 78 features)
- iptables enforcement: block, quarantine, redirect-to-honeypot, rate-limit with **auto-unblock**
- **DEAP genetic algorithm** threshold evolution with FP-penalised fitness function
- **A2A message bus**: in-process pub/sub connecting all agents (no external broker)
- **CrewAI orchestration**: sequential four-agent crew with optional per-task human approval gate
- Optional **Grok (xAI) LLM enrichment** — schema-constrained JSON outputs, purely advisory
- **Transparency reporter**: agent thought/tool/result stream to console and JSON-Lines log
- **HoneypotBridge**: Flask server (port 5001) feeds honeypot events to Mahoraga as training data

---

## Repository Structure

```
Hack-A-League/
├── README.md                        # ← you are here
├── swarmshield/runtime/             # Runtime artifacts (generated on run)
│   ├── blocked_ips.txt              # IPs currently blocked by Responder (LIVE_MODE)
│   └── mahoraga_best_strategy.json  # Best genome saved by Mahoraga (Evolver)
└── swarmshield/                     # Main project package
    ├── README.md                    # Detailed agent + API documentation
    ├── requirements.txt
    ├── run.py                       # CrewAI crew entry point (demo/interactive/batch/mcp)
    ├── run_live.py                  # Live demo entry point (real or simulated traffic)
    ├── docs/
    │   ├── workflow.md              # Pipeline architecture and data flow
    │   ├── scout.md
    │   ├── analyzer.md
    │   ├── responder.md
    │   ├── evolver.md
    │   ├── live_demo.md
    │   └── tech_used_and_why.md
    ├── src/swarmshield/
    │   ├── crew.py                  # SwarmShieldCrew (CrewAI)
    │   ├── mcp_server.py            # MCP server (stdio / HTTP)
    │   ├── agents/                  # Scout · Analyzer · Responder · Evolver · HoneypotBridge
    │   ├── tools/                   # CrewAI tools wrapping each agent's capabilities
    │   ├── utils/                   # A2A message bus · XGBoost classifier · Transparency reporter
    │   └── model/
    │       └── cic_multiclass_model.pkl
    └── tests/
```

---

## Quick Start

### Prerequisites

- Python 3.9+
- Optional: `XAI_API_KEY` (Grok) or `OPENAI_API_KEY` for LLM enrichment
- Optional: root / `CAP_NET_RAW` for live packet capture and real iptables enforcement

### Installation

```bash
cd swarmshield
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # add XAI_API_KEY if desired
```

### Run

```bash
# CrewAI crew — demo, dry-run (no root required)
python run.py

# Interactive scenario selection
python run.py --mode interactive

# 5 randomised batch scenarios
python run.py --mode batch --iterations 5

# Live traffic with real iptables rules (root required)
sudo python run.py --live

# Operator approval gate enabled
HUMAN_APPROVAL=true python run.py

# MCP server (stdio)
python run.py --mode mcp-server

# Live demo with synthetic traffic (no root)
python run_live.py --simulate

# Live demo on a real interface
sudo python run_live.py --interface eth0 --tick 5
```

---

## Configuration

Key `.env` variables (copy from `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `XAI_API_KEY` | — | Grok API key for LLM enrichment |
| `LIVE_MODE` | `false` | Apply real iptables rules (requires root) |
| `HUMAN_APPROVAL` | `false` | Operator confirmation before each action |
| `RESPONDER_PORT` | `5003` | Responder Flask port |
| `HONEYPOT_IP` | `192.168.1.99` | Honeypot redirect target |
| `AUTO_UNBLOCK_SECONDS` | `300` | Auto-unblock window for blocked IPs |
| `PREEMPTIVE_CONFIDENCE_GATE` | `0.40` | Min predicted confidence for pre-emptive action |
| `CONFIRMED_CONFIDENCE_GATE` | `0.60` | Min confidence for confirmed enforcement |
| `TRANSPARENCY_CONSOLE` | `true` | Print agent steps to terminal |
| `HONEYPOT_BRIDGE_ENABLED` | `false` | Start HoneypotBridge server (port 5001) |

---

## Testing

```bash
cd swarmshield
PYTHONPATH=src .venv/bin/pytest tests/ -q
PYTHONPATH=src .venv/bin/pytest tests/test_agents.py -v
PYTHONPATH=src python tests/run_scout_agent.py
```

---

## Documentation

Full documentation lives in [`swarmshield/docs/`](swarmshield/docs/):

- [workflow.md](swarmshield/docs/workflow.md) — pipeline architecture, data flow, A2A bus
- [scout.md](swarmshield/docs/scout.md) — detection logic, thresholds, rolling inference
- [analyzer.md](swarmshield/docs/analyzer.md) — threat graph, propagation simulation, CIC-ML addon
- [responder.md](swarmshield/docs/responder.md) — enforcement actions, Flask API, auto-unblock
- [evolver.md](swarmshield/docs/evolver.md) — Mahoraga genome, fitness function, DEAP config
- [live_demo.md](swarmshield/docs/live_demo.md) — live demo entry point, anticipatory pipeline
- [tech_used_and_why.md](swarmshield/docs/tech_used_and_why.md) — technology choices and rationale

---

## Tech Stack

| Layer | Technology |
|---|---|
| Multi-agent orchestration | CrewAI |
| Detection statistics | Monte Carlo simulation (NumPy) |
| Threshold evolution | DEAP genetic algorithm |
| ML intrusion detection | XGBoost (CIC-IDS2017, 10 classes) |
| Network enforcement | iptables (via subprocess) |
| Packet capture | Scapy |
| Inter-agent messaging | Custom A2A pub/sub message bus |
| LLM enrichment (optional) | Grok (xAI) / OpenAI-compatible |
| Agent API | Flask (ports 5001, 5003) |
| Protocol server | MCP (stdio / HTTP) |
