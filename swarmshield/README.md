# SwarmShield

SwarmShield is a multi-agent autonomous cybersecurity system for network threat detection, anticipatory analysis, and automated response. It combines deterministic algorithms (Monte Carlo simulation, genetic algorithms), a CIC-IDS2017 XGBoost ML layer, and optional Grok (xAI) LLM enrichment.

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

### Two pipelines

**Reactive** (confirmed threats):
`Scout.rolling_tick()` → confirmed → POST `/verdict` → `Responder.decide_and_act()`

**Anticipatory** (rising threats before confirmation):
`Scout.rolling_tick()` → early_warning → `Analyzer.pre_assess_risk()` → POST `/preemptive_action` → safety gate → `rate_limit` or `elevated_monitor`

**CIC-ML addon** (XGBoost second opinion, runs every tick):
`Analyzer.cic_screen()` → POST `/cic_block` → dispatch by CIC label

---

## Agents

| Agent | Role | Key mechanism |
|---|---|---|
| **Scout** | Packet-level detection | Monte Carlo simulation over traffic stats; rolling early-warning inference |
| **Analyzer** | Threat graph + risk | Attack graph construction; MC propagation simulation; CIC-IDS2017 XGBoost addon |
| **Responder** | Network enforcement | Flask service; iptables block/quarantine/redirect/rate-limit; auto-unblock thread |
| **Mahoraga (Evolver)** | Threshold evolution | DEAP genetic algorithm; evolves Scout detection thresholds from defense-cycle outcomes |

---

## Features

- Monte Carlo detection for **DDoS**, **PortScan**, **Exfiltration**
- Rolling trend analysis and **early-warning inference** — acts before confidence fully confirms
- **Four-gate pre-emptive safety system** — destructive actions blocked from early-warning path
- Attack-graph construction and MC **lateral-movement propagation simulation**
- **CIC-IDS2017 XGBoost** multi-class intrusion detection (10 classes, 78 features)
- iptables enforcement: block, quarantine, redirect-to-honeypot, rate-limit with **auto-unblock**
- **DEAP genetic algorithm** threshold evolution with FP-penalised fitness function
- **A2A message bus**: in-process pub/sub connecting all agents (no external broker)
- **CrewAI orchestration**: sequential four-agent crew with optional per-task human approval
- Optional **Grok (xAI) LLM enrichment** — schema-constrained JSON outputs, purely advisory
- **Transparency reporter**: agent thought/tool/result stream to console and JSON-Lines log
- **HoneypotBridge**: Flask server (port 5001) feeds honeypot events to Mahoraga as training data

---

## Project Structure

```
swarmshield/
├── README.md
├── requirements.txt
├── .env.example
├── conftest.py                      # pytest src/ path helper
├── run.py                           # CrewAI crew entry point (demo/interactive/batch/mcp)
├── run_live.py                      # Live demo entry point (real or simulated traffic)
├── docs/
│   ├── workflow.md
│   ├── scout.md
│   ├── analyzer.md
│   ├── responder.md
│   ├── evolver.md
│   ├── live_demo.md
│   └── tech_used_and_why.md
├── src/swarmshield/
│   ├── main.py
│   ├── crew.py                      # SwarmShieldCrew (CrewAI)
│   ├── mcp_server.py                # MCP server (stdio / HTTP)
│   ├── agents/
│   │   ├── scout.py
│   │   ├── analyzer.py
│   │   ├── responder.py             # Flask app (port 5003)
│   │   ├── evolver.py               # Mahoraga
│   │   ├── honeypot_bridge.py       # Flask app (port 5001)
│   │   └── llm_client.py
│   ├── tools/
│   │   ├── scout_tool.py
│   │   ├── analyzer_tool.py
│   │   ├── responder_tool.py
│   │   ├── evolution_tool.py
│   │   └── packet_capture_tool.py   # LivePacketCapture (Scapy)
│   ├── utils/
│   │   ├── message_bus.py           # A2A pub/sub singleton
│   │   ├── ml_classifier.py         # CICClassifier (XGBoost)
│   │   └── transparency.py
│   ├── model/
│   │   └── cic_multiclass_model.pkl
│   └── demo/
│       └── live_demo.py
└── tests/
    ├── test_agents.py
    ├── test_tools.py
    ├── test_crew.py
    ├── test_responder.py
    ├── run_scout_agent.py
    ├── run_analyzer_agent.py
    └── run_responder_agent.py
```

---

## Setup

### Prerequisites

- Python 3.9+
- Optional: `XAI_API_KEY` (Grok) or `OPENAI_API_KEY` for LLM enrichment
- Optional: root / `CAP_NET_RAW` for live packet capture

### Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env to add XAI_API_KEY if desired
```

---

## Running

### CrewAI crew

```bash
python run.py                                      # demo, 1 iteration, dry-run
python run.py --mode interactive                   # prompt for scenario
python run.py --mode batch --iterations 5          # 5 randomised scenarios
sudo python run.py --live                          # real iptables (requires root)
HUMAN_APPROVAL=true python run.py                  # operator approval gate
python run.py --mode mcp-server                    # stdio MCP server
python run.py --mode mcp-server --mcp-transport http --mcp-port 8765
```

### Live demo

```bash
python run_live.py --simulate                      # synthetic traffic, no root
sudo run_live.py --interface eth0 --tick 5         # live capture
```

---

## Testing

```bash
PYTHONPATH=src .venv/bin/pytest tests/ -q
PYTHONPATH=src .venv/bin/pytest tests/test_agents.py -v
PYTHONPATH=src python tests/run_scout_agent.py
```

---

## Configuration

Copy `.env.example` to `.env`. Key variables:

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

## Documentation

- [docs/workflow.md](docs/workflow.md) — pipeline architecture, data flow, A2A bus
- [docs/scout.md](docs/scout.md) — detection logic, thresholds, rolling inference
- [docs/analyzer.md](docs/analyzer.md) — threat graph, propagation simulation, CIC-ML addon
- [docs/responder.md](docs/responder.md) — enforcement actions, Flask API, auto-unblock
- [docs/evolver.md](docs/evolver.md) — Mahoraga genome, fitness function, DEAP config
- [docs/live_demo.md](docs/live_demo.md) — live demo entry point, anticipatory pipeline
- [docs/tech_used_and_why.md](docs/tech_used_and_why.md) — technology choices
