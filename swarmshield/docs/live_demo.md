# Live Demo

Source: `src/swarmshield/demo/live_demo.py`
Entry point: `run_live.py`

## What it does

The live demo runs SwarmShield in real time using either live network traffic (Scapy) or synthetic packet simulation (no root needed). Unlike the CrewAI crew (`run.py`), which runs one batch cycle, the live demo runs continuously with a rolling inference loop.

## Architecture

```
LivePacketCapture (Scapy, background thread)
    │  drain(window_seconds) → list[dict]
    ▼
ScoutAgent.run_rolling_inference()
    │  on_tick callback
    │      → pretty-prints tick summary
    │      → POST /verdict for confirmed threats  (reactive path)
    │      → Analyzer.cic_screen() → POST /cic_block  (CIC-ML addon)
    │
    │  on_early_warning callback
    │      → Analyzer.pre_assess_risk()
    │      → POST /preemptive_action  (anticipatory path)
    ▼
ResponderAgent Flask server (background daemon thread)
    Listens on localhost:5000 (configurable)

A2A Message Bus
    Subscribed to all 6 topics for console logging
    Mahoraga auto-records confirmed Responder actions as training data
```

## Running

```bash
# Synthetic traffic — no root, no Scapy required
python run_live.py --simulate

# Live capture, all interfaces (requires root)
sudo python run_live.py

# Live capture, specific interface
sudo python run_live.py --interface eth0

# Custom tick interval and rolling window
python run_live.py --simulate --tick 3 --horizon 120

# Custom Responder bind address
python run_live.py --simulate --responder-host 0.0.0.0 --responder-port 5000
```

Press `Ctrl-C` to stop all threads cleanly.

## Arguments

| Argument | Default | Description |
|---|---|---|
| `--interface` / `-i` | all | Network interface to sniff |
| `--filter` / `-f` | `"ip"` | BPF capture filter |
| `--tick` / `-t` | `5.0` | Seconds between Scout inference ticks |
| `--horizon` | `60.0` | Rolling buffer width in seconds |
| `--responder-host` | `127.0.0.1` | Responder Flask bind address |
| `--responder-port` | `5000` | Responder Flask port |
| `--simulate` | off | Use synthetic traffic instead of live capture |

## Startup sequence

1. Start Responder Flask server in background daemon thread.
2. If not `--simulate`: start `LivePacketCapture` (Scapy) and set `packet_source = cap.drain`.
3. Initialise `ScoutAgent(packet_source=packet_source)` and `AnalyzerAgent()`.
4. Subscribe all A2A bus topics for console visibility and Mahoraga auto-recording.
5. Build `on_tick` and `on_early_warning` callbacks.
6. Call `scout.run_rolling_inference(...)` — blocks until `Ctrl-C`.
7. Stop capture and shut down cleanly.

## Tick callback (`on_tick`)

Runs after every `rolling_tick()` call.

- Logs tick summary: buffer size, early warning count, confirmed count.
- For each confirmed IP: POST `{source_ip, predicted_attack_type, confidence, shap_explanation, recommended_action, agent_id}` to `/verdict`.
- Runs `analyzer.cic_screen(per_ip)` and POSTs each flagged IP to `/cic_block`.

## Early-warning callback (`on_early_warning`)

Runs only when one or more IPs reach `early_warning` alert level.

1. Builds a synthetic tick result containing only the early-warning IPs.
2. Calls `analyzer.pre_assess_risk(synthetic_tick)`.
3. For each preemptive action: POST to `/preemptive_action`.
4. Logs `ok` (action applied), `gate_rejected` (safety gate blocked it), or error.

## A2A bus subscriptions

All six topics are subscribed in `_setup_a2a_bus()`:

| Topic | Console output |
|---|---|
| `scout.tick` | buffer size, early warnings, confirmed threats (only when non-zero) |
| `scout.early_warning` | list of rising IPs |
| `analyzer.pre_assessment` | preemptive actions summary |
| `analyzer.assessment` | risk level and score |
| `responder.action` | action type, IP, success flag |
| `mahoraga.evolved` | fitness, outcomes used, confidence gate |

The `responder.action` handler also auto-records confirmed enforcement actions into Mahoraga's training data (`swarmshield/runtime/mahoraga_outcomes.jsonl`) so the GA evolves from real defense cycles.
