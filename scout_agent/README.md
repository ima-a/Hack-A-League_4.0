# Scout Agent — SwarmShield Member 2

The Scout Agent is the network-intelligence front-end of the **SwarmShield** multi-agent cybersecurity system.  It continuously captures live traffic, computes sliding-window statistics, estimates threat probabilities via Monte Carlo simulation, and reports findings to the Analyzer Agent.

---

## File Structure

```
scout_agent/
├── attack_patterns.md      # Catalogue of attack signatures and MC risk weights
├── scout_agent.py          # Main agent — all-in-one orchestrator & CLI entry point
├── packet_capture.py       # Scapy AsyncSniffer wrapper with packet normalisation
├── traffic_stats.py        # Thread-safe sliding-window statistics engine
├── monte_carlo.py          # Monte Carlo threat probability estimator
├── reporter.py             # JSON report builder + HTTP POST to Analyzer (with retry)
├── flask_server.py         # Flask HTTP server for runtime config updates
├── heartbeat.py            # Periodic heartbeat sender to the Coordinator
├── scout_log.txt           # Auto-created JSONL log of all outbound reports
└── README.md               # This file
```

---

## Architecture

```
Network Interface
      │  raw packets
      ▼
┌─────────────────┐     drain()     ┌──────────────────┐
│  PacketCapture  │ ──────────────► │   TrafficStats   │
│  (Scapy async)  │                 │  (sliding window)│
└─────────────────┘                 └────────┬─────────┘
                                             │ snapshot
                                    ┌────────▼─────────┐
                                    │  MonteCarloEst.  │
                                    │  (500 trials/cyc)│
                                    └────────┬─────────┘
                                             │ ThreatEstimate
                                    ┌────────▼─────────┐
                                    │     Reporter     │
                                    │  POST → Analyzer │
                                    └──────────────────┘

Sidecar threads:
  HeartbeatSender  → POST /heartbeat → Coordinator  (every 10 s)
  FlaskServer      ← POST /config    ← Coordinator / Evolver
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install scapy flask
```

> Scapy requires **root / administrator privileges** for raw packet capture.
> Run the agent with `sudo python scout_agent.py` on Linux, or inside a container with `NET_RAW` capability.

### 2. Run with defaults

```bash
# Basic run — listens on eth0, reports every 30 s to http://localhost:5001
sudo python scout_agent.py

# Explicit configuration
sudo python scout_agent.py \
    --interface eth0 \
    --analyzer-url http://analyzer:5001 \
    --coordinator-url http://coordinator:6000 \
    --report-interval 15 \
    --alert-threshold 0.70 \
    --flask-port 5100 \
    --verbose
```

### 3. Environment Variable Configuration

All CLI flags have environment variable equivalents — useful for Docker / Kubernetes:

| Variable               | Default                      | Description                          |
|------------------------|------------------------------|--------------------------------------|
| `SCOUT_AGENT_ID`       | `scout-1`                    | Logical agent name                   |
| `SCOUT_INTERFACE`      | `eth0`                       | Network interface to sniff           |
| `SCOUT_BPF_FILTER`     | `ip or arp`                  | BPF capture filter                   |
| `SCOUT_ANALYZER_URL`   | `http://localhost:5001`      | Analyzer base URL                    |
| `SCOUT_COORDINATOR_URL`| `http://localhost:6000`      | Coordinator base URL                 |
| `SCOUT_FLASK_PORT`     | `5100`                       | Config server port                   |
| `SCOUT_REPORT_INTERVAL`| `30`                         | Report cycle in seconds              |
| `SCOUT_ALERT_THRESHOLD`| `0.75`                       | Risk score that triggers instant alert |
| `SCOUT_MC_SIMULATIONS` | `500`                        | Monte Carlo trial count              |
| `SCOUT_WINDOW_SECONDS` | `30`                         | Sliding window width in seconds      |
| `SCOUT_LOG_PATH`       | `scout_log.txt`              | Path to the JSONL log file           |

---

## Flask Config Server API

The agent runs an embedded HTTP server (default port **5100**) for runtime reconfiguration without restarts.

### `GET /health`

Liveness probe.

```json
{"status": "ok", "agent_id": "scout-1", "uptime_seconds": 142.3}
```

### `GET /status`

Full operational snapshot.

```json
{
  "agent_id": "scout-1",
  "uptime_seconds": 142.3,
  "capture": {"total_captured": 18432, "total_dropped": 0, "queue_size": 0},
  "reporter": {"total_sent": 5, "total_failed": 0},
  "monte_carlo": {"n_simulations": 500, "pattern_count": 8}
}
```

### `POST /config`

Push partial configuration updates.  Body is a flat JSON object where each key is a dotted path:

```bash
curl -s -X POST http://scout:5100/config \
  -H "Content-Type: application/json" \
  -d '{
    "stats.window_seconds": 60,
    "monte_carlo.n_simulations": 1000,
    "monte_carlo.pattern.SYN Flood.base_severity": 0.90,
    "reporter.analyzer_url": "http://analyzer-new:5001",
    "agent.report_interval": 20
  }'
```

Response:

```json
{"status": "ok", "applied": ["stats.window_seconds", "monte_carlo.n_simulations"], "ignored": []}
```

**Supported config keys:**

| Key | Type | Description |
|-----|------|-------------|
| `capture.interface` | string | NIC to sniff |
| `capture.bpf_filter` | string | BPF filter expression |
| `stats.window_seconds` | float | Sliding window width |
| `monte_carlo.n_simulations` | int | MC trial count |
| `monte_carlo.pattern.<name>.<field>` | float | Update any pattern field |
| `reporter.analyzer_url` | string | Analyzer endpoint |
| `reporter.timeout` | float | HTTP timeout (s) |
| `reporter.max_retries` | int | Max retry attempts |
| `reporter.log_reports` | bool | Enable/disable disk logging |
| `agent.report_interval` | float | Report cycle (s) |
| `agent.alert_threshold` | float | Instant-alert risk threshold |

### `POST /reset`

Clear the traffic statistics window.

```bash
curl -X POST http://scout:5100/reset
```

---

## Report Schema

Each scheduled report POSTed to the Analyzer at `POST <analyzer_url>/report`:

```json
{
  "schema_version": "1.0",
  "report_id": "3f7a1c...",
  "agent_id": "scout-1",
  "generated_at": 1740080000.0,
  "generated_at_iso": "2026-02-21T10:00:00Z",
  "traffic_window": {
    "window_seconds": 30,
    "pkt_rate": 412.5,
    "byte_rate": 524288.0,
    "syn_ratio": 0.12,
    "port_spread": 8,
    "unique_src_ips": 4,
    "syn_flood_score": 0.0,
    "port_scan_score": 0.32,
    "arp_spoof_score": 0.0,
    "dns_amp_indicator": 0.0,
    "proto_dist": {"TCP": 0.72, "UDP": 0.21, "ARP": 0.07},
    ...
  },
  "threat_estimate": {
    "overall_risk": 0.18,
    "threat_level": "LOW",
    "top_threat": "None",
    "confidence": 0.94,
    "attack_estimates": [...]
  },
  "metadata": {
    "capture_stats": {...},
    "pattern_version": "1.0"
  }
}
```

Alerts (`POST <analyzer_url>/alert`) use a leaner payload:

```json
{
  "type": "ALERT",
  "threat_level": "HIGH",
  "top_threat": "SYN Flood",
  "overall_risk": 0.82,
  ...
}
```

---

## Heartbeat Protocol

The agent sends a heartbeat every 10 s to `POST <coordinator_url>/heartbeat`:

```json
{
  "schema_version": "1.0",
  "agent_id": "scout-1",
  "agent_type": "scout",
  "timestamp": 1740080010.0,
  "sequence": 42,
  "status": "ok",
  "threat_level": "LOW",
  "overall_risk": 0.18,
  "metrics": {
    "pkt_rate": 412.5,
    "unique_src_ips": 4,
    "queue_size": 0,
    "reports_sent": 5,
    "reports_failed": 0
  },
  "flask_port": 5100
}
```

Status transitions:
- `ok` — normal operation
- `degraded` — capture errors or persistent queue overflow
- `stopping` — final beat before shutdown

---

## Attack Patterns

See [attack_patterns.md](attack_patterns.md) for the full catalogue.  Supported patterns:

| Pattern | Base Severity | Propagation | Evidence Signal |
|---------|--------------|-------------|-----------------|
| SYN Flood | 0.85 | 0.15 | `syn_flood_score` |
| Port Scan | 0.45 | 0.50 | `port_scan_score` |
| Brute Force | 0.70 | 0.65 | `pkt_rate` |
| DNS Amplification | 0.80 | 0.20 | `dns_amp_indicator` |
| ARP Spoofing | 0.75 | 0.70 | `arp_spoof_score` |
| ICMP Flood | 0.60 | 0.15 | `icmp_rate` |
| UDP Flood | 0.72 | 0.15 | `port_spread` |
| C2 Beacon | 0.95 | 0.90 | `unique_src_ips` |

---

## Testing Without Root / Scapy

When Scapy is unavailable (no raw-socket privilege, or not installed), `packet_capture.py` automatically falls back to a **simulation mode** that generates synthetic packets at random intervals.  This allows the full agent pipeline — stats, Monte Carlo, reporting, heartbeat, Flask server — to be exercised without network access.

```bash
# No sudo required in simulation mode
python scout_agent.py --verbose
```

---

## Integration with SwarmShield

```
Scout Agent  ──POST /report──►  Analyzer Agent (Member 3)
Scout Agent  ──POST /heartbeat► Coordinator
Scout Agent  ◄─POST /config──   Evolver Agent (Member 4) / Coordinator
```

The Analyzer Agent should expose:
- `POST /report` — accepts full Scout reports
- `POST /alert`  — accepts lightweight instant alerts

The Coordinator should expose:
- `POST /heartbeat` — accepts Scout heartbeats

---

## Dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| `scapy` | Live packet capture | `pip install scapy` |
| `flask` | Config server | `pip install flask` |

All other functionality uses the Python standard library only.
