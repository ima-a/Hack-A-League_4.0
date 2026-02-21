# Scout Agent

Source: `src/swarmshield/agents/scout.py`

## What it does
The Scout Agent performs a *single-window* packet-metadata capture (simulated in this project), computes per-source traffic statistics, then uses a Monte Carlo ruleset to score likely threats per source IP.

The output of the Scout is a list of **threat observation reports** that can be passed to the Analyzer.

## Main flow
1. **Capture** a window of packet metadata (`capture_packets`).
2. **Group** by `src_ip`.
3. **Compute stats** for each source (`compute_stats`).
4. **Monte Carlo estimate** for each source (`monte_carlo_estimate`).
5. **Format report** and optionally **log detections** (`format_report`, `log_detection`).

## Key sections in the implementation
### 1) Detection thresholds and defaults
The module defines default thresholds in `_DEFAULT_THRESHOLDS` and default runtime values:
- `WINDOW_SECONDS`: analysis window size
- `N_SIMULATIONS`: number of Monte Carlo trials per IP
- `CONFIDENCE_THRESHOLD`: minimum confidence needed to report an anomaly
- `LOG_FILE`: default log filename for detections

You can override thresholds per instance by passing `thresholds=` to `ScoutAgent(...)`.

### 2) Packet metadata schema
The Scout works with a **list of dicts**. Each packet dict uses the keys:
- `src_ip` (str)
- `dst_ip` (str)
- `dst_port` (int)
- `protocol` (str, e.g. `"TCP"`)
- `size` (int bytes)
- `timestamp` (float epoch seconds)
- `is_syn` (bool)

In this repo, `capture_packets()` generates synthetic packets via `_simulate_packets()` so the pipeline works without root privileges / live capture.

### 3) Statistics computation (`_compute_stats`)
`_compute_stats(packets, source_ip, window_seconds)` produces these metrics:
- `packets_per_second`
- `bytes_per_second`
- `unique_dest_ips`
- `syn_count`
- `port_entropy` (Shannon entropy of destination ports)

Entropy is computed by `_shannon_entropy(values)`.

### 4) Monte Carlo scoring (`_monte_carlo_estimate`)
For `n_simulations` trials, each metric is perturbed with Gaussian noise (σ≈10%). Each trial checks rule triggers:
- **DDoS**: packet rate or SYN count exceeds threshold
- **Port scan**: unique destination IPs or port entropy exceeds threshold
- **Exfiltration**: bytes/sec exceeds threshold

Confidence is computed as fraction of trials that triggered the rule:
- `ddos_confidence`
- `port_scan_confidence`
- `exfiltration_confidence`

The result also includes:
- `top_threat`: `ddos | port_scan | exfiltration | normal`
- `top_confidence`: confidence of `top_threat`

If the highest confidence is very low, the threat is treated as `normal`.

### 5) Report formatting and logging
- `_format_report(...)` / `ScoutAgent.format_report(...)` builds a single structured report dict.
- `_log_detection(...)` / `ScoutAgent.log_detection(...)` appends a single-line record to a log file.

Report schema:
- `agent_id`
- `event` (currently `"threat_detected"`)
- `source_ip`
- `attack_type` (capitalized, e.g. `"DDoS"`, `"PortScan"`)
- `confidence`
- `stats`
- `monte_carlo`
- `timestamp`

## Public API (ScoutAgent)
### `ScoutAgent.capture_packets(window_seconds=WINDOW_SECONDS) -> list[dict]`
Returns a single window of packet metadata.

### `ScoutAgent.scan_network(window_seconds=WINDOW_SECONDS) -> dict`
Runs a full scan cycle and returns:
```json
{
  "source_ips": ["..."],
  "findings": {
    "<ip>": {
      "stats": {"...": "..."},
      "monte_carlo": {"...": "..."},
      "threat_level": "high|medium|low|normal"
    }
  },
  "timestamp": "..."
}
```

### `ScoutAgent.detect_anomalies(window_seconds=WINDOW_SECONDS, confidence_threshold=CONFIDENCE_THRESHOLD) -> list[dict]`
Returns a list of threat reports for sources whose `top_confidence` exceeds the threshold and are not `normal`.

### Static helpers (exposed for tests / downstream code)
- `compute_stats(packets, source_ip, window_seconds)`
- `get_all_source_ips(packets)`
- `monte_carlo_estimate(stats, n_simulations, thresholds=None)`
- `format_report(source_ip, stats, mc_result, agent_id)`
- `log_detection(source_ip, attack_type, confidence, log_file)`

## How to see it working
Run the smoke test:
- `tests/run_scout_agent.py`

It feeds synthetic packets, prints computed stats, the Monte Carlo scores, the formatted report, and the scan/anomaly outputs.
