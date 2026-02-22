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
# Scout Agent

Source: `src/swarmshield/agents/scout.py`

## What it does
The Scout Agent detects suspicious behavior per source IP.

It has two complementary modes:
1. **Single-window detection**: compute features for one time window and run a Monte Carlo ruleset to classify likely threats.
2. **Rolling inference (early warning)**: maintain a rolling packet buffer and track per-IP confidence trends to warn *before* the hard detection threshold is crossed.

Outputs are **threat observation reports** that are meant to feed into the Analyzer.

## Packet metadata schema
Scout operates on a list of dicts where each “packet” has:
- `src_ip` (str)
- `dst_ip` (str)
- `dst_port` (int)
- `protocol` (str)
- `size` (int bytes)
- `timestamp` (float epoch seconds)
- `is_syn` (bool)

In this repo, `capture_packets()` generates realistic synthetic traffic so the pipeline runs without root privileges or live capture.

## Detection logic (single window)
1. Capture packets (`capture_packets`).
2. Compute per-source statistics (`compute_stats`).
3. Run Monte Carlo estimation (`monte_carlo_estimate`).
4. Format a report (`format_report`) and optionally log (`log_detection`).

Threat rules scored (confidence is the fraction of Monte Carlo trials that trigger):
- **DDoS**: packets/sec or SYN count high
- **PortScan**: many unique destinations or high destination-port entropy
- **Exfiltration**: bytes/sec high

## Rolling inference (early warning)
Rolling inference tracks confidence history per IP and extrapolates a short-term trend.

- `rolling_tick(new_packets, horizon_seconds=...)`:
  - updates the internal time-bounded buffer
  - recomputes per-IP Monte Carlo confidence
  - computes a trend (direction + slope + predicted confidence)
  - assigns an `alert_level`:
    - `confirmed` (current confidence crosses hard threshold)
    - `early_warning` (predicted confidence crosses early-warning threshold)
    - `elevated` / `normal`
- `run_rolling_inference(...)` runs `rolling_tick()` in a loop.

This is intentionally conservative: it provides “heads up” signals without replacing the deterministic confidence scores.

## Optional LLM enrichment (Grok)
Scout can attach an `llm_insight` JSON object to:
- a threat report returned by `detect_anomalies()`
- a per-IP entry in `rolling_tick()` when the alert level is `early_warning` or `confirmed`

This is an *enrichment* layer only: core detection remains deterministic.

How to enable:
- Set `XAI_API_KEY` (and optionally `LLM_MODEL`, `LLM_TEMPERATURE`) in your environment.
- Construct an `LLMClient` and pass it into `ScoutAgent(llm_client=...)`.

## Public API
- `capture_packets(window_seconds=...) -> list[dict]`
- `scan_network(window_seconds=...) -> dict`
- `detect_anomalies(window_seconds=..., confidence_threshold=...) -> list[dict]`
- `rolling_tick(new_packets, horizon_seconds=...) -> dict`
- `run_rolling_inference(tick_seconds=..., horizon_seconds=..., n_ticks=..., on_tick=...) -> None`

## How to see it working
Run `tests/run_scout_agent.py`.
