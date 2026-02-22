# Scout Agent

Source: src/swarmshield/agents/scout.py

## What it does

The Scout Agent is the first stage in the SwarmShield pipeline. It detects suspicious behavior per source IP by computing traffic statistics and scoring threats using a Monte Carlo simulation.

It has two complementary modes:

1. Single-window detection: compute features for one time window and score each source IP.
2. Rolling inference (early warning): maintain a rolling packet buffer and track per-IP confidence trends to warn before the hard detection threshold is crossed.

## Packet metadata schema

Scout works on a list of packet dicts. Each packet has:

    src_ip        string
    dst_ip        string
    dst_port      int
    protocol      string (e.g. TCP)
    size          int (bytes)
    timestamp     float (epoch seconds)
    is_syn        bool

In this repo, capture_packets() generates synthetic traffic so the pipeline runs without root privileges. ScoutAgent falls back to synthetic data automatically.

## Detection logic (single window)

1. Capture or receive packet list.
2. Compute per-source-IP statistics (pps, bps, unique dest IPs, SYN count, port entropy).
3. Run Monte Carlo estimation: for N_SIMULATIONS trials, perturb each metric with Gaussian noise and check rule triggers.
4. Assign confidence scores: fraction of trials that triggered each rule.
5. Format a threat report per IP and optionally log to file.

Threat types scored:
- DDoS: packets per second or SYN count above threshold
- PortScan: many unique destination IPs or high destination-port entropy
- Exfiltration: bytes per second above threshold

## Detection thresholds

Defaults (overridable per instance via thresholds= kwarg):

    ddos_pps_threshold:          500   (packets/sec from single source)
    ddos_syn_threshold:          300   (SYN packets in window)
    port_scan_unique_ip_thresh:   20   (unique destination IPs)
    port_scan_entropy_threshold:  3.5  (Shannon entropy of destination ports)
    exfil_bps_threshold:     500000   (bytes/sec)

CONFIDENCE_THRESHOLD = 0.60 - minimum confidence to include a finding in the report.

## Rolling inference (early warning)

rolling_tick(new_packets, horizon_seconds) updates the internal buffer and extrapolates a confidence trend per IP. An early_warning alert is issued when predicted confidence crosses EARLY_WARNING_THRESHOLD (0.40) before confirmed detection.

Alert levels: confirmed, early_warning, elevated, normal.

## Optional LLM enrichment

If XAI_API_KEY is set and an LLMClient is passed into ScoutAgent(llm_client=...), threat reports include an llm_insight block with attack subtype, kill-chain stage, urgency, and rationale. The LLM output is purely advisory. The deterministic scores are never modified.

## CrewAI tools

The Scout exposes three CrewAI @tool functions in tools/scout_tool.py:

    scan_network_for_threats(window_seconds)   - full detection cycle
    simulate_attack_traffic(attack_type)       - generate and score synthetic traffic
    run_monte_carlo_analysis(packets_json)     - score a provided packet list

## Public API (ScoutAgent)

    capture_packets(window_seconds) -> list
    scan_network(window_seconds) -> dict
    detect_anomalies(window_seconds, confidence_threshold) -> list
    rolling_tick(new_packets, horizon_seconds) -> dict
    run_rolling_inference(tick_seconds, horizon_seconds, n_ticks, on_tick) -> None
