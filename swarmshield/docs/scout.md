# Scout Agent

Source: `src/swarmshield/agents/scout.py`

## What it does

The Scout Agent is the first stage in the SwarmShield pipeline. It detects suspicious behaviour per source IP by computing traffic statistics and scoring threats using Monte Carlo simulation.

Two complementary modes:

1. **Single-window detection**: compute features for one time window and score each source IP.
2. **Rolling inference**: maintain a time-bounded packet buffer, track per-IP confidence trends, issue early warnings before the hard detection threshold is crossed, and drive the anticipatory pipeline.

## Packet metadata schema

Each packet dict has:

    src_ip        string
    dst_ip        string
    dst_port      int
    protocol      string  (e.g. "TCP")
    size          int     (bytes)
    timestamp     float   (epoch seconds)
    is_syn        bool

`capture_packets()` uses a `packet_source` callable (e.g. `LivePacketCapture.drain`) if one is supplied, otherwise generates synthetic traffic so the pipeline runs without root or Scapy.

## Detection logic

1. Capture or receive a packet list.
2. Compute per-source-IP statistics: `packets_per_second`, `bytes_per_second`, `unique_dest_ips`, `syn_count`, `port_entropy` (Shannon).
3. Run Monte Carlo estimation: for `N_SIMULATIONS` (1000) trials, perturb each metric with Gaussian noise (σ=10%) and check rule triggers.
4. Assign confidence scores: fraction of trials that triggered each rule.
5. Pick the top threat; map to the correct response action via `_THREAT_ACTIONS`.
6. Format threat report, optionally log to file, optionally call LLM for enrichment.

## Threat types and default actions

| Threat | Trigger | Default action |
|---|---|---|
| DDoS | pps ≥ 500 or syn_count ≥ 300 | `block` |
| PortScan | unique_dest_ips ≥ 20 or port_entropy ≥ 3.5 | `redirect_to_honeypot` |
| Exfiltration | bps ≥ 500 000 | `quarantine` |
| Normal | none of the above | `monitor` |

## Detection thresholds

Defaults (overridable per-instance via `thresholds=` kwarg, and evolvable by Mahoraga):

    ddos_pps_threshold:          500    packets/sec from single source
    ddos_syn_threshold:          300    SYN packets in window
    port_scan_unique_ip_thresh:   20    unique destination IPs
    port_scan_entropy_threshold:  3.5   Shannon entropy of destination ports (bits)
    exfil_bps_threshold:     500 000   bytes/sec

    CONFIDENCE_THRESHOLD  = 0.60   minimum confidence to report a detection
    EARLY_WARNING_THRESHOLD = 0.40  predicted confidence above this → early_warning

## Rolling inference and early-warning

`rolling_tick(new_packets, horizon_seconds)`:

1. Appends new packets to the internal buffer, trims packets older than `horizon_seconds` (default: 60 s).
2. For each source IP, recomputes stats and Monte Carlo scores.
3. Updates per-IP belief history (up to 10 snapshots via `deque(maxlen=10)`).
4. Runs `_compute_trend()` — linear regression over the belief history to extrapolate confidence one tick ahead.
5. Classifies alert level: `confirmed`, `early_warning`, `elevated`, or `normal`.
6. Publishes `scout.tick` (every tick) and `scout.early_warning` (when early-warning IPs exist) to the A2A message bus.

Alert levels:

| Level | Condition |
|---|---|
| `confirmed` | current_confidence ≥ CONFIDENCE_THRESHOLD (0.60) |
| `early_warning` | predicted_confidence ≥ CONFIDENCE_THRESHOLD |
| `elevated` | predicted_confidence ≥ EARLY_WARNING_THRESHOLD (0.40) |
| `normal` | neither |

## Optional LLM enrichment

If `XAI_API_KEY` is set and an `LLMClient` is passed to `ScoutAgent(llm_client=...)`, confirmed and early-warning detections include an `llm_insight` block with:

- `attack_subtype`, `kill_chain_stage`, `recommended_action`, `urgency` (1–5), `iocs`, `rationale`

The LLM output is purely advisory. Deterministic scores are never modified.

## CrewAI tools

Three `@tool` functions in `tools/scout_tool.py`:

    scan_network_for_threats(window_seconds)   - full detection cycle
    simulate_attack_traffic(attack_type)       - generate and score synthetic traffic
    run_monte_carlo_analysis(packets_json)     - score a provided packet list

## Public API (ScoutAgent)

    capture_packets(window_seconds) -> list[dict]
    scan_network(window_seconds) -> dict
    detect_anomalies(window_seconds, confidence_threshold) -> list[dict]
    rolling_tick(new_packets, horizon_seconds) -> dict
    run_rolling_inference(tick_seconds, horizon_seconds, n_ticks,
                          on_tick, on_early_warning) -> None
    get_preemptive_candidates(tick_result) -> list[dict]

### `run_rolling_inference` callbacks

    on_tick(result: dict) -> None
        Called after every tick with the full rolling_tick() result.

    on_early_warning(ips: list[str], per_ip: dict) -> None
        Called ONLY when one or more IPs are at early_warning level.
        Fires before CONFIDENCE_THRESHOLD is crossed.
        Used by live_demo.py to trigger Analyzer.pre_assess_risk() → /preemptive_action.

### `get_preemptive_candidates(tick_result)`

Extracts IPs at `early_warning` alert level from a `rolling_tick()` result and returns them as structured dicts ready for `AnalyzerAgent.pre_assess_risk()`:

    [{source_ip, alert_level, current_confidence, predicted_confidence,
      threat_type, stats, trend_direction, trend}, ...]
