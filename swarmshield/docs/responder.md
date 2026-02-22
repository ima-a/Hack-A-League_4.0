# Responder Agent

Sources:
- Service: `src/swarmshield/agents/responder.py` — Flask app on port 5003
- CrewAI tool wrappers: `src/swarmshield/tools/responder_tool.py`
- Thin wrapper class (used by tests): `src/swarmshield/agents/__init__.py` (`ResponderAgent`)

## What it does

The Responder Agent is the third stage in the SwarmShield pipeline. It receives verdicts from the Analyzer (or directly from Scout via the live demo) and applies the minimum-sufficient defense action for each confirmed threat. It also handles pre-emptive actions (rate-limit, elevated-monitor) from the anticipatory pipeline, a CIC-ML addon endpoint, action logging, and automatic IP unblocking after a configurable timeout.

## Actions supported

    block                - iptables INPUT DROP for source IP
    redirect_to_honeypot - iptables DNAT rule → HONEYPOT_IP
    quarantine           - iptables FORWARD DROP both source and destination
    rate_limit           - iptables hashlimit rule (auto-expires)
    elevated_monitor     - log-only, no enforcement
    monitor              - log-only, no enforcement

## Decision logic (`decide_and_act`)

Priority order (explicit `recommended_action` wins over attack-type fallback):

1. `recommended == "block"` or `attack_type in (DDoS, DoS, Bot)` → **block**
2. `recommended == "redirect_to_honeypot"` or `attack_type == PortScan` → **redirect_to_honeypot**
3. `recommended == "quarantine"` or `attack_type in (Exfiltration, Infiltration)` → **quarantine**
4. `recommended == "rate_limit"` → **rate_limit**
5. Anything else → **monitor**

## Flask API

### `POST /verdict`

Receive a confirmed-threat verdict and execute the action.

Required fields: `source_ip`, `predicted_attack_type`, `confidence`, `shap_explanation`, `recommended_action`, `agent_id`.

Response: `{status, action_taken, success, agent_id, timestamp}`. Includes `llm_validation` if `XAI_API_KEY` is set.

### `POST /preemptive_action`

Receive an anticipatory action request from `Analyzer.pre_assess_risk()`.

Allowed actions: `rate_limit`, `elevated_monitor` only.

All four safety-gate conditions must pass:
1. Action is whitelisted (rate_limit or elevated_monitor).
2. `alert_level` is `early_warning`.
3. `predicted_confidence ≥ PREEMPTIVE_CONFIDENCE_GATE` (default 0.40).
4. `current_confidence < CONFIRMED_CONFIDENCE_GATE` (default 0.60).

A `gate_rejected` response (HTTP 200) means the gate worked — it is not an error.

Required fields: `source_ip`, `alert_level`, `current_confidence`, `predicted_confidence`, `recommended_action`, `agent_id`.

### `POST /cic_block`

CIC-ML addon endpoint. Act on an IP flagged by `Analyzer.cic_screen()`.

Required fields: `source_ip`, `cic_label`, `confidence`. Optional: `recommended_action`.

Minimum confidence gate: `CIC_BLOCK_MIN_CONFIDENCE` (default 0.60). Predictions below this are skipped.

Dispatch: `recommended_action == redirect_to_honeypot` → honeypot, `quarantine` → quarantine, anything else → block.

### `GET /health`

Liveness probe. Returns `{status: "alive", agent_id}`.

## Auto-unblock thread

A background daemon thread (`_auto_unblock_loop`) runs every `AUTO_UNBLOCK_SECONDS` (default: 300 s). It reads the action log, finds IPs whose last action was `block`, `redirect_to_honeypot`, or `rate_limit` and have exceeded their expiry window, then removes the iptables rule.

- Full blocks and redirects: expire after `AUTO_UNBLOCK_SECONDS`.
- Rate-limits: expire after `PREEMPTIVE_AUTO_EXPIRE_SECONDS` (default 60 s).

## Live mode vs dry-run

`LIVE_MODE=false` (default): all actions are simulated and logged but no iptables rules are applied.

`LIVE_MODE=true`: real iptables rules are applied. Requires root / `CAP_NET_ADMIN`.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `COORDINATOR_IP` | `192.168.1.100` | Coordinator address for action reports |
| `HONEYPOT_IP` | `192.168.1.99` | DNAT redirect target |
| `RESPONDER_PORT` | `5003` | Flask listen port |
| `RESPONDER_ID` | `responder-1` | Agent identifier in logs |
| `AUTO_UNBLOCK_SECONDS` | `300` | Seconds before blocks are removed |
| `AUTO_UNBLOCK_MINUTES` | — | Alternative to `AUTO_UNBLOCK_SECONDS` |
| `LIVE_MODE` | `false` | Apply real iptables rules |
| `HUMAN_APPROVAL` | `false` | Operator confirmation before each action |
| `PREEMPTIVE_CONFIDENCE_GATE` | `0.40` | Min predicted confidence for pre-emptive action |
| `CONFIRMED_CONFIDENCE_GATE` | `0.60` | Min confirmed confidence threshold |
| `PREEMPTIVE_EXPIRE_SECONDS` | `60` | Auto-expiry for rate-limit rules |
| `PREEMPTIVE_RATE_LIMIT_PPS` | `100` | Rate-limit threshold (packets/sec) |
| `CIC_BLOCK_MIN_CONFIDENCE` | `0.60` | Min CIC model confidence to act |

## Files written

    blocked_ips.txt          - currently blocked IPs (project root)
    responder_actions.log    - JSON-lines audit trail of all actions

## A2A bus

Every call to `log_action()` publishes to the `responder.action` topic:

    {source_ip, action, requester, success, timestamp, agent_id}

## CrewAI tools

Three `@tool` functions in `tools/responder_tool.py`:

    apply_defense_actions(analyzer_report_json)  - main entry, applies all recommendations
    block_ip_address(ip_address, reason)         - block a single IP immediately
    get_active_blocks()                          - list currently blocked IPs

## Optional LLM validation

If `XAI_API_KEY` is set, the `/verdict` endpoint validates the proposed action via Grok before execution. The LLM defaults to approving the action and only suggests an override when there is a concrete risk. The LLM output never blocks execution — it is advisory only.
