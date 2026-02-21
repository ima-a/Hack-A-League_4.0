# Responder Agent

Sources:
- Service implementation: `src/swarmshield/agents/responder.py`
- Thin wrapper class (used by unit tests): `src/swarmshield/agents/__init__.py` (`ResponderAgent`)

## What it does
The Responder Agent is a Flask service that receives verdicts (typically from Analyzer/Evolver), applies a defensive action, and logs/reports that action.

Actions supported:
- **block**: add `iptables` DROP rule for source IP
- **redirect_to_honeypot**: add `iptables` DNAT rule to send traffic to a honeypot
- **quarantine**: add `iptables` FORWARD DROP rules (both directions)
- **monitor**: no enforcement, just logs

It also has a background loop that can auto-unblock / remove redirects after a timeout.

## Configuration
Environment variables used by the service:
- `COORDINATOR_IP` (default `192.168.1.100`)
- `HONEYPOT_IP` (default `192.168.1.99`)
- `RESPONDER_PORT` (default `5003`)
- `RESPONDER_ID` (default `responder-1`)
- `AUTO_UNBLOCK_SECONDS` (default `300`) or `AUTO_UNBLOCK_MINUTES` (default `5`)

Files written at project root:
- `blocked_ips.txt`
- `responder_actions.log` (JSON lines)

## Key sections in the implementation
### 1) Command execution (`_run_cmd`)
Runs system commands (like `iptables`) with `shell=False`, captures output, and returns a boolean success flag.

### 2) Core action functions
- `block_ip(ip_address)`
- `redirect_to_honeypot(ip_address)`
- `quarantine_host(ip_address)`
- `unblock_ip(ip_address)`
- `remove_redirect(ip_address)`

Each action logs to `responder_actions.log` via `log_action(...)`.

### 3) Reporting callbacks (`report_action_async`)
Asynchronously POSTs the action result to:
- Coordinator: `http://<COORDINATOR_IP>:5000/action_taken`
- Dashboard: `http://<COORDINATOR_IP>:5005/update`

Failures to reach these targets are logged but do not break verdict handling.

### 4) Decision engine (`decide_and_act`)
Given a verdict payload, selects the response.

Priority order:
1. Explicit `recommended_action`
2. Fallback based on `predicted_attack_type`

### 5) Flask API
#### `POST /verdict`
Expected JSON fields:
- `source_ip`
- `predicted_attack_type`
- `confidence`
- `shap_explanation`
- `recommended_action`
- `agent_id`

Response:
- `status`, `action_taken`, `success`, `agent_id`, `timestamp`

If LLM validation is enabled, responses may also include:
- `llm_validation` (a strict JSON object validating/overriding the proposed action)

#### `GET /health`
Returns `{ "status": "alive", "agent_id": "responder-1" }` (agent id depends on `RESPONDER_ID`).

## ResponderAgent wrapper class
`src/swarmshield/agents/__init__.py` contains a small `ResponderAgent` class used by unit tests.

It provides:
- `deploy_mirage(config)` returning a summary dict (stub)
- lightweight `block(ip)` / `redirect_to_honeypot(ip)` helpers (local stubs)

## Optional LLM validation (Grok)
Responder can validate the deterministic decision engine’s chosen action using the shared Grok-backed `LLMClient`.

- The LLM is constrained to strict JSON output.
- It is instructed to approve the deterministic action by default and only suggest an override when there is a concrete risk.

## How to see it working
Run the smoke test:
- `tests/run_responder_agent.py`

It exercises helper functions and Flask endpoints using Flask’s test client, with `subprocess.run` mocked so the tests don’t require `sudo`.
