# Responder Agent

Sources:
- Service implementation: `src/swarmshield/agents/responder.py`
- Thin wrapper class: `src/swarmshield/agents/__init__.py` (`ResponderAgent`)

## What it does
The Responder Agent is a Flask service that receives verdicts (typically from Analyzer/Evolver), applies a defensive action, and logs/reports that action.

Actions supported:
- **block**: add `iptables` DROP rule for source IP
- **redirect_to_honeypot**: add `iptables` DNAT rule to send traffic to a honeypot
- **quarantine**: add `iptables` FORWARD drop rules (both directions)
- **monitor**: no enforcement, just logs

It also has an optional background loop that can auto-unblock / remove redirects after a timeout.

## Configuration
Environment variables used by the service:
- `COORDINATOR_IP` (default `192.168.1.100`)
- `HONEYPOT_IP` (default `192.168.1.99`)
- `RESPONDER_PORT` (default `5003`)

Files written at project root:
- `blocked_ips.txt`
- `responder_actions.log` (JSON lines)

## Key sections in the implementation
### 1) Command execution (`_run_cmd`)
Runs system commands (like `iptables`) with `shell=False`, captures output, and returns a boolean success flag.

### 2) Core action functions
- `block_ip(ip)`
- `redirect_to_honeypot(ip)`
- `quarantine_host(ip)`
- `unblock_ip(ip)`
- `remove_redirect(ip)`

Each action logs to `responder_actions.log` via `log_action(...)`.

### 3) Action logging (`log_action`)
Appends one JSON object per line:
- `timestamp`
- `attacker_ip`
- `action_taken`
- `requested_by`
- `success`

### 4) Reporting callbacks (`report_action_async`)
Asynchronously POSTs the action result to:
- Coordinator: `http://<COORDINATOR_IP>:5000/action_taken`
- Dashboard: `http://<COORDINATOR_IP>:5005/update`

Failures to reach these targets are logged but don’t break the request path.

### 5) Decision engine (`decide_and_act`)
Given a verdict payload, selects the response. Priority order:
1. Explicit `recommended_action`.
2. Fallback based on `predicted_attack_type`.

Returns `(action_taken, success)`.

### 6) Auto-unblock background loop
`start_auto_unblock_thread()` starts a daemon thread that periodically scans `responder_actions.log` and removes blocking/redirect actions older than `AUTO_UNBLOCK_SECONDS`.

### 7) Flask API
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

#### `GET /health`
Returns `{ "status": "alive", "agent_id": "responder-1" }`.

## ResponderAgent wrapper class
The repository also includes a small `ResponderAgent` class (in `agents/__init__.py`) used by unit tests. It provides:
- `deploy_mirage(config)` returning a summary dict
- lightweight `block(ip)` / `redirect_to_honeypot(ip)` helpers (local stubs)

## How to see it working
Run the smoke test:
- `tests/run_responder_agent.py`

It exercises helper functions and Flask endpoints using Flask’s test client, with `subprocess.run` mocked so the tests don’t require `sudo`.
