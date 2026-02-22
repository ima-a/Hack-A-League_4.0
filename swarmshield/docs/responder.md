# Responder Agent

Sources:
- Service implementation: src/swarmshield/agents/responder.py
- CrewAI tool wrappers: src/swarmshield/tools/responder_tool.py
- Thin wrapper class (used by tests): src/swarmshield/agents/__init__.py (ResponderAgent)

## What it does

The Responder Agent is the third stage in the SwarmShield pipeline. It receives the Analyzer risk assessment and applies the minimum-sufficient defense action for each confirmed threat. It also logs every action and auto-unblocks IPs after a configurable timeout to limit false positive impact.

## Actions supported

    block                  - iptables DROP rule for source IP
    redirect_to_honeypot   - iptables DNAT rule sending attack traffic to honeypot
    quarantine             - iptables FORWARD DROP both directions
    rate_limit             - iptables rate-limit rule
    monitor                - no enforcement, log only

## Defense decision logic (in apply_defense_actions)

Given a threat with a confidence score:
- confidence below 0.40:             monitor
- DDoS or SYN flood detected:        block
- PortScan detected:                 redirect_to_honeypot
- Exfiltration detected:             quarantine
- confidence 0.40 to 0.60 (other):  rate_limit
- confidence above 0.60 (other):    block

## Live mode vs dry-run mode

LIVE_MODE=false (default): all actions are simulated and logged but no iptables rules are created.
LIVE_MODE=true:            real iptables rules are applied. Requires root.

Set LIVE_MODE before importing the package:

    LIVE_MODE=true python run.py --live

## Human approval gate

When HUMAN_APPROVAL=true, the Responder pauses before each non-monitor action and prompts the operator with the IP, action, threat type, and confidence. The operator can approve (y), reject (n), or abort all remaining actions (a).

A second approval layer is provided at the CrewAI task level (Task human_input=True): after the Responder task output is shown, CrewAI pauses and lets the operator review and add instructions before Evolver begins.

## Configuration

Environment variables:

    COORDINATOR_IP             - default 192.168.1.100
    HONEYPOT_IP                - default 192.168.1.99
    RESPONDER_PORT             - default 5003
    RESPONDER_ID               - default responder-1
    AUTO_UNBLOCK_SECONDS       - seconds before auto-unblock (default 300)
    AUTO_UNBLOCK_MINUTES       - alternative to AUTO_UNBLOCK_SECONDS
    LIVE_MODE                  - true or false (default false)
    HUMAN_APPROVAL             - true or false (default false)
    PREEMPTIVE_CONFIDENCE_GATE - confidence threshold for preemptive actions (default 0.40)
    CONFIRMED_CONFIDENCE_GATE  - confidence threshold for confirmed actions (default 0.60)

## Files written

    blocked_ips.txt            - list of currently blocked IPs (live mode)
    responder_actions.log      - JSON-lines audit trail of all actions taken

Both files are written at the project root.

## CrewAI tools

The Responder exposes three CrewAI @tool functions in tools/responder_tool.py:

    apply_defense_actions(analyzer_report_json)    - main entry, applies all recommendations
    block_ip_address(ip_address, reason)           - block a single IP immediately
    get_active_blocks()                            - list currently blocked IPs

## Flask API (responder.py)

The responder module also runs as a standalone Flask service for direct HTTP-based verdict delivery:

    POST /verdict          - receive a verdict payload and apply the action
    GET  /health           - liveness probe

Verdict payload fields: source_ip, predicted_attack_type, confidence, recommended_action, agent_id, shap_explanation.

## Optional LLM validation

If XAI_API_KEY is set, the Flask /verdict endpoint can validate the deterministic action choice via Grok before execution. The LLM is instructed to approve by default and only suggest overrides when there is a concrete risk. The LLM output is advisory only.
