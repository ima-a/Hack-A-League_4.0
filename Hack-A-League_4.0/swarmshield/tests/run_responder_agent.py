"""
run_responder_agent.py — SwarmShield

Manual end-to-end smoke test for the Responder Agent.

Tests:
    1.  response_tool helpers  — load/save/remove blocked IPs, is_valid_ip,
                                 format_action_log_entry
    2.  ResponderAgent class   — instantiation, deploy_mirage()
    3.  Flask /health endpoint — liveness probe
    4.  Flask /verdict endpoint — DDoS/block, PortScan/redirect, Normal/monitor,
                                  missing-fields, no-JSON

Usage (from swarmshield/ directory):
    .venv/bin/python tests/run_responder_agent.py
"""

import json
import os
import sys
import tempfile
import threading
import time
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure the swarmshield project root (contains src/) is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PASS = f"{GREEN}[PASS]{RESET}"
FAIL = f"{RED}[FAIL]{RESET}"
INFO = f"{CYAN}[INFO]{RESET}"

results = []


def check(label: str, condition: bool, detail: str = ""):
    tag = PASS if condition else FAIL
    msg = f"  {tag}  {label}"
    if detail:
        msg += f"  →  {detail}"
    print(msg)
    results.append((label, condition))


# ===========================================================================
# 1 — response_tool helpers
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 1 — response_tool helpers{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

try:
    from src.swarmshield.tools.response_tool import (
        format_action_log_entry,
        is_valid_ip,
        load_blocked_ips,
        remove_blocked_ip,
        save_blocked_ip,
    )

    # ---- is_valid_ip --------------------------------------------------------
    print(f"\n  {CYAN}is_valid_ip(){RESET}")
    check("is_valid_ip('192.168.1.1') == True",  is_valid_ip("192.168.1.1"))
    check("is_valid_ip('10.0.0.255') == True",   is_valid_ip("10.0.0.255"))
    check("is_valid_ip('999.0.0.1') == False",   not is_valid_ip("999.0.0.1"))
    check("is_valid_ip('not-an-ip') == False",   not is_valid_ip("not-an-ip"))
    check("is_valid_ip('::1') == False (IPv6)",  not is_valid_ip("::1"))
    check("is_valid_ip('') == False",            not is_valid_ip(""))

    # ---- load / save / remove -----------------------------------------------
    print(f"\n  {CYAN}load_blocked_ips / save_blocked_ip / remove_blocked_ip(){RESET}")

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tf:
        tmp_path = tf.name

    try:
        # Empty file → empty set
        empty = load_blocked_ips(tmp_path)
        check("load from empty file → empty set", empty == set(), str(empty))

        # Missing file → empty set
        missing = load_blocked_ips("/tmp/__swarmshield_missing__.txt")
        check("load from missing file → empty set", missing == set(), str(missing))

        # Save a new IP
        added = save_blocked_ip("10.10.10.10", tmp_path)
        check("save_blocked_ip returns True (new IP)", added is True)

        stored = load_blocked_ips(tmp_path)
        check("IP appears in file after save", "10.10.10.10" in stored, str(stored))

        # Duplicate is silently rejected
        dup = save_blocked_ip("10.10.10.10", tmp_path)
        check("save_blocked_ip returns False (duplicate)", dup is False)

        # Save a second IP
        save_blocked_ip("172.16.0.1", tmp_path)
        stored2 = load_blocked_ips(tmp_path)
        check("two IPs in file", len(stored2) == 2, str(stored2))

        # Remove the first IP
        removed = remove_blocked_ip("10.10.10.10", tmp_path)
        check("remove_blocked_ip returns True (IP exists)", removed is True)

        after_remove = load_blocked_ips(tmp_path)
        check("removed IP is gone", "10.10.10.10" not in after_remove, str(after_remove))
        check("other IP still present", "172.16.0.1" in after_remove, str(after_remove))

        # Remove non-existent IP
        not_found = remove_blocked_ip("8.8.8.8", tmp_path)
        check("remove_blocked_ip returns False (not found)", not_found is False)

    finally:
        os.unlink(tmp_path)

    # ---- format_action_log_entry --------------------------------------------
    print(f"\n  {CYAN}format_action_log_entry(){RESET}")

    entry = format_action_log_entry("192.168.1.5", "block", "analyzer-1", True)
    check("returns a dict", isinstance(entry, dict))
    for key in ("timestamp", "attacker_ip", "action_taken", "requested_by", "success"):
        check(f"key '{key}' present", key in entry, str(entry.get(key, "MISSING")))
    check("attacker_ip == '192.168.1.5'",  entry["attacker_ip"]  == "192.168.1.5")
    check("action_taken == 'block'",        entry["action_taken"] == "block")
    check("requested_by == 'analyzer-1'",   entry["requested_by"] == "analyzer-1")
    check("success == True",                entry["success"]       is True)
    check("timestamp is a non-empty str",   isinstance(entry["timestamp"], str) and len(entry["timestamp"]) > 0)

    entry_fail = format_action_log_entry("10.0.0.1", "quarantine", "responder-1", False)
    check("success=False recorded correctly", entry_fail["success"] is False)

    print(f"\n  {INFO}  Sample log entry:")
    print("  " + json.dumps(entry, indent=4).replace("\n", "\n  "))

except Exception as exc:
    check("response_tool helpers import/run", False, str(exc))

# ===========================================================================
# 2 — ResponderAgent class
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 2 — ResponderAgent class{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

try:
    from src.swarmshield.agents import ResponderAgent

    ra = ResponderAgent()
    check("ResponderAgent instantiation", True)
    check("responder.name == 'Responder'", ra.name == "Responder", repr(ra.name))

    mirage = ra.deploy_mirage({})
    check("deploy_mirage({}) returns dict", isinstance(mirage, dict), str(mirage))
    check("deploy_mirage has 'status' key", "status" in mirage, str(list(mirage.keys())))

    mirage2 = ra.deploy_mirage({"honeypot_ip": "192.168.1.99", "target_subnet": "10.0.0.0/24"})
    check("deploy_mirage(config) returns dict", isinstance(mirage2, dict))

    print(f"\n  {INFO}  deploy_mirage result: {mirage}")

except Exception as exc:
    check("ResponderAgent import/run", False, str(exc))

# ===========================================================================
# 3 & 4 — Flask endpoints via test client (no network required)
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 3 — Flask /health endpoint{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

_flask_ok = False

try:
    from src.swarmshield.agents.responder import app as responder_app

    responder_app.config["TESTING"] = True
    client = responder_app.test_client()
    _flask_ok = True

    # --- /health -------------------------------------------------------------
    resp = client.get("/health")
    check("GET /health → HTTP 200", resp.status_code == 200, f"got {resp.status_code}")

    body = json.loads(resp.data)
    check("body has status == 'alive'",      body.get("status")   == "alive",       str(body))
    check("body has agent_id == 'responder-1'", body.get("agent_id") == "responder-1", str(body))

    print(f"\n  {INFO}  /health response: {body}")

except Exception as exc:
    check("Flask app import/setup", False, str(exc))

# ---- /verdict scenarios -----------------------------------------------------

print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  Section 4 — Flask /verdict endpoint{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

if _flask_ok:
    # Patch subprocess.run and requests.post for every sub-test
    with patch("src.swarmshield.agents.responder.subprocess.run") as mock_sub, \
         patch("src.swarmshield.agents.responder.requests.post") as mock_req:

        mock_sub.return_value = MagicMock(returncode=0, stderr="")
        mock_req.return_value = MagicMock(status_code=200)

        # --- DDoS / block ------------------------------------------------
        print(f"\n  {CYAN}Scenario A — DDoS + block{RESET}")
        payload_ddos = {
            "source_ip":             "203.0.113.42",
            "predicted_attack_type": "DDoS",
            "confidence":            0.97,
            "shap_explanation":      "High packet rate from single source",
            "recommended_action":    "block",
            "agent_id":              "analyzer-1",
        }
        r = client.post("/verdict", data=json.dumps(payload_ddos),
                        content_type="application/json")
        b = json.loads(r.data)
        check("DDoS → HTTP 200",            r.status_code == 200, f"got {r.status_code}")
        check("DDoS → action_taken = block", b.get("action_taken") == "block", str(b))
        check("DDoS → status = ok",          b.get("status") == "ok")
        check("DDoS → success = True",       b.get("success") is True)
        check("DDoS → subprocess.run called (iptables)", mock_sub.call_count >= 1,
              f"called {mock_sub.call_count} time(s)")
        print(f"          {INFO}  response: {b}")

        mock_sub.reset_mock()

        # --- PortScan / redirect ------------------------------------------
        print(f"\n  {CYAN}Scenario B — PortScan + redirect_to_honeypot{RESET}")
        payload_scan = {
            "source_ip":             "198.51.100.7",
            "predicted_attack_type": "PortScan",
            "confidence":            0.88,
            "shap_explanation":      "Sequential port probing detected",
            "recommended_action":    "redirect_to_honeypot",
            "agent_id":              "analyzer-1",
        }
        r = client.post("/verdict", data=json.dumps(payload_scan),
                        content_type="application/json")
        b = json.loads(r.data)
        check("PortScan → HTTP 200",                    r.status_code == 200, f"got {r.status_code}")
        check("PortScan → action_taken = redirect_to_honeypot",
              b.get("action_taken") == "redirect_to_honeypot", str(b))
        check("PortScan → subprocess.run called (DNAT rule)", mock_sub.call_count >= 1,
              f"called {mock_sub.call_count} time(s)")
        print(f"          {INFO}  response: {b}")

        mock_sub.reset_mock()

        # --- Normal / monitor (no subprocess) ----------------------------
        print(f"\n  {CYAN}Scenario C — Normal + monitor{RESET}")
        payload_norm = {
            "source_ip":             "10.10.10.10",
            "predicted_attack_type": "Normal",
            "confidence":            0.55,
            "shap_explanation":      "Baseline traffic",
            "recommended_action":    "monitor",
            "agent_id":              "analyzer-1",
        }
        r = client.post("/verdict", data=json.dumps(payload_norm),
                        content_type="application/json")
        b = json.loads(r.data)
        check("Normal → HTTP 200",                   r.status_code == 200, f"got {r.status_code}")
        check("Normal → action_taken = monitor",     b.get("action_taken") == "monitor", str(b))
        check("Normal → subprocess.run NOT called",  mock_sub.call_count == 0,
              f"called {mock_sub.call_count} time(s)")
        print(f"          {INFO}  response: {b}")

        mock_sub.reset_mock()

        # --- Ransomware / quarantine -------------------------------------
        print(f"\n  {CYAN}Scenario D — Ransomware + quarantine{RESET}")
        payload_ransom = {
            "source_ip":             "172.16.0.77",
            "predicted_attack_type": "Ransomware",
            "confidence":            0.91,
            "shap_explanation":      "Encrypted file patterns detected",
            "recommended_action":    "quarantine",
            "agent_id":              "analyzer-1",
        }
        r = client.post("/verdict", data=json.dumps(payload_ransom),
                        content_type="application/json")
        b = json.loads(r.data)
        check("Ransomware → HTTP 200",                   r.status_code == 200, f"got {r.status_code}")
        check("Ransomware → action_taken = quarantine",  b.get("action_taken") == "quarantine", str(b))
        check("Ransomware → subprocess.run called",      mock_sub.call_count >= 1,
              f"called {mock_sub.call_count} time(s)")
        print(f"          {INFO}  response: {b}")

        mock_sub.reset_mock()

        # --- Missing fields → 400 ----------------------------------------
        print(f"\n  {CYAN}Scenario E — Missing required fields{RESET}")
        r = client.post("/verdict", data=json.dumps({"source_ip": "1.2.3.4"}),
                        content_type="application/json")
        check("Missing fields → HTTP 400", r.status_code == 400, f"got {r.status_code}")
        b = json.loads(r.data)
        check("error key present in response", "error" in b, str(b))
        print(f"          {INFO}  response: {b}")

        # --- No JSON body → 400 ------------------------------------------
        print(f"\n  {CYAN}Scenario F — No JSON body{RESET}")
        r = client.post("/verdict", data="not json")
        check("No JSON → HTTP 400", r.status_code == 400, f"got {r.status_code}")
        print(f"          {INFO}  status code: {r.status_code}")

else:
    print(f"  {YELLOW}[SKIP]{RESET}  Flask app not available — skipping /verdict tests")

# ===========================================================================
# Summary
# ===========================================================================

print(f"\n{BOLD}{'='*60}{RESET}")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed
colour = GREEN if failed == 0 else RED
print(f"{BOLD}{colour}  Responder Agent — {passed}/{total} checks passed{RESET}")
if failed:
    print(f"\n  {RED}Failed checks:{RESET}")
    for label, ok in results:
        if not ok:
            print(f"    • {label}")
print(f"{BOLD}{'='*60}{RESET}\n")

sys.exit(0 if failed == 0 else 1)
