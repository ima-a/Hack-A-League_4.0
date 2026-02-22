"""
test_responder.py — SwarmShield

Unit tests for the Responder agent helper functions and Flask endpoints.

Run with:
    python -m unittest tests/test_responder.py
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from src.swarmshield.tools.response_tool import (
    format_action_log_entry,
    is_valid_ip,
    load_blocked_ips,
    remove_blocked_ip,
    save_blocked_ip,
)
from src.swarmshield.agents.responder import app


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_temp_file(content: str = "") -> str:
    """Create a named temp file with *content* and return its path."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


# ===========================================================================
# Tests — IP file helpers
# ===========================================================================

class TestLoadBlockedIps(unittest.TestCase):
    """Tests for load_blocked_ips()."""

    def test_load_blocked_ips_empty(self):
        """load_blocked_ips on an empty file returns an empty set."""
        path = _make_temp_file("")
        try:
            result = load_blocked_ips(path)
            self.assertIsInstance(result, set)
            self.assertEqual(result, set())
        finally:
            os.unlink(path)

    def test_load_blocked_ips_nonexistent_file(self):
        """load_blocked_ips on a missing file returns an empty set."""
        result = load_blocked_ips("/tmp/__nonexistent_swarmshield__.txt")
        self.assertEqual(result, set())

    def test_load_blocked_ips_with_entries(self):
        """load_blocked_ips correctly parses existing entries."""
        path = _make_temp_file("10.0.0.1\n10.0.0.2\n")
        try:
            result = load_blocked_ips(path)
            self.assertIn("10.0.0.1", result)
            self.assertIn("10.0.0.2", result)
            self.assertEqual(len(result), 2)
        finally:
            os.unlink(path)


# ===========================================================================

class TestSaveAndRemoveBlockedIp(unittest.TestCase):
    """Tests for save_blocked_ip() and remove_blocked_ip()."""

    def test_save_and_remove_blocked_ip(self):
        """Save an IP, verify it's present, remove it, verify it's gone."""
        path = _make_temp_file("")
        ip = "192.168.1.50"
        try:
            # --- save ---
            added = save_blocked_ip(ip, filepath=path)
            self.assertTrue(added, "save_blocked_ip should return True when adding a new IP")

            stored = load_blocked_ips(path)
            self.assertIn(ip, stored, "IP should appear in the file after saving")

            # --- duplicate save ---
            added_again = save_blocked_ip(ip, filepath=path)
            self.assertFalse(added_again, "save_blocked_ip should return False for a duplicate")

            # --- remove ---
            removed = remove_blocked_ip(ip, filepath=path)
            self.assertTrue(removed, "remove_blocked_ip should return True when IP exists")

            stored_after = load_blocked_ips(path)
            self.assertNotIn(ip, stored_after, "IP should be absent after removal")
        finally:
            os.unlink(path)

    def test_remove_nonexistent_ip(self):
        """remove_blocked_ip returns False when the IP is not in the file."""
        path = _make_temp_file("10.0.0.1\n")
        try:
            result = remove_blocked_ip("1.2.3.4", filepath=path)
            self.assertFalse(result)
        finally:
            os.unlink(path)


# ===========================================================================
# Tests — IP validation
# ===========================================================================

class TestIsValidIp(unittest.TestCase):
    """Tests for is_valid_ip()."""

    def test_is_valid_ip_true(self):
        """is_valid_ip returns True for a valid IPv4 address."""
        self.assertTrue(is_valid_ip("192.168.1.1"))

    def test_is_valid_ip_false_out_of_range(self):
        """is_valid_ip returns False for an out-of-range IPv4 string."""
        self.assertFalse(is_valid_ip("999.999.999.999"))

    def test_is_valid_ip_false_not_an_ip(self):
        """is_valid_ip returns False for a non-IP string."""
        self.assertFalse(is_valid_ip("not-an-ip"))

    def test_is_valid_ip_false_ipv6(self):
        """is_valid_ip returns False for an IPv6 address."""
        self.assertFalse(is_valid_ip("::1"))

    def test_is_valid_ip_false_empty(self):
        """is_valid_ip returns False for an empty string."""
        self.assertFalse(is_valid_ip(""))


# ===========================================================================
# Tests — log-entry formatting
# ===========================================================================

class TestFormatActionLogEntry(unittest.TestCase):
    """Tests for format_action_log_entry()."""

    def test_format_action_log_entry(self):
        """Returned dict has all expected keys with correct values."""
        ip        = "192.168.1.5"
        action    = "block"
        requester = "analyzer-1"
        success   = True

        entry = format_action_log_entry(ip, action, requester, success)

        # All required keys must be present
        for key in ("timestamp", "attacker_ip", "action_taken", "requested_by", "success"):
            self.assertIn(key, entry, f"Key '{key}' missing from log entry")

        self.assertEqual(entry["attacker_ip"],  ip)
        self.assertEqual(entry["action_taken"], action)
        self.assertEqual(entry["requested_by"], requester)
        self.assertEqual(entry["success"],      success)

        # Timestamp must be a non-empty string
        self.assertIsInstance(entry["timestamp"], str)
        self.assertTrue(len(entry["timestamp"]) > 0)

    def test_format_action_log_entry_failure(self):
        """Returned dict records success=False correctly."""
        entry = format_action_log_entry("10.0.0.1", "quarantine", "responder-1", False)
        self.assertFalse(entry["success"])


# ===========================================================================
# Tests — Flask /verdict endpoint
# ===========================================================================

class TestVerdictEndpoint(unittest.TestCase):
    """Integration-style tests for the /verdict Flask endpoint."""

    def setUp(self):
        """Configure the Flask test client."""
        app.config["TESTING"] = True
        self.client = app.test_client()

    # Patch subprocess.run (iptables) and requests.post (coordinator reports)
    @patch("src.swarmshield.agents.responder.requests.post")
    @patch("src.swarmshield.agents.responder.subprocess.run")
    def test_verdict_endpoint_ddos_block(self, mock_subprocess, mock_requests_post):
        """
        POST /verdict with DDoS + block triggers iptables (subprocess.run called)
        and returns HTTP 200 with action_taken='block'.
        """
        mock_subprocess.return_value = MagicMock(returncode=0, stderr="")
        mock_requests_post.return_value = MagicMock(status_code=200)

        payload = {
            "source_ip":            "203.0.113.42",
            "predicted_attack_type": "DDoS",
            "confidence":            0.97,
            "shap_explanation":      "High packet rate from single source",
            "recommended_action":    "block",
            "agent_id":              "analyzer-1",
        }

        response = self.client.post(
            "/verdict",
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

        body = json.loads(response.data)
        self.assertEqual(body["status"],       "ok")
        self.assertEqual(body["action_taken"], "block")
        self.assertTrue(body["success"])

        # iptables must have been invoked at least once
        mock_subprocess.assert_called()

    @patch("src.swarmshield.agents.responder.requests.post")
    @patch("src.swarmshield.agents.responder.subprocess.run")
    def test_verdict_endpoint_portscan_redirect(self, mock_subprocess, mock_requests_post):
        """
        POST /verdict with PortScan + redirect_to_honeypot triggers iptables DNAT rule.
        """
        mock_subprocess.return_value = MagicMock(returncode=0, stderr="")
        mock_requests_post.return_value = MagicMock(status_code=200)

        payload = {
            "source_ip":            "198.51.100.7",
            "predicted_attack_type": "PortScan",
            "confidence":            0.88,
            "shap_explanation":      "Sequential port probing detected",
            "recommended_action":    "redirect_to_honeypot",
            "agent_id":              "analyzer-1",
        }

        response = self.client.post(
            "/verdict",
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.data)
        self.assertEqual(body["action_taken"], "redirect_to_honeypot")
        mock_subprocess.assert_called()

    @patch("src.swarmshield.agents.responder.requests.post")
    @patch("src.swarmshield.agents.responder.subprocess.run")
    def test_verdict_endpoint_monitor(self, mock_subprocess, mock_requests_post):
        """
        POST /verdict with Normal + monitor does NOT call subprocess.run.
        """
        mock_subprocess.return_value = MagicMock(returncode=0, stderr="")
        mock_requests_post.return_value = MagicMock(status_code=200)

        payload = {
            "source_ip":            "10.10.10.10",
            "predicted_attack_type": "Normal",
            "confidence":            0.55,
            "shap_explanation":      "Baseline traffic",
            "recommended_action":    "monitor",
            "agent_id":              "analyzer-1",
        }

        response = self.client.post(
            "/verdict",
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.data)
        self.assertEqual(body["action_taken"], "monitor")
        mock_subprocess.assert_not_called()

    def test_verdict_endpoint_missing_fields(self):
        """POST /verdict with an incomplete payload returns HTTP 400."""
        response = self.client.post(
            "/verdict",
            data=json.dumps({"source_ip": "1.2.3.4"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_verdict_endpoint_no_json(self):
        """POST /verdict with no JSON body returns HTTP 400."""
        response = self.client.post("/verdict", data="not json")
        self.assertEqual(response.status_code, 400)


# ===========================================================================
# Tests — /health endpoint
# ===========================================================================

class TestHealthEndpoint(unittest.TestCase):
    """Tests for the /health liveness probe."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_health_returns_200(self):
        """GET /health returns HTTP 200."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

    def test_health_payload(self):
        """GET /health body contains status=alive and correct agent_id."""
        response = self.client.get("/health")
        body = json.loads(response.data)
        self.assertEqual(body["status"],   "alive")
        self.assertEqual(body["agent_id"], "responder-1")


# ===========================================================================

if __name__ == "__main__":
    unittest.main()
