"""
response_tools.py — SwarmShield

Standalone helper functions used by the Responder agent for IP list
management, input validation, log-entry formatting, and coordinator
communication.  No framework dependencies — only the standard library
plus *requests*.
"""

import ipaddress
import logging
import os
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IP file helpers
# ---------------------------------------------------------------------------

def load_blocked_ips(filepath: str = "blocked_ips.txt") -> set:
    """
    Load the set of currently blocked IP addresses from *filepath*.

    Each non-empty line in the file is treated as one IP string.
    Whitespace is stripped; blank lines are ignored.

    Args:
        filepath: Path to the blocked-IPs file. Defaults to
                  ``"blocked_ips.txt"`` in the current working directory.

    Returns:
        A :class:`set` of IP strings.  Returns an empty set if the file
        does not exist or cannot be read.
    """
    blocked: set = set()
    if not os.path.exists(filepath):
        return blocked
    try:
        with open(filepath, "r") as fh:
            for line in fh:
                ip = line.strip()
                if ip:
                    blocked.add(ip)
    except OSError as exc:
        logger.error("load_blocked_ips: cannot read %s: %s", filepath, exc)
    return blocked


def save_blocked_ip(ip: str, filepath: str = "blocked_ips.txt") -> bool:
    """
    Append *ip* to *filepath* if it is not already present.

    Args:
        ip:       The IP address string to persist.
        filepath: Path to the blocked-IPs file. Defaults to
                  ``"blocked_ips.txt"``.

    Returns:
        ``True`` if the IP was added, ``False`` if it was already in the
        file (no duplicate is written).
    """
    existing = load_blocked_ips(filepath)
    if ip in existing:
        logger.debug("save_blocked_ip: %s already in %s", ip, filepath)
        return False
    try:
        with open(filepath, "a") as fh:
            fh.write(f"{ip}\n")
        logger.info("save_blocked_ip: added %s to %s", ip, filepath)
        return True
    except OSError as exc:
        logger.error("save_blocked_ip: cannot write to %s: %s", filepath, exc)
        return False


def remove_blocked_ip(ip: str, filepath: str = "blocked_ips.txt") -> bool:
    """
    Remove *ip* from *filepath*, rewriting the file without that line.

    Args:
        ip:       The IP address string to remove.
        filepath: Path to the blocked-IPs file. Defaults to
                  ``"blocked_ips.txt"``.

    Returns:
        ``True`` if the IP was found and removed, ``False`` if it was not
        present in the file.
    """
    if not os.path.exists(filepath):
        logger.debug("remove_blocked_ip: %s does not exist", filepath)
        return False
    try:
        with open(filepath, "r") as fh:
            lines = fh.readlines()
        filtered = [ln for ln in lines if ln.strip() != ip]
        if len(filtered) == len(lines):
            logger.debug("remove_blocked_ip: %s not found in %s", ip, filepath)
            return False
        with open(filepath, "w") as fh:
            fh.writelines(filtered)
        logger.info("remove_blocked_ip: removed %s from %s", ip, filepath)
        return True
    except OSError as exc:
        logger.error("remove_blocked_ip: error updating %s: %s", filepath, exc)
        return False


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def is_valid_ip(ip_string: str) -> bool:
    """
    Check whether *ip_string* is a valid IPv4 address.

    Uses :mod:`ipaddress` from the standard library; no third-party
    dependencies required.

    Args:
        ip_string: The string to validate.

    Returns:
        ``True`` if *ip_string* is a syntactically valid IPv4 address,
        ``False`` otherwise (including IPv6, hostnames, or malformed input).
    """
    try:
        addr = ipaddress.ip_address(ip_string)
        return addr.version == 4
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Log-entry formatting
# ---------------------------------------------------------------------------

def format_action_log_entry(
    ip: str,
    action: str,
    requester: str,
    success: bool,
) -> dict:
    """
    Build a structured log-entry dictionary for a Responder action.

    Args:
        ip:        The attacker / target IP address.
        action:    The action taken (e.g. ``"block"``, ``"quarantine"``).
        requester: Identifier of the agent or component that requested
                   the action (e.g. ``"responder-1"``).
        success:   Whether the action completed successfully.

    Returns:
        A :class:`dict` with the following keys:

        * ``timestamp``   — UTC time of creation as an ISO-8601 string.
        * ``attacker_ip`` — the *ip* argument.
        * ``action_taken``— the *action* argument.
        * ``requested_by``— the *requester* argument.
        * ``success``     — the *success* argument (bool).
    """
    return {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "attacker_ip":  ip,
        "action_taken": action,
        "requested_by": requester,
        "success":      success,
    }


# ---------------------------------------------------------------------------
# Coordinator / Dashboard communication
# ---------------------------------------------------------------------------

def post_to_coordinator(
    coordinator_ip: str,
    port: int,
    endpoint: str,
    payload_dict: dict,
) -> bool:
    """
    Send a JSON POST request to a coordinator or dashboard service.

    Constructs the URL as ``http://{coordinator_ip}:{port}/{endpoint}``
    and posts *payload_dict* as the JSON body.

    Args:
        coordinator_ip: IP address (or hostname) of the target service.
        port:           TCP port of the target service.
        endpoint:       URL path without a leading slash
                        (e.g. ``"action_taken"`` or ``"update"``).
        payload_dict:   Dictionary to serialise as the JSON request body.

    Returns:
        ``True`` if the request was sent and a response was received
        (any HTTP status code counts as a successful send).
        ``False`` if a network error, timeout, or exception occurred.
    """
    url = f"http://{coordinator_ip}:{port}/{endpoint}"
    try:
        response = requests.post(url, json=payload_dict, timeout=3)
        logger.info(
            "post_to_coordinator: POST %s → HTTP %d", url, response.status_code
        )
        return True
    except requests.exceptions.Timeout:
        logger.warning("post_to_coordinator: timed out reaching %s", url)
        return False
    except requests.exceptions.ConnectionError as exc:
        logger.warning("post_to_coordinator: connection error to %s: %s", url, exc)
        return False
    except requests.exceptions.RequestException as exc:
        logger.error("post_to_coordinator: unexpected error posting to %s: %s", url, exc)
        return False
