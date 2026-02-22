#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# SwarmShield launcher — automatically activates the virtualenv and delegates
# to run.py, forwarding all arguments unchanged.
#
# Usage:
#   ./run.sh [--dry-run | --live] [--mode demo|batch|interactive|mcp-server] [--iterations N]
#            [--mcp-transport stdio|http] [--mcp-port PORT]
#
# Examples:
#   ./run.sh --dry-run --mode demo --iterations 1
#   ./run.sh --live   --mode batch --iterations 5
#   ./run.sh --mode mcp-server                         # stdio MCP (Claude Desktop)
#   ./run.sh --mode mcp-server --mcp-transport http --mcp-port 8765
# ---------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON="$VENV_DIR/bin/python3"

# ── locate virtual environment ─────────────────────────────────────────────
if [[ ! -x "$PYTHON" ]]; then
    echo "[swarmshield] Virtual environment not found at $VENV_DIR"
    echo "[swarmshield] Creating it now…"
    python3 -m venv "$VENV_DIR"
    echo "[swarmshield] Installing dependencies…"
    "$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
fi

# ── load .env if present ───────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
fi

# ── run ───────────────────────────────────────────────────────────────────
exec "$PYTHON" "$SCRIPT_DIR/run.py" "$@"
