#!/usr/bin/env python3
"""
SwarmShield Entry Point

Simple launcher for the SwarmShield multi-agent system.
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Load .env before importing the package so API keys are available
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

from swarmshield.main import main


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="SwarmShield: Autonomous Network Defense AI Swarm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                                    # Run default demo (dry-run)
  python run.py --mode=interactive                # Interactive mode
  python run.py --iterations=3                    # Run 3 demo iterations
  python run.py --dry-run                         # Explicit dry-run (no iptables)
  python run.py --live                            # Apply real firewall rules (root)
  python run.py --mode=batch --iterations=5       # Batch mode, 5 iterations
  python run.py --mode=mcp-server                 # Start MCP server (stdio)
  python run.py --mode=mcp-server --mcp-transport http --mcp-port 8765
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["demo", "interactive", "batch", "mcp-server"],
        default="demo",
        help="Execution mode (default: demo). Use 'mcp-server' to start the MCP server."
    )
    
    parser.add_argument(
        "--agents",
        type=str,
        default="scout,analyzer,responder,evolver",
        help="Comma-separated agent names to activate"
    )
    
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of iterations to run (default: 1)"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Path to custom config file"
    )

    # MCP server options (only used when --mode=mcp-server)
    parser.add_argument(
        "--mcp-transport",
        choices=["stdio", "http"],
        default="stdio",
        dest="mcp_transport",
        help="MCP transport: 'stdio' (default) for Claude Desktop / VS Code Copilot, "
             "'http' for networked MCP hosts."
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8765,
        dest="mcp_port",
        help="HTTP port for MCP server when --mcp-transport=http (default: 8765)."
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        dest="mcp_host",
        help="Bind address for MCP HTTP server (default: 127.0.0.1)."
    )

    # Mutually exclusive live / dry-run flags
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Simulate all defence actions without touching iptables (default)"
    )
    mode_group.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Apply real iptables rules (requires root; sets LIVE_MODE=true)"
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Set LIVE_MODE env var BEFORE importing crew/tools so modules pick it up
    if getattr(args, "live", False):
        os.environ["LIVE_MODE"] = "true"
        print("[SwarmShield] LIVE MODE - real iptables rules will be applied.")
    else:
        os.environ.setdefault("LIVE_MODE", "false")
        print("[SwarmShield] DRY-RUN MODE — no real firewall changes.")

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Starting SwarmShield...")

    # ── MCP server mode ──────────────────────────────────────────────────────
    if args.mode == "mcp-server":
        from swarmshield.mcp_server import mcp
        transport = args.mcp_transport
        if transport == "http":
            logger.info(
                "Launching SwarmShield MCP server (HTTP) on %s:%d",
                args.mcp_host, args.mcp_port,
            )
            mcp.run(transport="streamable-http", host=args.mcp_host, port=args.mcp_port)
        else:
            logger.info("Launching SwarmShield MCP server (stdio)")
            mcp.run(transport="stdio")
        sys.exit(0)
    # ─────────────────────────────────────────────────────────────────────────

    try:
        # Run the main function with parsed arguments
        main(
            mode=args.mode,
            agents=args.agents.split(","),
            iterations=args.iterations,
            config_path=args.config
        )
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)
