#!/usr/bin/env python3
"""
SwarmShield Entry Point

Simple launcher for the SwarmShield multi-agent system.
"""

import sys
import argparse
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from swarmshield.main import main


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="SwarmShield: Autonomous Network Defense AI Swarm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                                    # Run default demo
  python run.py --mode=interactive                # Interactive mode
  python run.py --agents=scout,analyzer           # Specific agents
  python run.py --iterations=10                   # Run for 10 iterations
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["demo", "interactive", "batch"],
        default="demo",
        help="Execution mode (default: demo)"
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
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Starting SwarmShield...")
    
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
