"""
SwarmShield Main Entry Point

Primary execution module for the CrewAI-based multi-agent system.
"""

# Load .env before anything else so API keys and config are in os.environ
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — env vars must be set manually

import logging
import sys
from pathlib import Path
from typing import List, Optional

from .crew import SwarmShieldCrew

logger = logging.getLogger(__name__)


def main(
    mode: str = "demo",
    agents: Optional[List[str]] = None,
    iterations: int = 1,
    config_path: Optional[str] = None,
) -> None:
    """
    Main entry point for SwarmShield.
    
    Args:
        mode: Execution mode ('demo', 'interactive', 'batch')
        agents: List of agent names to activate
        iterations: Number of iterations to run
        config_path: Optional custom configuration file path
    """
    
    logger.info(f"Initializing SwarmShield in {mode} mode")
    
    try:
        # Initialize the crew
        crew = SwarmShieldCrew(config_path=config_path)
        
        # Execute based on mode
        if mode == "demo":
            logger.info("Running demo mode...")
            crew.run_demo(iterations=iterations)
        
        elif mode == "interactive":
            logger.info("Running interactive mode...")
            crew.run_interactive()
        
        elif mode == "batch":
            logger.info("Running batch mode...")
            crew.run_batch(iterations=iterations)
        
        else:
            raise ValueError(f"Unknown mode: {mode}")
        
        logger.info("SwarmShield execution completed successfully")
    
    except Exception as e:
        logger.exception(f"Error during execution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    main()
