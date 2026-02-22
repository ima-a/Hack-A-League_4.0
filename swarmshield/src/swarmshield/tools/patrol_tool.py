"""
Patrol Tool

Legacy shim kept for backwards compatibility.
Actual network monitoring is handled by ScoutAgent in agents/scout.py.
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class PatrolTool:
    """Legacy patrol shim. Use ScoutAgent for real network monitoring."""
    
    def __init__(self):
        """Initialize patrol tool."""
        self.logger = logging.getLogger(f"{__name__}.PatrolTool")
    
    def execute(self, network_data: Dict) -> Dict[str, Any]:
        """
        Execute patrol analysis on network data.
        
        Args:
            network_data: Network statistics and flow data
            
        Returns:
            Anomaly detection results
        """
        self.logger.info("Executing patrol analysis...")
        return {
            "anomalies_detected": [],
            "confidence_scores": [],
            "threat_level": "low"
        }
