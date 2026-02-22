"""
SwarmShield: Autonomous Network Defense AI Swarm

A distributed multi-agent system for network threat detection, analysis, response, and learning.
"""

__version__ = "0.1.0"
__author__ = "SwarmShield Team"
__description__ = "Autonomous network defense using CrewAI agents"

from . import agents
from . import tools

__all__ = [
    "agents",
    "tools",
]
