"""
SwarmShield Agents

Agent implementations for network defense swarm.
"""

try:
    from .scout import ScoutAgent
except Exception:
    ScoutAgent = None  # type: ignore[assignment,misc]

try:
    from .analyzer import AnalyzerAgent
except Exception:
    AnalyzerAgent = None  # type: ignore[assignment,misc]

try:
    from .responder import app as responder_app
except Exception:
    responder_app = None  # type: ignore[assignment]

try:
    from .evolver import EvolverAgent
except Exception:
    EvolverAgent = None  # type: ignore[assignment,misc]

__all__ = [
    "ScoutAgent",
    "AnalyzerAgent",
    "responder_app",
    "EvolverAgent",
]
