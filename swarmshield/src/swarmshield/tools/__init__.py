"""
SwarmShield Tools
==================
Exports all CrewAI @tool functions and legacy class-based tools.

Each import is wrapped in try/except so an optional missing dependency
(e.g. scapy not installed, deap not installed) does not break the whole package.
"""

# Scout tools
try:
    from .scout_tool import (
        run_monte_carlo_analysis,
        scan_network_for_threats,
        simulate_attack_traffic,
    )
except ImportError as _e:
    import logging as _logging
    _logging.getLogger(__name__).warning("scout_tool import failed: %s", _e)

# Analyzer tools
try:
    from .analyzer_tool import (
        build_threat_graph,
        run_propagation_simulation,
        full_threat_analysis,
    )
except ImportError as _e:
    import logging as _logging
    _logging.getLogger(__name__).warning("analyzer_tool import failed: %s", _e)

# Responder tools
try:
    from .responder_tool import (
        apply_defense_actions,
        block_ip_address,
        get_active_blocks,
    )
except ImportError as _e:
    import logging as _logging
    _logging.getLogger(__name__).warning("responder_tool import failed: %s", _e)

# Evolution (Mahoraga) tools
try:
    from .evolution_tool import (
        evolve_detection_thresholds,
        get_current_thresholds,
        EvolutionTool,
    )
except ImportError as _e:
    import logging as _logging
    _logging.getLogger(__name__).warning("evolution_tool import failed: %s", _e)

# Legacy class-based tools (backwards compat)
try:
    from .patrol_tool import PatrolTool
except ImportError:
    pass

try:
    from .threat_sim_tool import ThreatSimTool
except ImportError:
    pass

try:
    from .response_tool import ResponseTool
except ImportError:
    pass

try:
    from .packet_capture_tool import PacketCaptureTool, LivePacketCapture
except ImportError:
    pass

__all__ = [
    # Scout
    "run_monte_carlo_analysis",
    "scan_network_for_threats",
    "simulate_attack_traffic",
    # Analyzer
    "build_threat_graph",
    "run_propagation_simulation",
    "full_threat_analysis",
    # Responder
    "apply_defense_actions",
    "block_ip_address",
    "get_active_blocks",
    # Evolver
    "evolve_detection_thresholds",
    "get_current_thresholds",
    # Legacy class shims
    "EvolutionTool",
    "PatrolTool",
    "ThreatSimTool",
    "ResponseTool",
    "PacketCaptureTool",
]
