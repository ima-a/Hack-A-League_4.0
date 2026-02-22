"""
SwarmShield Utilities

Shared helper functions and utilities.
"""

from . import message_bus

# Optional modules — silently skipped if missing or if deps unavailable
try:
    from . import ml_classifier
    __all__ = ["message_bus", "ml_classifier"]
except ImportError:
    __all__ = ["message_bus"]
