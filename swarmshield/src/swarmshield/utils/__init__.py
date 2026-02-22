"""
SwarmShield Utilities

Shared helper functions and utilities.
"""

from . import message_bus

# Optional modules — silently skipped if missing or if deps unavailable
try:
    from . import ml_classifier
    _has_ml = True
except ImportError:
    _has_ml = False

try:
    from . import transparency
    _has_transparency = True
except ImportError:
    _has_transparency = False

__all__ = ["message_bus"]
if _has_ml:           __all__ += ["ml_classifier"]
if _has_transparency: __all__ += ["transparency"]
