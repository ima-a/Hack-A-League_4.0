"""
Evolution (Mahoraga) CrewAI Tools
===================================
Wraps the Mahoraga DEAP genetic-algorithm evolver as CrewAI @tool functions
so the Evolver CrewAI Agent can call them during orchestrated task execution.

All tools:
- Accept/return plain strings (JSON-encoded where needed)
- Catch all exceptions and return a JSON error dict instead of raising
- Degrade gracefully when DEAP is not installed (returns DEFAULT_GENOME)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# A2A bus helper — never raises
def _bus_publish(topic: str, message: dict) -> None:
    """Publish to the A2A message bus, silently ignoring any errors."""
    try:
        from ..utils.message_bus import get_bus
        get_bus().publish(topic, message)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Bus publish failed for topic '%s': %s", topic, exc)

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

try:
    from crewai.tools import tool as crewai_tool
    _CREWAI_AVAILABLE = True
except ImportError:
    logger.warning("crewai not installed — evolution tools will not be registered as CrewAI tools.")
    _CREWAI_AVAILABLE = False

    def crewai_tool(name=None, description=None):  # type: ignore[misc]
        """Fallback no-op decorator when crewai is unavailable."""
        def decorator(fn):
            return fn
        return decorator


# ---------------------------------------------------------------------------
# Tool: evolve_detection_thresholds
# ---------------------------------------------------------------------------

@crewai_tool("evolve_detection_thresholds")
def evolve_detection_thresholds(responder_summary_json: str = "{}") -> str:
    """
    Run the Mahoraga genetic algorithm to evolve Scout detection thresholds.

    Accepts a JSON object from the Responder summary (output of apply_defense_actions).
    Extracts outcome records or uses previously-recorded outcomes from disk.
    Falls back to synthetic training scenarios when no real outcomes exist.

    Returns a JSON object with evolved thresholds:
      {
        "best_genome": [...],
        "best_thresholds": {ddos_pps_threshold, ddos_syn_threshold, ...},
        "confidence_threshold": float,
        "best_fitness": float,
        "generations_run": int,
        "outcomes_used": int,
        "llm_insight": {...} or null,
        "timestamp": "..."
      }
    """
    try:
        from ..agents.evolver import Mahoraga

        evolver = Mahoraga()

        # Try to build outcomes from the responder summary
        outcomes = []
        try:
            summary = json.loads(responder_summary_json)
            actions = summary.get("actions_applied", [])
            for act in actions:
                ip = act.get("ip", "")
                action = act.get("action", "monitor")
                confidence = float(act.get("confidence", 0.5))
                threat_type = act.get("threat_type", "Unknown")
                if ip:
                    evolver.record_outcome(
                        source_ip=ip,
                        stats={"packets_per_second": 100.0, "bytes_per_second": 10000.0,
                               "unique_dest_ips": 1, "syn_count": 50,
                               "port_entropy": 0.5, "window_seconds": 10},
                        attack_type=threat_type,
                        confidence=confidence,
                        action_taken=action,
                        enforcement_success=bool(act.get("success", True)),
                    )
        except (json.JSONDecodeError, AttributeError, TypeError):
            pass  # responder_summary_json may be empty or malformed — that's fine

        # Run evolution (falls back to synthetic + saved outcomes automatically)
        result = evolver.evolve()
        # A2A publish
        from ..utils.message_bus import TOPIC_MAHORAGA_EVOLVED
        _bus_publish(TOPIC_MAHORAGA_EVOLVED, {
            "best_fitness": result.get("best_fitness", 0.0),
            "best_thresholds": result.get("best_thresholds", {}),
            "confidence_threshold": result.get("confidence_threshold", 0.6),
            "outcomes_used": result.get("outcomes_used", 0),
            "generations_run": result.get("generations_run", 0),
            "timestamp": _now_iso(),
        })
        return json.dumps(result, default=str)

    except Exception as exc:  # noqa: BLE001
        logger.exception("evolve_detection_thresholds error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Tool: get_current_thresholds
# ---------------------------------------------------------------------------

@crewai_tool("get_current_thresholds")
def get_current_thresholds() -> str:
    """
    Load the most recently evolved Scout detection thresholds from disk.

    Returns a JSON object with the best saved strategy, or the default
    genome if no evolved strategy has been saved yet.

    Keys:
      best_genome, best_thresholds, confidence_threshold, best_fitness,
      generations_run, outcomes_used, timestamp
    """
    try:
        from ..agents.evolver import Mahoraga, DEFAULT_GENOME, GENE_NAMES, _genome_to_thresholds

        evolver = Mahoraga()
        strategy = evolver.get_best_strategy()

        if strategy:
            return json.dumps(strategy, default=str)

        # Return default genome if nothing evolved yet
        default_strategy = {
            "best_genome": list(DEFAULT_GENOME),
            "best_thresholds": _genome_to_thresholds(DEFAULT_GENOME),
            "confidence_threshold": DEFAULT_GENOME[-1],
            "best_fitness": 0.0,
            "generations_run": 0,
            "outcomes_used": 0,
            "source": "default_genome",
            "timestamp": None,
        }
        return json.dumps(default_strategy, default=str)

    except Exception as exc:  # noqa: BLE001
        logger.exception("get_current_thresholds error: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Backwards-compatible class shim (kept so existing imports don't break)
# ---------------------------------------------------------------------------

class EvolutionTool:
    """
    Backwards-compatible shim.
    The actual logic now lives in the @tool functions above.
    """

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.EvolutionTool")

    def execute(self, evolution_params: Dict) -> Dict[str, Any]:
        self.logger.info("Executing strategy evolution via Mahoraga…")
        try:
            result_json = evolve_detection_thresholds("{}")
            return json.loads(result_json)
        except Exception as exc:  # noqa: BLE001
            self.logger.error("Evolution failed: %s", exc)
            return {"evolved_strategies": [], "fitness_scores": [], "best_strategy": {}}
