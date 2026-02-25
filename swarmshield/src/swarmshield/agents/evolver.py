"""
Mahoraga — Adaptive Defense Strategy Evolver
=============================================

Named after the Divine General Mahoraga (Jujutsu Kaisen):
  "The being that adapts to all techniques."

Uses DEAP genetic algorithms to evolve Scout detection thresholds from
real defense-cycle outcomes, minimising both false positives and false
negatives over time.

LLM enrichment (optional)
--------------------------
After every evolution run Mahoraga asks Grok (via LLMClient) to review
the evolved thresholds and return structured strategic advice:
  - threshold_assessment  : whether each gene looks sensible
  - blind_spots           : potential attack vectors the thresholds may miss
  - recommended_tuning    : gene-level suggestions (string)
  - adaptation_rating     : score 0–10 for how well Mahoraga adapted
  - reasoning             : brief free-text explanation

The LLM output is attached as ``llm_insight`` in the ``evolve()`` result.
It is purely advisory — the deterministic GA result is never changed by it.

Genome (chromosome)
-------------------
Index  Name                          Default      Bounds
  0    ddos_pps_threshold             500        [50, 2 000]
  1    ddos_syn_threshold             300        [20, 1 000]
  2    port_scan_unique_ip_thresh      20        [2, 100]
  3    port_scan_entropy_threshold      3.5      [1.0, 6.0]
  4    exfil_bps_threshold         500 000       [10 000, 2 000 000]
  5    confidence_threshold             0.60     [0.30, 0.90]

Fitness
-------
    fitness = (TP + TN) / (TP + TN + 2·FP + FN + ε)

FP penalised 2× because blocking legitimate traffic is worse than missing a
threat.  Score is in [0, 1]; higher is better.
"""

import json
import logging
import os
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from deap import algorithms, base, creator, tools as deap_tools
    _DEAP_AVAILABLE = True
except ImportError:
    _DEAP_AVAILABLE = False

try:
    from .llm_client import LLMClient
except Exception:
    LLMClient = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Gene layout
# ---------------------------------------------------------------------------
GENE_NAMES: List[str] = [
    "ddos_pps_threshold",           # 0  packets/sec
    "ddos_syn_threshold",           # 1  SYN packets in window
    "port_scan_unique_ip_thresh",   # 2  unique dest IPs
    "port_scan_entropy_threshold",  # 3  Shannon entropy of dest ports
    "exfil_bps_threshold",          # 4  bytes/sec
    "confidence_threshold",         # 5  Scout report confidence gate [0–1]
]

GENE_BOUNDS: List[Tuple[float, float]] = [
    (50.0,      2_000.0),
    (20.0,      1_000.0),
    (2.0,       100.0),
    (1.0,       6.0),
    (10_000.0,  2_000_000.0),
    (0.30,      0.90),
]

DEFAULT_GENOME: List[float] = [500.0, 300.0, 20.0, 3.5, 500_000.0, 0.60]

MUT_SIGMA: List[float] = [80.0, 40.0, 4.0, 0.25, 40_000.0, 0.04]

# DEAP hyper-parameters
POP_SIZE      = 30
N_GENERATIONS = 20
CXPB          = 0.70
MUTPB         = 0.30
INDPB         = 0.30
TOURNAMENT_K  = 3

# Storage
_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", "..", ".."))

# Runtime artifacts live under swarmshield/runtime/ (kept out of git).
RUNTIME_DIR = os.path.join(PROJECT_ROOT, "swarmshield", "runtime")
OUTCOMES_FILE = os.path.join(RUNTIME_DIR, "mahoraga_outcomes.jsonl")
BEST_GENOME_FILE = os.path.join(RUNTIME_DIR, "mahoraga_best_strategy.json")


# ===========================================================================
# Synthetic fallback scenarios  (used on day one, before real data exists)
# ===========================================================================

_SYNTHETIC_SCENARIOS: List[Dict[str, Any]] = [
    # DDoS
    {"stats": {"packets_per_second": 800,  "bytes_per_second": 400_000,   "unique_dest_ips": 3,  "syn_count": 500, "port_entropy": 0.8, "window_seconds": 10}, "was_threat": True,  "attack_type": "DDoS"},
    {"stats": {"packets_per_second": 1200, "bytes_per_second": 600_000,   "unique_dest_ips": 2,  "syn_count": 800, "port_entropy": 0.5, "window_seconds": 10}, "was_threat": True,  "attack_type": "DDoS"},
    {"stats": {"packets_per_second": 600,  "bytes_per_second": 300_000,   "unique_dest_ips": 1,  "syn_count": 400, "port_entropy": 0.3, "window_seconds": 10}, "was_threat": True,  "attack_type": "DDoS"},
    # PortScan
    {"stats": {"packets_per_second": 80,   "bytes_per_second": 8_000,     "unique_dest_ips": 35, "syn_count": 35,  "port_entropy": 4.5, "window_seconds": 10}, "was_threat": True,  "attack_type": "PortScan"},
    {"stats": {"packets_per_second": 120,  "bytes_per_second": 12_000,    "unique_dest_ips": 50, "syn_count": 50,  "port_entropy": 5.1, "window_seconds": 10}, "was_threat": True,  "attack_type": "PortScan"},
    {"stats": {"packets_per_second": 60,   "bytes_per_second": 6_000,     "unique_dest_ips": 28, "syn_count": 28,  "port_entropy": 4.2, "window_seconds": 10}, "was_threat": True,  "attack_type": "PortScan"},
    # Exfiltration
    {"stats": {"packets_per_second": 30,   "bytes_per_second": 800_000,   "unique_dest_ips": 2,  "syn_count": 5,   "port_entropy": 0.5, "window_seconds": 10}, "was_threat": True,  "attack_type": "Exfiltration"},
    {"stats": {"packets_per_second": 20,   "bytes_per_second": 1_200_000, "unique_dest_ips": 1,  "syn_count": 2,   "port_entropy": 0.3, "window_seconds": 10}, "was_threat": True,  "attack_type": "Exfiltration"},
    # Normal
    {"stats": {"packets_per_second": 30,   "bytes_per_second": 15_000,    "unique_dest_ips": 5,  "syn_count": 10,  "port_entropy": 1.8, "window_seconds": 10}, "was_threat": False, "attack_type": "Normal"},
    {"stats": {"packets_per_second": 60,   "bytes_per_second": 30_000,    "unique_dest_ips": 8,  "syn_count": 20,  "port_entropy": 2.2, "window_seconds": 10}, "was_threat": False, "attack_type": "Normal"},
    {"stats": {"packets_per_second": 15,   "bytes_per_second": 5_000,     "unique_dest_ips": 3,  "syn_count": 4,   "port_entropy": 1.2, "window_seconds": 10}, "was_threat": False, "attack_type": "Normal"},
    {"stats": {"packets_per_second": 45,   "bytes_per_second": 22_000,    "unique_dest_ips": 6,  "syn_count": 12,  "port_entropy": 2.0, "window_seconds": 10}, "was_threat": False, "attack_type": "Normal"},
]


# ===========================================================================
# LLM prompts
# ===========================================================================

_MAHORAGA_SYSTEM_PROMPT = """
You are a cybersecurity AI advisor reviewing evolved network-defense thresholds
produced by a genetic algorithm (Mahoraga / SwarmShield).

Your task is to assess whether the evolved genome looks operationally sound and
flag potential issues.

IMPORTANT RULES:
- Respond ONLY with a valid JSON object — no prose, no markdown.
- Base your assessment STRICTLY on the numbers provided; do NOT invent data.
- Never suggest changing the GA fitness function or the GA itself.
- The computed fitness value is GROUND TRUTH; do not question it.

Required JSON keys:
{
  "threshold_assessment": {
    "ddos_pps_threshold":          "ok | too_low | too_high | note",
    "ddos_syn_threshold":          "ok | too_low | too_high | note",
    "port_scan_unique_ip_thresh":  "ok | too_low | too_high | note",
    "port_scan_entropy_threshold": "ok | too_low | too_high | note",
    "exfil_bps_threshold":         "ok | too_low | too_high | note",
    "confidence_threshold":        "ok | too_low | too_high | note"
  },
  "blind_spots":        ["list of potential attack vectors the thresholds may miss"],
  "recommended_tuning": "one-sentence actionable suggestion for the next evolution cycle",
  "adaptation_rating":  <integer 0-10, where 10 = perfectly adapted>,
  "reasoning":          "two-sentence plain-English explanation"
}
""".strip()


def _build_mahoraga_user_message(
    best_thresholds:    Dict[str, float],
    confidence_gate:    float,
    best_fitness:       float,
    n_outcomes:         int,
    generations_run:    int,
    prev_fitness:       Optional[float],
) -> str:
    delta = ""
    if prev_fitness is not None:
        delta = f"\nPrevious best fitness: {prev_fitness:.4f}  (delta = {best_fitness - prev_fitness:+.4f})"

    lines = [
        "Evolved threshold set produced by Mahoraga genetic algorithm:",
        "",
        f"  ddos_pps_threshold:          {best_thresholds.get('ddos_pps_threshold', 0):.1f}  (bounds 50–2000)",
        f"  ddos_syn_threshold:          {best_thresholds.get('ddos_syn_threshold', 0):.1f}  (bounds 20–1000)",
        f"  port_scan_unique_ip_thresh:  {best_thresholds.get('port_scan_unique_ip_thresh', 0):.1f}  (bounds 2–100)",
        f"  port_scan_entropy_threshold: {best_thresholds.get('port_scan_entropy_threshold', 0):.2f}  (bounds 1.0–6.0)",
        f"  exfil_bps_threshold:         {best_thresholds.get('exfil_bps_threshold', 0):.0f}  (bounds 10000–2000000)",
        f"  confidence_threshold (gate): {confidence_gate:.2f}  (bounds 0.30–0.90)",
        "",
        f"Fitness (higher is better, range 0–1): {best_fitness:.4f}{delta}",
        f"Outcomes used for evolution: {n_outcomes}",
        f"Generations run: {generations_run}",
        "",
        "Assess the threshold set and return the required JSON.",
    ]
    return "\n".join(lines)


def _ask_llm_for_insight(
    llm_client:       Any,
    best_thresholds:  Dict[str, float],
    confidence_gate:  float,
    best_fitness:     float,
    n_outcomes:       int,
    generations_run:  int,
    prev_fitness:     Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """
    Call Grok to get structured strategic advice on the evolved genome.
    Returns None if LLM is unavailable or the call fails.
    """
    if llm_client is None or not llm_client.available:
        return None
    user_msg = _build_mahoraga_user_message(
        best_thresholds, confidence_gate, best_fitness,
        n_outcomes, generations_run, prev_fitness,
    )
    return llm_client.complete(_MAHORAGA_SYSTEM_PROMPT, user_msg)


# ===========================================================================
# Internal helpers
# ===========================================================================

def _genome_to_thresholds(genome: List[float]) -> Dict[str, float]:
    return {name: float(genome[i]) for i, name in enumerate(GENE_NAMES[:-1])}


def _confidence_from_genome(genome: List[float]) -> float:
    return float(genome[len(GENE_NAMES) - 1])


def _clamp_genome(genome: List[float]) -> None:
    for i, (lo, hi) in enumerate(GENE_BOUNDS):
        genome[i] = max(lo, min(hi, genome[i]))


def _evaluate_genome(
    genome:   List[float],
    outcomes: List[Dict[str, Any]],
) -> Tuple[float]:
    """
    DEAP fitness function.
    fitness = (TP + TN) / (TP + TN + 2·FP + FN + ε)
    """
    from .scout import ScoutAgent   # local import — avoids circular dep at module load

    thresholds = _genome_to_thresholds(genome)
    conf_gate  = _confidence_from_genome(genome)
    tp = fn = tn = fp = 0

    for o in outcomes:
        stats = o.get("stats")
        if not stats:
            continue
        mc       = ScoutAgent.monte_carlo_estimate(stats, thresholds=thresholds)
        detected = (mc["top_confidence"] > conf_gate) and (mc["top_threat"] != "normal")
        was_real = bool(o.get("was_threat", False))

        if was_real and detected:
            tp += 1
        elif was_real and not detected:
            fn += 1
        elif not was_real and not detected:
            tn += 1
        else:
            fp += 1

    return ((tp + tn) / (tp + tn + 2 * fp + fn + 1e-9),)


# ===========================================================================
# DEAP setup
# ===========================================================================

def _setup_deap() -> Optional[Any]:
    if not _DEAP_AVAILABLE:
        return None
    if not hasattr(creator, "MaharagaFitness"):
        creator.create("MaharagaFitness", base.Fitness, weights=(1.0,))
    if not hasattr(creator, "MaharagaIndividual"):
        creator.create("MaharagaIndividual", list, fitness=creator.MaharagaFitness)

    tb = base.Toolbox()

    def _rand_ind():
        return creator.MaharagaIndividual(
            random.uniform(lo, hi) for lo, hi in GENE_BOUNDS
        )

    tb.register("individual", deap_tools.initIterate, creator.MaharagaIndividual, _rand_ind)
    tb.register("population", deap_tools.initRepeat,  list, tb.individual)
    tb.register("mate",   deap_tools.cxBlend, alpha=0.5)
    tb.register("mutate", deap_tools.mutGaussian,
                mu=[0] * len(GENE_NAMES), sigma=MUT_SIGMA, indpb=INDPB)
    tb.register("select", deap_tools.selTournament, tournsize=TOURNAMENT_K)
    return tb


_TOOLBOX = _setup_deap()


# ===========================================================================
# Mahoraga
# ===========================================================================

class Mahoraga:
    """
    Mahoraga — Adaptive Defense Strategy Evolver.

    Named after the Divine General Mahoraga (Jujutsu Kaisen):
    the being that adapts to every technique.

    Lifecycle
    ---------
    1. Each defense cycle:  record_outcome(...)
    2. Periodically:        evolve()    → runs GA, saves best genome
    3. After evolution:     apply_to_agents(scout_agent)  → pushes thresholds live

    LLM enrichment
    --------------
    Pass an initialised LLMClient to get structured strategic advice attached
    as ``llm_insight`` in the dict returned by ``evolve()``.
    Agents degrade gracefully when no LLM key is configured.
    """

    name: str = "Mahoraga"

    def __init__(
        self,
        outcomes_file:    str = OUTCOMES_FILE,
        best_genome_file: str = BEST_GENOME_FILE,
        pop_size:         int = POP_SIZE,
        n_generations:    int = N_GENERATIONS,
        llm_client:       Optional["LLMClient"] = None,
    ) -> None:
        self.outcomes_file    = outcomes_file
        self.best_genome_file = best_genome_file
        self.pop_size         = pop_size
        self.n_generations    = n_generations
        self._llm_client      = llm_client
        self.logger           = logging.getLogger(f"{__name__}.Mahoraga")
        self._toolbox         = _TOOLBOX

        if not _DEAP_AVAILABLE:
            self.logger.warning(
                "DEAP not installed — evolution disabled. "
                "Install with: pip install 'deap==1.4.3'"
            )
        if llm_client and llm_client.available:
            self.logger.info("Mahoraga: LLM enrichment enabled (Grok).")

    # ------------------------------------------------------------------
    # Outcome recording
    # ------------------------------------------------------------------

    def record_outcome(
        self,
        source_ip:           str,
        stats:               Dict[str, Any],
        attack_type:         str,
        confidence:          float,
        action_taken:        str,
        enforcement_success: bool = True,
    ) -> None:
        """
        Append one defense-cycle observation to ``mahoraga_outcomes.jsonl``.

        ``was_threat`` is inferred:
          block / redirect_to_honeypot / quarantine  →  True
          monitor                                     →  False
        """
        was_threat = action_taken in ("block", "redirect_to_honeypot", "quarantine")
        record: Dict[str, Any] = {
            "timestamp":           datetime.now(timezone.utc).isoformat(),
            "source_ip":           source_ip,
            "stats":               stats,
            "attack_type":         attack_type,
            "original_confidence": confidence,
            "action_taken":        action_taken,
            "enforcement_success": enforcement_success,
            "was_threat":          was_threat,
        }
        try:
            os.makedirs(os.path.dirname(self.outcomes_file), exist_ok=True)
            with open(self.outcomes_file, "a") as fh:
                fh.write(json.dumps(record) + "\n")
            self.logger.debug(
                "Recorded outcome: %s → %s (was_threat=%s)",
                source_ip, action_taken, was_threat,
            )
        except OSError as exc:
            self.logger.error("Could not write outcome: %s", exc)

    # ------------------------------------------------------------------
    # Outcome loading
    # ------------------------------------------------------------------

    def load_outcomes(self) -> List[Dict[str, Any]]:
        """Load all recorded outcomes from disk. Returns [] if file missing."""
        if not os.path.exists(self.outcomes_file):
            return []
        records: List[Dict[str, Any]] = []
        try:
            with open(self.outcomes_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError as exc:
            self.logger.error("Could not read outcomes: %s", exc)
        return records

    # ------------------------------------------------------------------
    # Fitness evaluation
    # ------------------------------------------------------------------

    def evaluate_genome(
        self,
        genome:   List[float],
        outcomes: Optional[List[Dict[str, Any]]] = None,
    ) -> float:
        """Evaluate a genome against outcomes (or synthetic if none). Returns [0,1]."""
        if outcomes is None:
            outcomes = self.load_outcomes()
        if not outcomes:
            outcomes = list(_SYNTHETIC_SCENARIOS)
        return _evaluate_genome(genome, outcomes)[0]

    # ------------------------------------------------------------------
    # Population helpers
    # ------------------------------------------------------------------

    def create_population(
        self,
        size:          Optional[int] = None,
        seed_defaults: bool = True,
    ) -> List[Any]:
        """
        Create an initial DEAP population.
        Individual[0] is seeded from DEFAULT_GENOME when ``seed_defaults=True``.
        """
        n = size or self.pop_size
        if not _DEAP_AVAILABLE or self._toolbox is None:
            pop = []
            for i in range(n):
                g = list(DEFAULT_GENOME) if (i == 0 and seed_defaults) \
                    else [random.uniform(lo, hi) for lo, hi in GENE_BOUNDS]
                pop.append(g)
            return pop
        pop = self._toolbox.population(n=n)
        if seed_defaults and pop:
            for i, val in enumerate(DEFAULT_GENOME):
                pop[0][i] = val
        return pop

    # ------------------------------------------------------------------
    # Core: run the genetic algorithm
    # ------------------------------------------------------------------

    def evolve(
        self,
        outcomes: Optional[List[Dict[str, Any]]] = None,
        verbose:  bool = False,
    ) -> Dict[str, Any]:
        """
        Run the DEAP genetic algorithm and return the best-found strategy.

        Falls back to DEFAULT_GENOME if DEAP is unavailable.
        Uses synthetic scenarios if no real outcomes are recorded yet.

        The returned dict always includes:
          best_genome, best_thresholds, confidence_threshold,
          best_fitness, generations_run, population_size,
          outcomes_used, timestamp

        If an LLMClient was provided and is available, the dict also contains:
          llm_insight  — structured strategic advice from Grok (or None)
        """
        if not _DEAP_AVAILABLE or self._toolbox is None:
            self.logger.warning("DEAP unavailable — returning DEFAULT_GENOME.")
            return self._default_result(len(outcomes or []))

        if outcomes is None:
            outcomes = self.load_outcomes()
        if not outcomes:
            self.logger.info("No recorded outcomes — using synthetic fallback.")
            outcomes = list(_SYNTHETIC_SCENARIOS)

        n_outcomes = len(outcomes)
        self.logger.info(
            "Mahoraga evolving — pop=%d  gen=%d  outcomes=%d",
            self.pop_size, self.n_generations, n_outcomes,
        )

        # Remember previous best fitness for LLM delta reporting
        prev_fitness: Optional[float] = None
        prev = self.get_best_strategy()
        if prev:
            prev_fitness = prev.get("best_fitness")

        self._toolbox.register("evaluate", _evaluate_genome, outcomes=outcomes)

        population = self.create_population(size=self.pop_size, seed_defaults=True)
        for ind, fit in zip(population, map(self._toolbox.evaluate, population)):
            ind.fitness.values = fit

        stats_tracker = deap_tools.Statistics(lambda ind: ind.fitness.values[0])
        stats_tracker.register("avg",  lambda x: round(sum(x) / len(x), 4))
        stats_tracker.register("best", max)
        hof = deap_tools.HallOfFame(1)

        _, logbook = algorithms.eaSimple(
            population, self._toolbox,
            cxpb=CXPB, mutpb=MUTPB,
            ngen=self.n_generations,
            stats=stats_tracker,
            halloffame=hof,
            verbose=verbose,
        )

        if verbose:
            for rec in logbook:
                self.logger.info(
                    "Gen %02d | avg=%.4f | best=%.4f",
                    rec["gen"], rec["avg"], rec["best"],
                )

        best = list(hof[0])
        _clamp_genome(best)

        result: Dict[str, Any] = {
            "best_genome":          best,
            "best_thresholds":      _genome_to_thresholds(best),
            "confidence_threshold": _confidence_from_genome(best),
            "best_fitness":         round(hof[0].fitness.values[0], 4),
            "generations_run":      self.n_generations,
            "population_size":      self.pop_size,
            "outcomes_used":        n_outcomes,
            "timestamp":            datetime.now(timezone.utc).isoformat(),
        }

        # ---- LLM enrichment ------------------------------------------------
        result["llm_insight"] = _ask_llm_for_insight(
            llm_client      = self._llm_client,
            best_thresholds = result["best_thresholds"],
            confidence_gate = result["confidence_threshold"],
            best_fitness    = result["best_fitness"],
            n_outcomes      = n_outcomes,
            generations_run = self.n_generations,
            prev_fitness    = prev_fitness,
        )
        if result["llm_insight"]:
            self.logger.info(
                "LLM insight received — adaptation_rating=%s",
                result["llm_insight"].get("adaptation_rating", "?"),
            )

        self._save_best(result)
        self.logger.info(
            "Evolution complete — fitness=%.4f | thresholds=%s",
            result["best_fitness"],
            {k: round(v, 2) for k, v in result["best_thresholds"].items()},
        )
        try:
            from ..utils.message_bus import get_bus, TOPIC_MAHORAGA_EVOLVED
            get_bus().publish(TOPIC_MAHORAGA_EVOLVED, {
                "best_fitness":         result["best_fitness"],
                "best_thresholds":      result["best_thresholds"],
                "confidence_threshold": result["confidence_threshold"],
                "outcomes_used":        result["outcomes_used"],
                "generations_run":      result["generations_run"],
                "timestamp":            result["timestamp"],
            })
        except Exception:  # noqa: BLE001
            pass
        return result

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_best(self, result: Dict[str, Any]) -> None:
        try:
            os.makedirs(os.path.dirname(self.best_genome_file), exist_ok=True)
            with open(self.best_genome_file, "w") as fh:
                json.dump(result, fh, indent=2)
            self.logger.info("Best strategy saved → %s", self.best_genome_file)
        except OSError as exc:
            self.logger.error("Could not save best strategy: %s", exc)

    def get_best_strategy(self) -> Optional[Dict[str, Any]]:
        """Load the most recently saved best strategy, or None."""
        if not os.path.exists(self.best_genome_file):
            return None
        try:
            with open(self.best_genome_file) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.error("Could not load best strategy: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Pipeline integration
    # ------------------------------------------------------------------

    def apply_to_agents(
        self,
        scout_agent:    Any,
        analyzer_agent: Any = None,
    ) -> bool:
        """
        Push the best-evolved thresholds into a live ScoutAgent.
        Returns True if thresholds were applied, False if none saved yet.
        """
        strategy = self.get_best_strategy()
        if not strategy:
            self.logger.warning("No best strategy saved yet — Scout keeps defaults.")
            return False
        scout_agent.thresholds = strategy["best_thresholds"]
        self.logger.info(
            "Applied evolved thresholds to %s: %s",
            getattr(scout_agent, "name", "Scout"),
            {k: round(v, 2) for k, v in strategy["best_thresholds"].items()},
        )
        return True

    # ------------------------------------------------------------------
    # Backwards-compatibility shims
    # ------------------------------------------------------------------

    def evaluate_fitness(self, strategy: Dict[str, Any]) -> float:
        """Evaluate a thresholds-dict genome. Returns fitness in [0, 1]."""
        genome = [
            strategy.get(name, DEFAULT_GENOME[i])
            for i, name in enumerate(GENE_NAMES)
        ]
        return self.evaluate_genome(genome)

    def create_population_legacy(self) -> List[Dict[str, Any]]:
        return [_genome_to_thresholds(ind) for ind in self.create_population()]

    def evolve_strategies(self, outcomes: List[Dict]) -> List[Dict[str, Any]]:
        return [self.evolve(outcomes=outcomes)]

    # ------------------------------------------------------------------

    def _default_result(self, n_outcomes: int) -> Dict[str, Any]:
        return {
            "best_genome":          list(DEFAULT_GENOME),
            "best_thresholds":      _genome_to_thresholds(DEFAULT_GENOME),
            "confidence_threshold": DEFAULT_GENOME[-1],
            "best_fitness":         0.0,
            "generations_run":      0,
            "population_size":      0,
            "outcomes_used":        n_outcomes,
            "timestamp":            datetime.now(timezone.utc).isoformat(),
            "llm_insight":          None,
        }


# ---------------------------------------------------------------------------
# Backwards-compatibility alias
# ---------------------------------------------------------------------------
EvolverAgent = Mahoraga
