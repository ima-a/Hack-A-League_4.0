"""
monte_carlo.py
--------------
Monte Carlo threat estimation engine for the SwarmShield Scout Agent.

How It Works
------------
1.  Accepts a :class:`~traffic_stats.TrafficSnapshot` (or equivalent dict).
2.  Maps each anomaly sub-score from the snapshot onto a probability
    distribution for each known attack pattern defined in attack_patterns.md.
3.  Runs ``n_simulations`` Monte Carlo trials by sampling from those
    distributions and aggregating weighted impact scores.
4.  Returns a :class:`ThreatEstimate` containing:
    - per-attack probabilities and sampled severity ranges,
    - a combined ``overall_risk`` score (0 → 1),
    - the derived ``threat_level`` string (LOW / MEDIUM / HIGH / CRITICAL).

Design Principles
-----------------
- Fully deterministic when ``seed`` is provided (for reproducibility in tests).
- No external ML dependencies — uses only ``random`` and ``statistics`` from
  the standard library so it runs anywhere without installs.
- All weight constants are exposed as class attributes so the Flask config
  endpoint can update them at runtime without a restart.
"""

from __future__ import annotations

import logging
import math
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Attack pattern registry
# ---------------------------------------------------------------------------

@dataclass
class AttackPattern:
    """
    One entry in the Monte Carlo pattern registry.

    Attributes
    ----------
    name : str
        Human-readable attack name (matches attack_patterns.md).
    base_severity : float
        Base severity weight in [0, 1] from the pattern catalogue.
    propagation : float
        Propagation potential in [0, 1] (higher = more dangerous laterally).
    stat_key : str
        The field name in the snapshot dict that acts as the primary evidence
        indicator for this pattern.
    stat_multiplier : float
        Scales the raw stat value into a [0, 1] evidence probability.
        evidence_prob = min(1.0, snapshot[stat_key] * stat_multiplier)
    secondary_key : str, optional
        An additional evidence field that augments the estimate.
    secondary_weight : float
        Weight (0..1) blended with primary evidence.
    """

    name: str
    base_severity: float
    propagation: float
    stat_key: str
    stat_multiplier: float = 1.0
    secondary_key: str = ""
    secondary_weight: float = 0.0


# Default pattern registry — mirrors attack_patterns.md
DEFAULT_PATTERNS: List[AttackPattern] = [
    AttackPattern(
        name="SYN Flood",
        base_severity=0.85,
        propagation=0.15,
        stat_key="syn_flood_score",
        stat_multiplier=1.0,
        secondary_key="pkt_rate",
        secondary_weight=0.2,
    ),
    AttackPattern(
        name="Port Scan",
        base_severity=0.45,
        propagation=0.50,
        stat_key="port_scan_score",
        stat_multiplier=1.0,
    ),
    AttackPattern(
        name="Brute Force",
        base_severity=0.70,
        propagation=0.65,
        stat_key="pkt_rate",
        stat_multiplier=0.002,       # normalise: 500 pps → 1.0
        secondary_key="unique_src_ips",
        secondary_weight=0.15,
    ),
    AttackPattern(
        name="DNS Amplification",
        base_severity=0.80,
        propagation=0.20,
        stat_key="dns_amp_indicator",
        stat_multiplier=1.0,
    ),
    AttackPattern(
        name="ARP Spoofing",
        base_severity=0.75,
        propagation=0.70,
        stat_key="arp_spoof_score",
        stat_multiplier=1.0,
    ),
    AttackPattern(
        name="ICMP Flood",
        base_severity=0.60,
        propagation=0.15,
        stat_key="icmp_rate",
        stat_multiplier=0.001,       # normalise: 1000 pps → 1.0
    ),
    AttackPattern(
        name="UDP Flood",
        base_severity=0.72,
        propagation=0.15,
        stat_key="port_spread",
        stat_multiplier=0.01,        # normalise: 100 unique ports → 1.0
        secondary_key="pkt_rate",
        secondary_weight=0.25,
    ),
    AttackPattern(
        name="C2 Beacon",
        base_severity=0.95,
        propagation=0.90,
        stat_key="unique_src_ips",
        stat_multiplier=0.05,        # very low raw score but high weight
        secondary_key="byte_rate",
        secondary_weight=0.1,
    ),
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AttackEstimate:
    """Simulation result for a single attack pattern."""
    name: str
    evidence_probability: float      # 0..1  — how likely this attack is occurring
    mean_severity: float             # averaged across simulations
    std_severity: float              # spread of severity samples
    min_severity: float
    max_severity: float
    propagation: float               # from pattern definition
    risk_contribution: float         # evidence * mean_severity * propagation_factor

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "evidence_probability": round(self.evidence_probability, 4),
            "mean_severity": round(self.mean_severity, 4),
            "std_severity": round(self.std_severity, 4),
            "severity_range": [round(self.min_severity, 4), round(self.max_severity, 4)],
            "propagation": round(self.propagation, 4),
            "risk_contribution": round(self.risk_contribution, 4),
        }


@dataclass
class ThreatEstimate:
    """Aggregated Monte Carlo output for one snapshot."""
    timestamp: float
    n_simulations: int
    attack_estimates: List[AttackEstimate] = field(default_factory=list)

    overall_risk: float = 0.0         # 0..1
    threat_level: str = "LOW"
    top_threat: str = "None"
    confidence: float = 0.0           # internal agreement (1 - normalised std)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "n_simulations": self.n_simulations,
            "overall_risk": round(self.overall_risk, 4),
            "threat_level": self.threat_level,
            "top_threat": self.top_threat,
            "confidence": round(self.confidence, 4),
            "attack_estimates": [a.to_dict() for a in self.attack_estimates],
        }


# ---------------------------------------------------------------------------
# Monte Carlo engine
# ---------------------------------------------------------------------------

_THREAT_THRESHOLDS = [
    (0.76, "CRITICAL"),
    (0.56, "HIGH"),
    (0.31, "MEDIUM"),
    (0.00, "LOW"),
]


def _classify_risk(score: float) -> str:
    for threshold, label in _THREAT_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


class MonteCarloEstimator:
    """
    Monte Carlo threat estimator.

    Parameters
    ----------
    n_simulations : int
        Number of Monte Carlo trials per snapshot (default 500).
        Higher values give tighter confidence intervals at the cost of CPU.
    patterns : list[AttackPattern], optional
        Custom attack pattern registry.  Defaults to :data:`DEFAULT_PATTERNS`.
    seed : int, optional
        Random seed for reproducible runs (useful in tests).
    pkt_rate_norm : float
        Normalisation divisor for pkt_rate evidence — packets/s at which
        pkt_rate evidence reaches 1.0.

    Usage
    -----
    ::

        estimator = MonteCarloEstimator(n_simulations=500)
        threat = estimator.estimate(snapshot.to_dict())
        print(threat.threat_level, threat.overall_risk)
    """

    def __init__(
        self,
        n_simulations: int = 500,
        patterns: Optional[List[AttackPattern]] = None,
        seed: Optional[int] = None,
        pkt_rate_norm: float = 500.0,
    ) -> None:
        self.n_simulations = n_simulations
        self.patterns = patterns if patterns is not None else list(DEFAULT_PATTERNS)
        self.pkt_rate_norm = pkt_rate_norm
        self._rng = random.Random(seed)

        logger.info(
            "MonteCarloEstimator initialised — n=%d  patterns=%d  seed=%s",
            n_simulations,
            len(self.patterns),
            seed,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def estimate(self, snapshot: dict) -> ThreatEstimate:
        """
        Run Monte Carlo simulations against *snapshot* and return a
        :class:`ThreatEstimate`.

        Parameters
        ----------
        snapshot : dict
            Output of :meth:`~traffic_stats.TrafficSnapshot.to_dict`.
            Required keys vary by pattern; missing keys default to 0.
        """
        t0 = time.monotonic()
        result = ThreatEstimate(
            timestamp=snapshot.get("timestamp", time.time()),
            n_simulations=self.n_simulations,
        )

        risk_scores: List[float] = []

        for pattern in self.patterns:
            estimate = self._simulate_pattern(pattern, snapshot)
            result.attack_estimates.append(estimate)
            risk_scores.append(estimate.risk_contribution)

        # Overall risk: weighted combination (propagation-weighted mean)
        if risk_scores:
            result.overall_risk = min(1.0, sum(risk_scores) / max(len(risk_scores), 1))
        else:
            result.overall_risk = 0.0

        result.threat_level = _classify_risk(result.overall_risk)

        # Top threat
        if result.attack_estimates:
            top = max(result.attack_estimates, key=lambda a: a.risk_contribution)
            result.top_threat = top.name if top.risk_contribution > 0.05 else "None"

        # Confidence: 1 - coefficient_of_variation
        if len(risk_scores) > 1 and statistics.mean(risk_scores) > 0:
            cv = statistics.stdev(risk_scores) / statistics.mean(risk_scores)
            result.confidence = max(0.0, min(1.0, 1.0 - cv))
        else:
            result.confidence = 1.0

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug(
            "MC estimate done in %.1f ms — risk=%.3f  level=%s  top=%s",
            elapsed_ms,
            result.overall_risk,
            result.threat_level,
            result.top_threat,
        )
        return result

    def update_pattern(self, name: str, **kwargs) -> bool:
        """
        Update a pattern's attributes at runtime (e.g. from Flask config endpoint).

        Returns True if the pattern was found and updated, False otherwise.
        """
        for pattern in self.patterns:
            if pattern.name == name:
                for k, v in kwargs.items():
                    if hasattr(pattern, k):
                        setattr(pattern, k, v)
                        logger.info("Pattern '%s' → %s = %s", name, k, v)
                return True
        return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_evidence(self, pattern: AttackPattern, snap: dict) -> float:
        """
        Derive a primary evidence probability in [0, 1] from the snapshot.
        """
        raw = snap.get(pattern.stat_key, 0.0)

        # Special normalisation for pkt_rate
        if pattern.stat_key == "pkt_rate":
            raw = raw / self.pkt_rate_norm

        primary = min(1.0, float(raw) * pattern.stat_multiplier)

        if pattern.secondary_key:
            sec_raw = snap.get(pattern.secondary_key, 0.0)
            if pattern.secondary_key == "pkt_rate":
                sec_raw = sec_raw / self.pkt_rate_norm
            secondary = min(1.0, float(sec_raw) * pattern.stat_multiplier)
            evidence = (
                primary * (1 - pattern.secondary_weight)
                + secondary * pattern.secondary_weight
            )
        else:
            evidence = primary

        return max(0.0, min(1.0, evidence))

    def _simulate_pattern(
        self, pattern: AttackPattern, snap: dict
    ) -> AttackEstimate:
        """
        Run ``n_simulations`` trials for a single attack pattern.

        Each trial:
        1. Samples a boolean: is the attack present? (Bernoulli w/ p = evidence)
        2. If present, samples the severity from a Beta(α, β) distribution
           shaped around ``base_severity``.
        3. Accumulates severity scores.

        Returns an :class:`AttackEstimate`.
        """
        evidence = self._get_evidence(pattern, snap)

        # Beta distribution parameters shaped around base_severity
        # High base_severity → right-skewed → more severe outcomes
        alpha = max(1.0, pattern.base_severity * 8)
        beta_param = max(1.0, (1.0 - pattern.base_severity) * 8)

        severities: List[float] = []
        for _ in range(self.n_simulations):
            # Bernoulli draw: is attack active this trial?
            if self._rng.random() <= evidence:
                # Sample severity from Beta distribution
                sev = self._sample_beta(alpha, beta_param)
                # Add propagation as a multiplier for lateral risk
                sev = min(1.0, sev * (1.0 + pattern.propagation * 0.3))
                severities.append(sev)
            else:
                severities.append(0.0)

        non_zero = [s for s in severities if s > 0]
        mean_sev = statistics.mean(severities) if severities else 0.0
        std_sev = statistics.stdev(severities) if len(severities) > 1 else 0.0
        min_sev = min(non_zero) if non_zero else 0.0
        max_sev = max(non_zero) if non_zero else 0.0

        # Risk contribution: evidence × mean severity × propagation boost
        prop_boost = 1.0 + pattern.propagation * 0.5
        risk_contribution = min(1.0, evidence * mean_sev * prop_boost)

        return AttackEstimate(
            name=pattern.name,
            evidence_probability=evidence,
            mean_severity=mean_sev,
            std_severity=std_sev,
            min_severity=min_sev,
            max_severity=max_sev,
            propagation=pattern.propagation,
            risk_contribution=risk_contribution,
        )

    def _sample_beta(self, alpha: float, beta_param: float) -> float:
        """
        Sample from Beta(alpha, beta) using the standard library's
        :func:`random.betavariate`.
        """
        try:
            return self._rng.betavariate(alpha, beta_param)
        except ValueError:
            # Degenerate case (alpha or beta ~ 0) — fall back to uniform
            return self._rng.random()
