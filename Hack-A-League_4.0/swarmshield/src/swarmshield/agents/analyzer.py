import logging
import math
import random
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from .llm_client import LLMClient
except ImportError:
    LLMClient = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROPAGATION_BASE = 0.4   # base probability an attacker moves to a neighbour
N_SIM_TRIALS     = 500   # Monte Carlo trials for propagation simulation
RISK_HIGH        = 0.70
RISK_MEDIUM      = 0.40


# ===========================================================================
# LLM prompt engineering (Analyzer)
# ===========================================================================

_ANALYZER_SYSTEM_PROMPT = (
    "You are a threat correlation and attack-graph analysis assistant embedded in "
    "SwarmShield, an autonomous cybersecurity defense system.\n\n"
    "Your ONLY task: given pre-computed threat-graph data, Monte Carlo propagation "
    "results, and risk assessment outputs, return structured correlation intelligence "
    "in the exact JSON schema specified below.\n\n"
    "CRITICAL CONSTRAINTS — violation will cause system failures:\n"
    "1. All node counts, edge counts, confidence scores, spread metrics, and risk "
    "scores in the input are GROUND TRUTH from deterministic algorithms. "
    "Do NOT contradict them.\n"
    "2. Respond with valid JSON containing ONLY the OUTPUT SCHEMA fields. "
    "No prose, no extra keys.\n"
    "3. Use ONLY the enumerated values specified. No freeform choices.\n"
    "4. Do not invent IP addresses or threat types absent from the input.\n"
    "5. If avg_spread < 0.30 and risk_score < 0.40, lateral_movement_risk "
    "MUST NOT be 'high'.\n\n"
    "THREAT CORRELATION RULES — \"threat_correlation\" must be one of:\n"
    "  coordinated — two or more nodes share same threat_type "
    "AND both confidence >= 0.70\n"
    "  independent — nodes have different threat types OR large confidence gap\n"
    "  unclear     — single node, or insufficient data to determine\n\n"
    "VALID ACTIONS (for recommended_actions[*].action):\n"
    "  block                 — iptables DROP all traffic from source IP\n"
    "  rate_limit            — throttle source traffic\n"
    "  redirect_to_honeypot  — DNAT source to honeypot\n"
    "  quarantine            — FORWARD DROP both directions\n"
    "  monitor               — observe only, no enforcement\n"
    "  escalate              — requires human review\n\n"
    "LATERAL MOVEMENT RISK — apply these thresholds strictly:\n"
    "  high   — avg_spread >= 0.60 OR (risk_score >= 0.70 AND edge_count >= 2)\n"
    "  medium — avg_spread >= 0.30 OR risk_score >= 0.40\n"
    "  low    — avg_spread > 0.0  OR risk_score > 0.0\n"
    "  none   — avg_spread = 0.0  AND edge_count = 0\n\n"
    "OUTPUT SCHEMA — respond with ONLY this JSON object, no other text:\n"
    '{\n'
    '  "threat_correlation":    "<coordinated|independent|unclear>",\n'
    '  "attack_chain_summary":  "<1-2 sentence factual description>",\n'
    '  "lateral_movement_risk": "<high|medium|low|none>",\n'
    '  "escalation_needed":     <true|false>,\n'
    '  "containment_priority":  ["<ip>", ...],\n'
    '  "recommended_actions": [\n'
    '    { "ip": "<ip>", "action": "<action>", "reason": "<one sentence>" }\n'
    '  ]\n'
    '}'
)


def _build_analyzer_user_message(
    graph_summary: dict,
    top_threats:   list,
    sim_results:   list,
    assessment:    dict,
    agent_name:    str,
) -> str:
    """Build the grounded user message fed to the Analyzer LLM call."""
    import json as _json
    return (
        f"THREAT GRAPH ANALYSIS\n"
        f"agent: {agent_name}\n"
        f"\n"
        f"GRAPH SUMMARY (ground truth):\n"
        f"  node_count     : {graph_summary.get('node_count', 0)}\n"
        f"  edge_count     : {graph_summary.get('edge_count', 0)}\n"
        f"  attack_types   : {graph_summary.get('attack_types', [])}\n"
        f"  max_confidence : {graph_summary.get('max_confidence', 0.0):.4f}\n"
        f"\n"
        f"TOP THREATS (ground truth, sorted by confidence desc):\n"
        f"{_json.dumps(top_threats[:5], indent=2)}\n"
        f"\n"
        f"PROPAGATION SIMULATION (ground truth):\n"
        f"  trials_run : {len(sim_results)}\n"
        f"  avg_spread : {assessment.get('avg_spread', 0.0):.4f}\n"
        f"  max_spread : {assessment.get('max_spread', 0.0):.4f}\n"
        f"\n"
        f"RISK ASSESSMENT (ground truth):\n"
        f"  risk_level : {assessment.get('risk_level', 'none')}\n"
        f"  risk_score : {assessment.get('risk_score', 0.0):.4f}\n"
        f"\n"
        f"Provide threat correlation analysis and ranked containment recommendations."
    )


# ===========================================================================
# Internal helpers
# ===========================================================================

def _confidence_to_propagation(confidence: float) -> float:
    """
    Map threat confidence [0,1] → propagation probability [0,1].
    Higher confidence → higher chance the attacker moves laterally.
    """
    return min(1.0, PROPAGATION_BASE + confidence * 0.5)


def _build_nodes(observations: List[Dict]) -> List[Dict]:
    """
    Convert a list of Scout threat observations into graph nodes.

    Each node represents a unique source IP with aggregated threat type
    and maximum confidence across all observations from that IP.
    """
    ip_map: Dict[str, Dict] = {}
    for obs in observations:
        ip   = obs.get("source_ip", "unknown")
        conf = float(obs.get("confidence", 0.0))
        att  = obs.get("attack_type", "Unknown")
        mc   = obs.get("monte_carlo", {})

        if ip not in ip_map or conf > ip_map[ip]["confidence"]:
            ip_map[ip] = {
                "ip":          ip,
                "threat_type": att,
                "confidence":  conf,
                "monte_carlo": mc,
                "agent_id":    obs.get("agent_id", "unknown"),
                "timestamp":   obs.get("timestamp", ""),
            }

    return list(ip_map.values())


def _build_edges(nodes: List[Dict]) -> List[Dict]:
    """
    Infer attack-graph edges based on shared threat type and temporal proximity.

    Two nodes are connected if they share the same threat type AND both have
    confidence > 0.50 (suggesting a coordinated campaign).
    """
    edges = []
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            if (a["threat_type"] == b["threat_type"]
                    and a["confidence"] > 0.50
                    and b["confidence"] > 0.50):
                weight = round((a["confidence"] + b["confidence"]) / 2, 3)
                edges.append({
                    "src":         a["ip"],
                    "dst":         b["ip"],
                    "threat_type": a["threat_type"],
                    "weight":      weight,
                })
    return edges


def _graph_summary(nodes: List[Dict], edges: List[Dict]) -> Dict:
    """High-level summary stats for the threat graph."""
    if not nodes:
        return {"node_count": 0, "edge_count": 0, "attack_types": [], "max_confidence": 0.0}

    attack_types = sorted({n["threat_type"] for n in nodes})
    max_conf     = max(n["confidence"] for n in nodes)
    return {
        "node_count":    len(nodes),
        "edge_count":    len(edges),
        "attack_types":  attack_types,
        "max_confidence": round(max_conf, 4),
    }


def _run_propagation_simulation(
    nodes: List[Dict],
    edges: List[Dict],
    n_trials: int = N_SIM_TRIALS,
) -> List[Dict]:
    """
    Monte Carlo simulation of lateral movement through the attack graph.

    Each trial:
    1. Pick a random "entry" node (weighted by confidence).
    2. Attempt to propagate along edges using each edge's weight as a
       Bernoulli probability.
    3. Record which nodes were reached and the path length.

    Returns a list of per-trial result dicts.
    """
    if not nodes:
        return []

    # Build adjacency list for quick lookup
    adj: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
    for edge in edges:
        adj[edge["src"]].append((edge["dst"], edge["weight"]))
        adj[edge["dst"]].append((edge["src"], edge["weight"]))

    ip_list = [n["ip"] for n in nodes]
    conf_list = [n["confidence"] for n in nodes]

    # Weighted random entry-node selection helper
    def pick_entry() -> str:
        total = sum(conf_list) or len(ip_list)
        r = random.random() * total
        acc = 0.0
        for ip, w in zip(ip_list, conf_list):
            acc += w
            if r <= acc:
                return ip
        return ip_list[-1]

    results = []
    rng = random.Random()

    for trial in range(n_trials):
        entry  = pick_entry()
        visited = {entry}
        frontier = [entry]
        steps = 0

        while frontier:
            next_frontier = []
            for node in frontier:
                for (neighbour, weight) in adj.get(node, []):
                    if neighbour not in visited:
                        prop_prob = min(1.0, weight + rng.gauss(0, 0.05))
                        if rng.random() < prop_prob:
                            visited.add(neighbour)
                            next_frontier.append(neighbour)
            frontier = next_frontier
            steps += 1
            if steps > len(nodes):   # circuit breaker
                break

        results.append({
            "trial":           trial + 1,
            "entry_node":      entry,
            "nodes_reached":   len(visited),
            "path_length":     steps,
            "compromised_ips": sorted(visited),
        })

    return results


def _aggregate_risk(
    nodes: List[Dict],
    sim_results: List[Dict],
) -> Dict[str, Any]:
    """
    Aggregate Monte Carlo results into a risk-assessment report.

    Returns
    -------
    dict with keys:
        risk_level      : "high" | "medium" | "low" | "none"
        risk_score      : float [0, 1]
        avg_spread      : float   (avg fraction of nodes reached per trial)
        max_spread      : float
        top_threats     : list of dicts  (sorted by confidence desc)
        recommendations : list of str
        timestamp       : ISO-8601 string
    """
    if not nodes:
        return {
            "risk_level":      "none",
            "risk_score":      0.0,
            "avg_spread":      0.0,
            "max_spread":      0.0,
            "top_threats":     [],
            "recommendations": ["No threat observations to analyze."],
            "timestamp":       datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    total_nodes = max(len(nodes), 1)

    # Spread metrics from simulation
    if sim_results:
        spreads   = [r["nodes_reached"] / total_nodes for r in sim_results]
        avg_spread = sum(spreads) / len(spreads)
        max_spread = max(spreads)
    else:
        avg_spread = 0.0
        max_spread = 0.0

    # Risk score = weighted average of (confidence × propagation factor)
    max_conf = max(n["confidence"] for n in nodes)
    risk_score = round(
        min(1.0, max_conf * 0.6 + avg_spread * 0.4), 4
    )

    risk_level = (
        "high"   if risk_score >= RISK_HIGH   else
        "medium" if risk_score >= RISK_MEDIUM else
        "low"    if risk_score > 0.0          else
        "none"
    )

    # Top threats sorted by confidence
    top_threats = sorted(
        [{"ip": n["ip"], "threat_type": n["threat_type"], "confidence": n["confidence"]}
         for n in nodes],
        key=lambda x: x["confidence"],
        reverse=True,
    )

    # Recommendations
    recs = []
    for threat in top_threats:
        tt = threat["threat_type"].lower()
        ip = threat["ip"]
        c  = threat["confidence"]
        if "ddos" in tt and c >= 0.70:
            recs.append(f"Block {ip} immediately (DDoS confidence={c:.0%})")
        elif "portscan" in tt or "port_scan" in tt:
            recs.append(f"Redirect {ip} to honeypot (PortScan confidence={c:.0%})")
        elif "exfil" in tt:
            recs.append(f"Quarantine {ip} — data exfiltration detected (confidence={c:.0%})")
        elif c >= 0.50:
            recs.append(f"Monitor {ip} — elevated risk ({threat['threat_type']}, confidence={c:.0%})")
    if not recs:
        recs.append("No immediate action required.")

    return {
        "risk_level":      risk_level,
        "risk_score":      risk_score,
        "avg_spread":      round(avg_spread, 4),
        "max_spread":      round(max_spread, 4),
        "top_threats":     top_threats,
        "recommendations": recs,
        "timestamp":       datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _llm_enrich_risk(
    nodes:       List[dict],
    sim_results: list,
    assessment:  dict,
    agent_name:  str,
    llm_client,          # Optional[LLMClient]
) -> Optional[dict]:
    """
    Call the LLM to enrich a risk assessment with threat correlation intelligence.
    Returns None (silently) if the client is unavailable or the API call fails.
    """
    if llm_client is None or not llm_client.available:
        return None
    attack_types = sorted({n["threat_type"] for n in nodes})
    max_conf     = max((n["confidence"] for n in nodes), default=0.0)
    graph_summary = {
        "node_count":     len(nodes),
        "edge_count":     0,   # not in scope at assess_risk call site
        "attack_types":   attack_types,
        "max_confidence": round(max_conf, 4),
    }
    top_threats = assessment.get("top_threats", [])
    user_msg = _build_analyzer_user_message(
        graph_summary, top_threats, sim_results, assessment, agent_name,
    )
    return llm_client.complete(_ANALYZER_SYSTEM_PROMPT, user_msg)


# ===========================================================================
# AnalyzerAgent
# ===========================================================================

class AnalyzerAgent:
    """
    Threat Analysis Agent

    Responsibilities:
    - Build attack graphs from Scout observations (nodes = IPs, edges = lateral move paths)
    - Run Monte Carlo propagation simulations on the graph
    - Aggregate results into a structured risk assessment
    - Produce actionable recommendations for the Responder
    """

    def __init__(self, name: str = "Analyzer", llm_client=None):
        self.name        = name
        self.logger      = logging.getLogger(f"{__name__}.{name}")
        self._llm_client = llm_client   # Optional LLM enrichment layer

    def model_threat_graph(self, observations: List[Dict]) -> Dict[str, Any]:
        """
        Build a threat graph from a list of Scout threat observations.

        Parameters
        ----------
        observations : list of dict
            Each dict should contain at minimum:
            source_ip, attack_type, confidence, (optionally) monte_carlo,
            agent_id, timestamp.

        Returns
        -------
        dict
            {
              "nodes":   [ {ip, threat_type, confidence, ...}, ... ],
              "edges":   [ {src, dst, threat_type, weight}, ... ],
              "summary": {node_count, edge_count, attack_types, max_confidence}
            }
        """
        self.logger.info("Building threat graph from %d observation(s)…", len(observations))
        nodes   = _build_nodes(observations)
        edges   = _build_edges(nodes)
        summary = _graph_summary(nodes, edges)
        self.logger.info(
            "Graph: %d node(s), %d edge(s), max_conf=%.2f",
            summary["node_count"], summary["edge_count"], summary["max_confidence"],
        )
        return {"nodes": nodes, "edges": edges, "summary": summary}

    def simulate_attack(self, threat_graph: Dict) -> List[Dict[str, Any]]:
        """
        Run Monte Carlo lateral-movement simulations on *threat_graph*.

        Parameters
        ----------
        threat_graph : dict
            Output of model_threat_graph(), expected keys: nodes, edges.

        Returns
        -------
        list of dict
            One dict per simulation trial:
            {trial, entry_node, nodes_reached, path_length, compromised_ips}
        """
        nodes = threat_graph.get("nodes", [])
        edges = threat_graph.get("edges", [])
        self.logger.info(
            "Running %d simulation trials on %d node(s)…", N_SIM_TRIALS, len(nodes)
        )
        results = _run_propagation_simulation(nodes, edges)
        if results:
            avg_reached = sum(r["nodes_reached"] for r in results) / len(results)
            self.logger.info(
                "Simulation done — avg nodes reached per trial: %.2f / %d",
                avg_reached, len(nodes),
            )
        return results

    def assess_risk(self, simulation_results: List[Dict]) -> Dict[str, Any]:
        """
        Aggregate simulation results into a risk assessment.

        Parameters
        ----------
        simulation_results : list of dict
            Output of simulate_attack().

        Returns
        -------
        dict
            {risk_level, risk_score, avg_spread, max_spread,
             top_threats, recommendations, timestamp}

        Note: Because node metadata is needed for proper risk scoring, this
        method also accepts a dict with keys "nodes" and "simulation_results"
        if the caller wants to pass both together.
        """
        # Handle case where caller passes the full context dict
        if isinstance(simulation_results, dict):
            nodes = simulation_results.get("nodes", [])
            sims  = simulation_results.get("simulation_results", [])
        else:
            # simulation_results is a plain list — rebuild node list from
            # the compromised IPs seen across all trials
            sims  = simulation_results
            all_ips = {ip for r in sims for ip in r.get("compromised_ips", [])}
            nodes = [{"ip": ip, "threat_type": "Unknown", "confidence": 0.5}
                     for ip in all_ips]

        self.logger.info(
            "Assessing risk from %d trial(s), %d node(s)…", len(sims), len(nodes)
        )
        assessment = _aggregate_risk(nodes, sims)
        self.logger.info(
            "Risk assessment: level=%s, score=%.4f",
            assessment["risk_level"], assessment["risk_score"],
        )
        llm_insight = _llm_enrich_risk(
            nodes, sims, assessment, self.name, self._llm_client,
        )
        if llm_insight:
            assessment["llm_insight"] = llm_insight
            self.logger.info(
                "Risk assessment LLM insight: correlation=%s, lateral_risk=%s",
                llm_insight.get("threat_correlation", "?"),
                llm_insight.get("lateral_movement_risk", "?"),
            )
        try:
            from ..utils.message_bus import get_bus, TOPIC_ANALYZER_ASSESSMENT
            get_bus().publish(TOPIC_ANALYZER_ASSESSMENT, {
                "risk_level":      assessment.get("risk_level", "unknown"),
                "risk_score":      assessment.get("risk_score", 0.0),
                "recommendations": assessment.get("recommendations", []),
                "timestamp":       assessment.get("timestamp", ""),
                "agent_id":        self.name,
            })
        except Exception:  # noqa: BLE001
            pass
        return assessment

    def pre_assess_risk(self, tick_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Anticipatory risk assessment from Scout's ``rolling_tick()`` output.

        Processes only IPs at ``early_warning`` alert level — those whose
        *predicted* confidence is rising toward the confirmed threshold but
        have not yet crossed it.  Only low-impact actions are recommended:
        ``rate_limit`` or ``elevated_monitor``.

        This method is the analytical layer of the anticipatory pipeline:

            Scout.rolling_tick()
                → Scout.get_preemptive_candidates()   (optional helper)
                → Analyzer.pre_assess_risk()           (this method)
                → Responder POST /preemptive_action    (enforcement with safety gate)

        Parameters
        ----------
        tick_result : dict
            Direct output of ``ScoutAgent.rolling_tick()``.

        Returns
        -------
        dict
            {
              "preemptive_actions": [
                {
                  "source_ip":            str,
                  "alert_level":          "early_warning",
                  "current_confidence":   float,
                  "predicted_confidence": float,
                  "threat_type":          str,
                  "trend_direction":      str,
                  "recommended_action":   "rate_limit" | "elevated_monitor",
                  "reasoning":            str,
                  "agent_id":             str,
                }, ...
              ],
              "total_early_warnings": int,
              "timestamp":            str (ISO-8601 UTC),
            }

        Safety contract (enforced here, re-enforced at Responder):
        - Only ``rate_limit`` or ``elevated_monitor`` are ever recommended.
        - IPs at ``confirmed`` or higher alert levels are excluded — they must
          travel the normal reactive path through ``assess_risk()``.
        - An IP is only escalated to ``rate_limit`` when its predicted
          confidence is >= 0.50 AND the trend is ``rising``.
        """
        # Low-impact pre-emptive actions only
        _RATE_LIMIT_PRED_THRESHOLD = 0.50

        early_warning_ips = tick_result.get("early_warnings", [])
        per_ip            = tick_result.get("per_ip", {})

        preemptive_actions: List[Dict[str, Any]] = []

        for ip in early_warning_ips:
            ip_data    = per_ip.get(ip, {})
            alert_level = ip_data.get("alert_level", "")

            # Only process genuine early_warning IPs (exclude confirmed ones)
            if alert_level != "early_warning":
                continue

            current_conf = ip_data.get("current_confidence", 0.0)
            pred_conf    = ip_data.get("predicted_confidence", 0.0)
            mc           = ip_data.get("monte_carlo", {})
            threat_type  = mc.get("top_threat", "unknown")
            trend        = ip_data.get("trend", {})
            trend_dir    = trend.get("trend_direction", "stable")

            # Decision: rate_limit for rising high-pred threats;
            #           elevated_monitor for everything else in the zone
            if pred_conf >= _RATE_LIMIT_PRED_THRESHOLD and trend_dir == "rising":
                recommended = "rate_limit"
                reasoning = (
                    f"Predicted confidence {pred_conf:.2f} is rising toward the "
                    f"confirmed threshold. Throttling {ip} pre-emptively to reduce "
                    f"impact if the threat materialises."
                )
            else:
                recommended = "elevated_monitor"
                reasoning = (
                    f"Confidence {current_conf:.2f} (predicted {pred_conf:.2f}, "
                    f"trend: {trend_dir}) in early-warning zone for {threat_type}. "
                    f"Elevating monitoring; withholding enforcement until confirmation."
                )

            preemptive_actions.append({
                "source_ip":            ip,
                "alert_level":          "early_warning",
                "current_confidence":   current_conf,
                "predicted_confidence": pred_conf,
                "threat_type":          threat_type,
                "trend_direction":      trend_dir,
                "recommended_action":   recommended,
                "reasoning":            reasoning,
                "agent_id":             self.name,
            })

        self.logger.info(
            "Pre-emptive risk assessment: %d early-warning IP(s), %d action(s) recommended.",
            len(early_warning_ips), len(preemptive_actions),
        )

        pre_result = {
            "preemptive_actions":   preemptive_actions,
            "total_early_warnings": len(early_warning_ips),
            "timestamp":            datetime.now(timezone.utc).isoformat(),
        }
        try:
            from ..utils.message_bus import get_bus, TOPIC_ANALYZER_PREASSESS
            get_bus().publish(TOPIC_ANALYZER_PREASSESS, {
                **pre_result,
                "agent_id": self.name,
            })
        except Exception:  # noqa: BLE001
            pass
        return pre_result

    # ------------------------------------------------------------------
    # CIC-ML addon layer
    # ------------------------------------------------------------------

    def cic_screen(self, per_ip: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Run the CIC-IDS2017 XGBoost model over per-IP Scout stats.

        This is a **light addon** — it silently returns an empty result if
        the model is unavailable.  It does NOT replace any part of the main
        pipeline; it adds a second-opinion layer that the demo wires into
        the Responder's ``/cic_block`` endpoint.

        Parameters
        ----------
        per_ip : dict
            Mapping of ``{source_ip: {"stats": {...}, ...}}`` as returned
            by ``ScoutAgent.rolling_tick()["per_ip"]``.

        Returns
        -------
        dict
            {
              "flagged_ips": [
                {
                  "source_ip":         str,
                  "cic_label":         str,   e.g. "DDoS", "PortScan"
                  "confidence":        float,
                  "recommended_action": "block",
                }
              ],
              "screened": int,   # IPs inspected
              "available": bool, # False if model not loaded
            }
        """
        try:
            from ..utils.ml_classifier import get_classifier  # noqa: PLC0415
        except ImportError:
            return {"flagged_ips": [], "screened": 0, "available": False}

        clf = get_classifier().ensure_loaded()
        if not clf.available:
            return {"flagged_ips": [], "screened": 0, "available": False}

        # Map each CIC attack class to the semantically correct response action.
        # PortScan → honeypot (collect intel); destructive attacks → block;
        # infiltration/lateral-movement → quarantine (bidirectional isolation).
        _CIC_ACTION: Dict[str, str] = {
            "DDoS":                         "block",
            "Bot":                          "block",
            "FTP-Patator":                  "block",
            "SSH-Patator":                  "block",
            "Web Attack - Brute Force":     "block",
            "Web Attack - Sql Injection":   "block",
            "Web Attack - XSS":             "block",
            "PortScan":                     "redirect_to_honeypot",
            "Infiltration":                 "quarantine",
        }

        flagged: List[Dict[str, Any]] = []
        for source_ip, ip_data in per_ip.items():
            stats = ip_data.get("stats", {})
            label, conf, is_attack = clf.predict(stats)
            if is_attack:
                action = _CIC_ACTION.get(label, "block")
                self.logger.info(
                    "[CIC-ML] %s flagged as %s (conf=%.2f) → %s",
                    source_ip, label, conf, action,
                )
                flagged.append({
                    "source_ip":          source_ip,
                    "cic_label":          label,
                    "confidence":         conf,
                    "recommended_action": action,
                })

        return {
            "flagged_ips": flagged,
            "screened":    len(per_ip),
            "available":   True,
        }
