import logging
import math
import random
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROPAGATION_BASE = 0.4   # base probability an attacker moves to a neighbour
N_SIM_TRIALS     = 500   # Monte Carlo trials for propagation simulation
RISK_HIGH        = 0.70
RISK_MEDIUM      = 0.40


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

    def __init__(self, name: str = "Analyzer"):
        self.name   = name
        self.logger = logging.getLogger(f"{__name__}.{name}")

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
        return assessment
