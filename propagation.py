"""
Siege Map propagation engine.

Models cross-sector dependencies as a weighted directed graph (networkx).
Edge weight = how strongly a compromise in the source sector bleeds into
the target sector's risk. Propagation is applied over multiple hops per
tick (so an attack can ripple A -> B -> C), with strength decaying by
distance and scaled by how anomalous the source currently is.

Also provides a simple linear-trend "blast radius" forecast: given a
sector's recent risk history, estimate whether/when it will cross the
critical threshold if the current trend continues.
"""
from collections import deque

import networkx as nx
import numpy as np

CRITICAL_THRESHOLD = 75
WATCH_THRESHOLD = 60


def build_dependency_graph():
    """Weighted, directed edges: source -> target, weight in (0, 1]."""
    g = nx.DiGraph()
    g.add_edge("power_grid", "hospital", weight=0.65, reason="Backup power dependency")
    g.add_edge("bank", "hospital", weight=0.35, reason="Shared payment/records infrastructure")
    g.add_edge("power_grid", "bank", weight=0.25, reason="Grid-dependent data center cooling")
    return g


class PropagationEngine:
    def __init__(self, sectors, max_hops=2):
        self.graph = build_dependency_graph()
        self.sectors = sectors
        self.max_hops = max_hops
        self.history = {s: deque(maxlen=30) for s in sectors}

    def record(self, sector, risk_score):
        self.history[sector].append(risk_score)

    def propagate(self, base_scores, anomaly_flags):
        """
        base_scores: {sector: risk_score}
        anomaly_flags: {sector: bool}
        Returns (adjusted_scores, propagation_events)
        propagation_events: list of {from, to, hop, weight, boost}
        """
        adjusted = dict(base_scores)
        events = []

        # BFS-style multi-hop relaxation: each hop's contribution decays
        frontier = [s for s in self.sectors if anomaly_flags.get(s)]
        visited_edges = set()

        for hop in range(1, self.max_hops + 1):
            next_frontier = []
            for source in frontier:
                source_severity = base_scores.get(source, 0) / 100.0
                for target in self.graph.successors(source):
                    edge_key = (source, target)
                    if edge_key in visited_edges:
                        continue
                    visited_edges.add(edge_key)

                    weight = self.graph[source][target]["weight"]
                    hop_decay = 0.8 ** (hop - 1)
                    boost = 40.0 * weight * source_severity * hop_decay

                    if boost > 1.0:
                        adjusted[target] = min(100, adjusted.get(target, 0) + boost)
                        events.append({
                            "from": source,
                            "to": target,
                            "hop": hop,
                            "weight": round(weight, 2),
                            "boost": round(boost, 1),
                            "reason": self.graph[source][target].get("reason", ""),
                        })
                        # a target that gets pushed into anomaly range can
                        # itself become a new source for the next hop
                        if adjusted[target] >= WATCH_THRESHOLD:
                            next_frontier.append(target)
            frontier = next_frontier

        return adjusted, events

    def blast_radius(self, sector, critical_threshold=None):
        """Linear-trend forecast: does this sector look like it's heading
        toward the critical threshold, and how soon? `critical_threshold`
        lets callers pass the sector's own configurable cutoff (falls back
        to the global default when omitted)."""
        threshold = critical_threshold if critical_threshold is not None else CRITICAL_THRESHOLD
        hist = list(self.history[sector])
        if len(hist) < 5:
            return None

        y = np.array(hist[-10:])
        x = np.arange(len(y))
        slope, intercept = np.polyfit(x, y, 1)

        current = y[-1]
        if slope <= 0.15 or current >= threshold:
            return None  # not trending upward meaningfully, or already critical

        ticks_to_critical = (threshold - current) / slope
        if ticks_to_critical <= 0 or ticks_to_critical > 30:
            return None

        # crude confidence: steeper + more consistent trend = higher confidence
        residuals = y - (slope * x + intercept)
        fit_quality = 1.0 / (1.0 + np.std(residuals))
        probability = float(np.clip(fit_quality * min(1.0, slope / 5.0) * 2, 0.1, 0.95))

        return {
            "sector": sector,
            "eta_ticks": round(float(ticks_to_critical), 1),
            "eta_seconds": round(float(ticks_to_critical) * 2, 0),
            "probability": round(probability, 2),
        }