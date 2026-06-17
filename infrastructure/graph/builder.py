"""
Infrastructure Graph Builder
════════════════════════════════════════════════════════════════
Builds a NetworkX DiGraph from InfrastructureNode + NodeConnection models.

NOTE: This module handles the PHYSICAL infrastructure graph
      (servers, gateways, switches, databases).

      The CVE cascade graph is built entirely in the frontend
      (InfrastructureGraph.tsx) from CVE data returned by the
      simulation API. These are two separate graphs.
"""

import networkx as nx
from infrastructure.models import InfrastructureNode, NodeConnection


class GraphBuilder:

    @staticmethod
    def build_graph(infrastructure_id=None):
        """
        Build a directed graph of infrastructure nodes and their connections.

        Args:
            infrastructure_id: Optional filter (reserved for future use).

        Returns:
            nx.DiGraph with nodes (id, name, stability, risk, node_type)
                        and edges (weight = risk_propagation_factor).
        """
        G = nx.DiGraph()

        # ── Add nodes ─────────────────────────────────────────────────
        nodes = InfrastructureNode.objects.all()
        for node in nodes:
            G.add_node(
                node.id,
                name=node.name,
                node_type=node.node_type,
                stability=node.stability,
                risk=node.risk,
                status=node.status,
                is_critical=node.is_critical,
                tier=node.tier,
                current_load=node.current_load,
                max_load=node.max_load,
            )

        # ── Add edges (connections) ───────────────────────────────────
        connections = NodeConnection.objects.select_related(
            "source_node", "target_node"
        ).all()
        for conn in connections:
            G.add_edge(
                conn.source_node.id,
                conn.target_node.id,
                weight=conn.risk_propagation_factor,
            )

        return G

    @staticmethod
    def to_dict(G: nx.DiGraph) -> dict:
        """
        Serialize a graph to a JSON-serializable dict for API responses.
        """
        return {
            "nodes": [
                {"id": node_id, **data}
                for node_id, data in G.nodes(data=True)
            ],
            "edges": [
                {
                    "source": source,
                    "target": target,
                    "weight": data.get("weight", 0.5),
                }
                for source, target, data in G.edges(data=True)
            ],
            "node_count": G.number_of_nodes(),
            "edge_count": G.number_of_edges(),
        }
