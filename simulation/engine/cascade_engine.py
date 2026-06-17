from infrastructure.graph.builder import GraphBuilder
from simulation.models import SimulationStep


class CascadeEngine:

    @staticmethod
    def run_simulation(simulation):

        print("Simulation started")

        G = GraphBuilder.build_graph(simulation.infrastructure.id)

        # Apply initial impact
        if simulation.start_node.id in G.nodes:
            G.nodes[simulation.start_node.id]['stability'] -= simulation.initial_impact

        for t in range(simulation.total_steps):

            print(f"Time step: {t}")

            updated_stabilities = {}

            for node in G.nodes:
                stability = G.nodes[node]['stability']
                threshold = G.nodes[node]['threshold']
                recovery_time = G.nodes[node]['recovery_time']

                # Failure propagation
                if stability <= threshold:
                    for successor in G.successors(node):
                        weight = G[node][successor]['weight']
                        impact = weight * 20
                        updated_stabilities[successor] = (
                            G.nodes[successor]['stability'] - impact
                        )

                # Recovery logic
                else:
                    recovery_rate = 100 / (recovery_time * 2)
                    updated_stabilities[node] = min(
                        stability + recovery_rate,
                        100
                    )

            # Apply updates
            for node_id, new_stability in updated_stabilities.items():
                G.nodes[node_id]['stability'] = max(new_stability, 0)

            # Store snapshot
            for node in G.nodes:
                SimulationStep.objects.create(
                    simulation=simulation,
                    time_step=t,
                    node_name=G.nodes[node]['name'],
                    stability_score=G.nodes[node]['stability']
                )

        print("Simulation finished")
        return True