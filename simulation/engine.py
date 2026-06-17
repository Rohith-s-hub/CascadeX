import random
from infrastructure.models import InfrastructureNode, NodeConnection


class CascadeSimulationEngine:
    def __init__(self, simulation_speed=1.5, failure_probability=25.0, 
                 recovery_rate=60.0, auto_recovery=True, cascade_prevention=False, 
                 total_ticks=50):
        
        self.simulation_speed = simulation_speed
        self.failure_probability = failure_probability / 100.0
        self.recovery_rate = recovery_rate / 100.0
        self.auto_recovery = auto_recovery
        self.cascade_prevention = cascade_prevention
        self.total_ticks = total_ticks

        self.node_states = {}
        self.timeline = {}
        self.risk_propagation = []

    def run(self):
        if not self.load_infrastructure():
            return self._empty_result()

        for tick in range(self.total_ticks):
            self._simulate_tick(tick)

        return self._build_result()

    def load_infrastructure(self):
        nodes = InfrastructureNode.objects.all()
        if not nodes.exists():
            return False

        for node in nodes:
            self.node_states[node.id] = {
                "id": str(node.id),
                "name": node.name,
                "type": node.node_type,
                "stability": float(node.stability),
                "risk": float(node.risk),
                "status": node.status,
                "connections": []
            }
            self.timeline[node.name] = []

        connections = NodeConnection.objects.select_related('source_node', 'target_node').all()
        for conn in connections:
            if conn.source_node.id in self.node_states:
                self.node_states[conn.source_node.id]["connections"].append(str(conn.target_node.id))

        return True

    def _simulate_tick(self, tick):
        for state in self.node_states.values():
            if state["status"] == "operational":
                if random.random() < self.failure_probability * 0.08:
                    state["stability"] = max(10, state["stability"] - random.uniform(10, 30))

            if state["stability"] < 30:
                state["status"] = "critical"
            elif state["stability"] < 60:
                state["status"] = "warning"

        for conn in NodeConnection.objects.select_related('source_node', 'target_node').all():
            source = self.node_states.get(conn.source_node.id)
            target = self.node_states.get(conn.target_node.id)
            if source and target and source["stability"] < 65:
                damage = random.uniform(5, 22) * conn.risk_propagation_factor
                target["stability"] = max(10, target["stability"] - damage)
                if damage > 8:
                    self.risk_propagation.append({
                        "from": source["name"],
                        "to": target["name"],
                        "intensity": int(min(100, damage * 3))
                    })

        if self.auto_recovery:
            for state in self.node_states.values():
                if state["stability"] < 85:
                    state["stability"] = min(100, state["stability"] + random.uniform(3, 10))

        for state in self.node_states.values():
            self.timeline[state["name"]].append(round(state["stability"], 1))

    def _build_result(self):
        nodes_list = list(self.node_states.values())
        avg_health = sum(n["stability"] for n in nodes_list) / len(nodes_list) if nodes_list else 100

        return {
            "nodes": nodes_list,
            "timeline": self.timeline,
            "riskPropagation": self.risk_propagation[:15],
            "analytics": {
                "systemHealth": round(avg_health, 1),
                "totalFailures": sum(1 for n in nodes_list if n["status"] in ["critical", "failed"]),
                "criticalNodes": sum(1 for n in nodes_list if n["status"] in ["critical", "failed"]),
                "avgRecoveryTime": 4.2
            }
        }

    def _empty_result(self):
        return {"nodes": [], "timeline": {}, "riskPropagation": [], "analytics": {
            "systemHealth": 100, "totalFailures": 0, "criticalNodes": 0, "avgRecoveryTime": 0
        }}
