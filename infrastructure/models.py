from django.db import models

class InfrastructureNode(models.Model):
    NODE_TYPES = [
        ("gateway", "Gateway / Load Balancer"),
        ("server", "Application Server"),
        ("database", "Database"),
        ("network", "Network / Switch"),
        ("cache", "Cache Layer"),
        ("queue", "Message Queue"),
        ("cdn", "CDN Edge Node"),
    ]

    STATUS_CHOICES = [
        ("operational", "Operational"),
        ("warning", "Warning"),
        ("critical", "Critical"),
        ("failed", "Failed"),
    ]

    name = models.CharField(max_length=100)
    node_type = models.CharField(max_length=20, choices=NODE_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="operational")
    stability = models.FloatField(default=100.0)
    risk = models.FloatField(default=0.0)
    max_load = models.FloatField(default=100.0)
    current_load = models.FloatField(default=0.0)
    is_critical = models.BooleanField(default=False)
    tier = models.IntegerField(default=0)
    position_index = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["tier", "position_index"]

    def __str__(self):
        return f"{self.name} ({self.node_type})"

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "type": self.node_type,
            "stability": self.stability,
            "risk": self.risk,
            "status": self.status,
            "connections": [str(conn.target_node.id) for conn in self.outgoing_connections.all()]
        }


class NodeConnection(models.Model):
    source_node = models.ForeignKey(
        InfrastructureNode, 
        on_delete=models.CASCADE, 
        related_name="outgoing_connections"
    )
    target_node = models.ForeignKey(
        InfrastructureNode, 
        on_delete=models.CASCADE, 
        related_name="incoming_connections"
    )
    risk_propagation_factor = models.FloatField(default=0.6)

    class Meta:
        unique_together = ("source_node", "target_node")

    def __str__(self):
        return f"{self.source_node.name} → {self.target_node.name}"


class RealWorldScenario(models.Model):
    """Real-world inspired outage scenarios"""
    name = models.CharField(max_length=200)
    description = models.TextField()
    source = models.CharField(max_length=100, help_text="e.g., Fastly 2021, AWS us-east-1")
    year = models.IntegerField()
    severity = models.CharField(max_length=20, choices=[
        ("minor", "Minor"),
        ("major", "Major"),
        ("catastrophic", "Catastrophic")
    ])
    config = models.JSONField(help_text="Configuration to load nodes and connections")

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.year})"
