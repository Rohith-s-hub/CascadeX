from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import InfrastructureNode, NodeConnection

@csrf_exempt
@require_http_methods(["POST"])
def seed_infrastructure(request):
    """Seed realistic cloud infrastructure"""
    # Clear existing data
    NodeConnection.objects.all().delete()
    InfrastructureNode.objects.all().delete()

    # Create Nodes
    gateway = InfrastructureNode.objects.create(
        name="API Gateway", node_type="gateway", stability=100, risk=0, 
        tier=0, is_critical=True, current_load=450, max_load=1000
    )
    cdn = InfrastructureNode.objects.create(
        name="CDN Edge", node_type="gateway", stability=100, risk=0, 
        tier=0, current_load=800, max_load=2000
    )
    switch1 = InfrastructureNode.objects.create(
        name="Core Switch A", node_type="network", stability=100, risk=0, 
        tier=1, is_critical=True, current_load=200, max_load=500
    )
    switch2 = InfrastructureNode.objects.create(
        name="Core Switch B", node_type="network", stability=100, risk=0, 
        tier=1, current_load=180, max_load=500
    )
    web1 = InfrastructureNode.objects.create(
        name="Web Server 1", node_type="server", stability=100, risk=0, 
        tier=2, current_load=120, max_load=200
    )
    web2 = InfrastructureNode.objects.create(
        name="Web Server 2", node_type="server", stability=100, risk=0, 
        tier=2, current_load=90, max_load=200
    )
    app = InfrastructureNode.objects.create(
        name="App Server", node_type="server", stability=100, risk=0, 
        tier=2, is_critical=True, current_load=200, max_load=300
    )
    cache = InfrastructureNode.objects.create(
        name="Redis Cache", node_type="cache", stability=100, risk=0, 
        tier=2, current_load=60, max_load=100
    )
    db_primary = InfrastructureNode.objects.create(
        name="PostgreSQL Primary", node_type="database", stability=100, risk=0, 
        tier=3, is_critical=True, current_load=70, max_load=100
    )
    db_replica = InfrastructureNode.objects.create(
        name="PostgreSQL Replica", node_type="database", stability=100, risk=0, 
        tier=3, current_load=40, max_load=100
    )

    # Create Connections
    connections = [
        (gateway, switch1, 0.8), (gateway, switch2, 0.7),
        (cdn, switch1, 0.6),
        (switch1, web1, 0.8), (switch1, web2, 0.8),
        (switch2, app, 0.9),
        (web1, cache, 0.5), (web2, cache, 0.5),
        (app, db_primary, 0.95), (app, cache, 0.6),
        (db_primary, db_replica, 0.4),
    ]

    for source, target, risk in connections:
        NodeConnection.objects.create(
            source_node=source, 
            target_node=target, 
            risk_propagation_factor=risk
        )

    return JsonResponse({
        "status": "success",
        "message": "Infrastructure seeded successfully",
        "nodes": InfrastructureNode.objects.count(),
        "connections": NodeConnection.objects.count()
    })
