from django.contrib import admin
from .models import InfrastructureNode, NodeConnection


@admin.register(InfrastructureNode)
class InfrastructureNodeAdmin(admin.ModelAdmin):
    list_display = ('name', 'node_type', 'status', 'stability', 'risk', 'tier', 'is_critical')
    list_filter = ('node_type', 'status', 'is_critical')
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Basic Info', {
            'fields': ('name', 'node_type', 'status')
        }),
        ('Health Metrics', {
            'fields': ('stability', 'risk', 'current_load', 'max_load')
        }),
        ('Structure', {
            'fields': ('tier', 'position_index', 'is_critical')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(NodeConnection)
class NodeConnectionAdmin(admin.ModelAdmin):
    list_display = ('source_node', 'target_node', 'risk_propagation_factor')
    list_filter = ('source_node__node_type', 'target_node__node_type')
    search_fields = ('source_node__name', 'target_node__name')
