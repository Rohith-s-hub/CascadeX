# simulation/urls.py

from django.urls import path
from . import views

app_name = 'simulation'

urlpatterns = [
    # ═══════════════════════════════════════════════════════════
    # CORE ENDPOINTS (Available in rewritten views.py)
    # ═══════════════════════════════════════════════════════════
    
    # Health
    path('health/',
         views.HealthCheckView.as_view(),
         name='health'),

    # CVE Operations
    path('scan/',
         views.CVEScanView.as_view(),
         name='scan'),
    
    path('cves/',
         views.CVEListView.as_view(),
         name='cve-list'),
    
    path('cves/<str:cve_id>/',
         views.CVEDetailView.as_view(),
         name='cve-detail'),
    
    path('cves/<str:cve_id>/explain/',
         views.RiskExplanationView.as_view(),
         name='cve-explain'),

    # Intelligence
    path('cascade/nodes/',
         views.CascadeNodesView.as_view(),
         name='cascade-nodes'),

    # Mitigation
    path('mitigate/',
         views.MitigationView.as_view(),
         name='mitigate'),

    # Stats
    path('stats/',
         views.StatsView.as_view(),
         name='stats'),

    # MITRE ATT&CK
    path('mitre/map/<str:cve_id>/',
         views.MitreMappingView.as_view(),
         name='mitre-map'),
    
    path('mitre/coverage/',
         views.MitreCoverageView.as_view(),
         name='mitre-coverage'),

    # Assets
    path('assets/',
         views.AssetListView.as_view(),
         name='asset-list'),
    
    path('assets/<int:asset_id>/',
         views.AssetDetailView.as_view(),
         name='asset-detail'),

    # ═══════════════════════════════════════════════════════════
    # COMPLIANCE & TRENDING (NEW)
    # ═══════════════════════════════════════════════════════════
    
    path('compliance/',
         views.ComplianceView.as_view(),
         name='compliance'),
    
    path('trending/',
         views.TrendingView.as_view(),
         name='trending'),
    
    path('trending/snapshot/',
         views.TrendingSnapshotView.as_view(),
         name='trending-snapshot'),
    path('report/export/',
         views.ReportExportView.as_view(),
         name='report-export'),

    # ═══════════════════════════════════════════════════════════
    # MONITORING & ALERTS (NEW)
    # ═══════════════════════════════════════════════════════════
    
    path('monitor/status/',
         views.MonitorStatusView.as_view(),
         name='monitor-status'),
    
    path('monitor/control/',
         views.MonitorControlView.as_view(),
         name='monitor-control'),
    
    path('alerts/',
         views.AlertsView.as_view(),
         name='alerts'),
    path('alerts/<int:alert_id>/acknowledge/',
         views.AlertAcknowledgeView.as_view(),
         name='alert-acknowledge'),

    # Integrations
    path('integrations/status/',
         views.IntegrationStatusView.as_view(),
         name='integrations-status'),
    path('integrations/configure/',
         views.IntegrationConfigureView.as_view(),
         name='integrations-configure'),

    # ═══════════════════════════════════════════════════════════
    # ACTIVE SCANNING (NEW)
    # ═══════════════════════════════════════════════════════════
    
    path('integrations/deliveries/',
         views.WebhookDeliveriesView.as_view(),
         name='webhook-deliveries'),
    path('integrations/recent/',
         views.IntegrationRecentResultsView.as_view(),
         name='integrations-recent'),
    path('integrations/test/',
         views.IntegrationTestView.as_view(),
         name='integrations-test'),
    path('scan/active/',
         views.ActiveScanView.as_view(),
         name='scan-active'),
]
