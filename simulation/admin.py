# simulation/admin.py

from django.contrib import admin
from .models import CVERecord, MitigationRecord, ScanHistory


@admin.register(CVERecord)
class CVERecordAdmin(admin.ModelAdmin):
    list_display = ['cve_id', 'severity', 'cvss_score', 'status', 'exploit_available', 'patch_available', 'created_at']
    list_filter = ['severity', 'status', 'exploit_available', 'patch_available']
    search_fields = ['cve_id', 'description']
    ordering = ['-cvss_score', '-created_at']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(MitigationRecord)
class MitigationRecordAdmin(admin.ModelAdmin):
    list_display = ['cve', 'action', 'status', 'risk_reduction', 'created_at']
    list_filter = ['action', 'status']
    search_fields = ['cve__cve_id', 'notes']


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'started_at', 'total_found', 'critical_count', 'high_count', 'success', 'duration_seconds']
    list_filter = ['success']
    ordering = ['-started_at']