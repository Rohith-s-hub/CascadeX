# accounts/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ['username', 'email', 'role', 'organization', 'is_active', 'total_scans', 'last_login']
    list_filter = ['role', 'is_active', 'organization']
    search_fields = ['username', 'email', 'organization']
    
    fieldsets = UserAdmin.fieldsets + (
        ('CascadeX Profile', {
            'fields': ('role', 'organization', 'job_title', 'phone',
                      'default_scan_depth', 'default_severity', 'email_alerts',
                      'total_scans', 'last_scan'),
        }),
    )
    
    readonly_fields = ['total_scans', 'last_scan', 'created_at', 'updated_at']