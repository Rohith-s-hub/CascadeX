# simulation/models.py

from django.db import models
from django.conf import settings
from django.utils import timezone


class CVERecord(models.Model):
    """Stores CVE vulnerability data from NVD"""
    
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('NONE', 'None'),
    ]
    
    STATUS_CHOICES = [
        ('operational', 'Operational'),
        ('elevated', 'Elevated'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
        ('exploited', 'Exploited'),
        ('not_applicable', 'Not Applicable'),
        ('mitigated', 'Mitigated'),
    ]
    
    cve_id = models.CharField(max_length=20, unique=True, db_index=True)
    description = models.TextField(blank=True)
    nvd_status = models.CharField(max_length=50, default='Analyzed')
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_version = models.CharField(max_length=10, blank=True, default='3.1')
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='MEDIUM')
    
    # CVSS Vector information
    attack_vector = models.CharField(max_length=50, blank=True)
    attack_complexity = models.CharField(max_length=20, blank=True)
    privileges_required = models.CharField(max_length=20, blank=True)
    user_interaction = models.CharField(max_length=20, blank=True)
    scope = models.CharField(max_length=20, blank=True)
    
    # Status tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='warning')
    exploit_available = models.BooleanField(default=False)
    exploit_maturity = models.CharField(max_length=20, blank=True, default='unknown')
    exploit_confidence = models.IntegerField(default=0)
    exploit_sources = models.JSONField(default=list, blank=True)
    patch_available = models.BooleanField(default=False)
    patch_confidence = models.IntegerField(default=0)
    patch_sources = models.JSONField(default=list, blank=True)
    cisa_kev = models.BooleanField(default=False)
    
    # Affected products
    affected_products = models.JSONField(default=list)
    affected_vendors = models.JSONField(default=list)
    affected_entries = models.JSONField(default=list, blank=True)
    cwe_ids = models.JSONField(default=list)
    
    # References
    references = models.JSONField(default=list)
    
    # EPSS — Exploit Prediction Scoring System
    epss_score = models.FloatField(null=True, blank=True)
    epss_percentile = models.FloatField(null=True, blank=True)
    epss_updated_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    published_date = models.DateTimeField(null=True, blank=True)
    last_modified_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-cvss_score', '-published_date']
        verbose_name = 'CVE Record'
        verbose_name_plural = 'CVE Records'
    
    def __str__(self):
        return f"{self.cve_id} ({self.severity})"
    
    @property
    def risk_score(self):
        """Calculate risk score (0-100)"""
        base_risk = (self.cvss_score or 5) * 10
        if self.exploit_available:
            base_risk = min(100, base_risk + 15)
        if not self.patch_available:
            base_risk = min(100, base_risk + 10)
        return round(base_risk, 1)
    
    @property
    def stability_score(self):
        """Calculate stability score (inverse of risk)"""
        return round(max(5, 100 - self.risk_score * 0.8), 1)


class MitigationRecord(models.Model):
    """Track mitigation actions"""
    
    ACTION_CHOICES = [
        ('patch', 'Apply Patch'),
        ('isolate', 'Isolate System'),
        ('block', 'Block Attack Vector'),
        ('monitor', 'Enhanced Monitoring'),
        ('script', 'Run Remediation Script'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    cve = models.ForeignKey(CVERecord, on_delete=models.CASCADE, related_name='mitigations')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    risk_reduction = models.IntegerField(default=0)
    notes = models.TextField(blank=True)
    
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.cve.cve_id} - {self.action}"


class ScanHistory(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='scan_histories',
    )
    """Track vulnerability scan history"""
    
    scan_type = models.CharField(max_length=50, default='nvd_api')
    keywords = models.JSONField(default=list)
    severity_filter = models.CharField(max_length=20, blank=True)
    days_back = models.IntegerField(default=30)
    
    total_found = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)
    
    success = models.BooleanField(default=False)
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-started_at']
        verbose_name_plural = 'Scan Histories'
    
    def __str__(self):
        return f"Scan #{self.id} - {self.started_at.strftime('%Y-%m-%d %H:%M')}"


# ═══════════════════════════════════════════════════════════════
# ASSET INVENTORY
# ═══════════════════════════════════════════════════════════════

class AssetInventory(models.Model):
    """
    Asset inventory for context-aware vulnerability analysis.
    Without this, your tool is just a CVE list viewer.
    With this, it becomes a real security product.
    """
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='assets',
    )
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(unique=True)
    os_type = models.CharField(max_length=100, blank=True, default='')
    os_version = models.CharField(max_length=100, blank=True, default='')

    # Service fingerprinting
    services = models.JSONField(default=list)

    # Business context
    criticality = models.CharField(
        max_length=20,
        choices=[
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
        ],
        default='medium',
    )
    environment = models.CharField(
        max_length=20,
        choices=[
            ('production', 'Production'),
            ('staging', 'Staging'),
            ('development', 'Development'),
        ],
        default='production',
    )
    data_classification = models.CharField(
        max_length=20,
        choices=[
            ('public', 'Public'),
            ('internal', 'Internal'),
            ('confidential', 'Confidential'),
            ('restricted', 'Restricted'),
        ],
        default='internal',
    )

    # Network exposure
    internet_facing = models.BooleanField(default=False)
    behind_firewall = models.BooleanField(default=True)
    requires_vpn = models.BooleanField(default=False)

    # Discovery metadata
    last_scanned = models.DateTimeField(auto_now=True)
    scan_method = models.CharField(max_length=50, default='manual')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'asset_inventory'
        ordering = ['-criticality', 'hostname']
        verbose_name = 'Asset'
        verbose_name_plural = 'Asset Inventory'

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"


class CVEAssetMapping(models.Model):
    """
    Bridge between CVEs and actual infrastructure.
    This is what makes the product REAL.
    """
    cve = models.ForeignKey(
        CVERecord,
        on_delete=models.CASCADE,
        related_name='asset_mappings',
    )
    asset = models.ForeignKey(
        AssetInventory,
        on_delete=models.CASCADE,
        related_name='vulnerabilities',
    )
    matched_product = models.CharField(max_length=255)
    matched_service = models.JSONField(default=dict)
    confidence_score = models.IntegerField(default=0)
    is_exploitable = models.BooleanField(default=False)
    match_type = models.CharField(max_length=50, default='product_match')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'cve_asset_mapping'
        unique_together = ['cve', 'asset', 'matched_product']

    def __str__(self):
        return f"{self.cve.cve_id} -> {self.asset.hostname}"


# ═══════════════════════════════════════════════════════════════
# TRENDING & MONITORING
# ═══════════════════════════════════════════════════════════════

class RiskSnapshot(models.Model):
    """Historical risk posture snapshots for trending analysis"""
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    total_cves = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    avg_risk = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    system_health = models.IntegerField(default=100)
    entry_points = models.IntegerField(default=0)
    assets_scanned = models.IntegerField(default=0)
    asset_matches = models.IntegerField(default=0)
    exploit_count = models.IntegerField(default=0)
    data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        db_table = 'risk_snapshots'
        indexes = [
            models.Index(fields=['-timestamp']),
        ]
    
    def __str__(self):
        return f"Snapshot {self.timestamp.strftime('%Y-%m-%d %H:%M')} — Health: {self.system_health}"


class AlertRecord(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='alert_records',
    )
    """Real-time monitoring alerts"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    alert_type = models.CharField(max_length=100)
    message = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        db_table = 'alert_records'
    
    def __str__(self):
        return f"{self.alert_type} — {self.severity}"


# ═══════════════════════════════════════════════════════════════
# RBAC & API KEYS
# ═══════════════════════════════════════════════════════════════

class UserProfile(models.Model):
    """Extended user profile for RBAC"""
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('analyst', 'Security Analyst'),
        ('viewer', 'Viewer'),
        ('api_user', 'API User'),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='security_profile',
    )
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='viewer',
    )
    organization = models.CharField(max_length=200, blank=True)
    api_key = models.CharField(max_length=64, unique=True, null=True, blank=True)
    api_key_created = models.DateTimeField(null=True, blank=True)
    allowed_actions = models.JSONField(default=list)
    notification_preferences = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_profiles'

    def __str__(self):
        return f"{self.user.username} ({self.role})"

    @property
    def can_scan(self):
        return self.role in ('admin', 'analyst')

    @property
    def can_mitigate(self):
        return self.role in ('admin', 'analyst')

    @property
    def can_manage_assets(self):
        return self.role in ('admin', 'analyst')

    @property
    def can_manage_users(self):
        return self.role == 'admin'


class APIKey(models.Model):
    """API Key management"""
    key = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=100)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='api_keys',
    )
    is_active = models.BooleanField(default=True)
    permissions = models.JSONField(default=list)
    rate_limit = models.IntegerField(default=100)  # requests per minute
    last_used = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'api_keys'

    def __str__(self):
        return f"{self.name} ({self.user.username})"


class IntegrationConfig(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='integration_configs',
    )
    """Persisted integration configurations"""
    INTEGRATION_TYPES = [
        ('slack',      'Slack'),
        ('jira',       'Jira'),
        ('pagerduty',  'PagerDuty'),
        ('webhook',    'Webhook'),
    ]

    integration_type = models.CharField(
        max_length=20,
        choices=INTEGRATION_TYPES
    )
    name        = models.CharField(max_length=100)
    config_data = models.JSONField(default=dict)
    is_enabled  = models.BooleanField(default=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('integration_type', 'name')

    def __str__(self):
        return f"{self.integration_type}: {self.name}"


class WebhookDelivery(models.Model):
    """Stores every webhook delivery attempt and result"""
    STATUS_CHOICES = [
        ("success", "Success"),
        ("failed",  "Failed"),
        ("pending", "Pending"),
    ]

    integration_name = models.CharField(max_length=100)
    integration_type = models.CharField(max_length=20, default="webhook")
    event_type       = models.CharField(max_length=100)
    event_title      = models.CharField(max_length=255, blank=True)
    severity         = models.CharField(max_length=20, default="info")
    payload          = models.JSONField(default=dict)
    status           = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    status_code      = models.IntegerField(null=True, blank=True)
    response_preview = models.TextField(blank=True)
    error_message    = models.TextField(blank=True)
    delivered_at     = models.DateTimeField(auto_now_add=True)
    duration_ms      = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ["-delivered_at"]

    def __str__(self):
        return f"{self.integration_name} → {self.event_type} [{self.status}]"
