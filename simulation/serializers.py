# simulation/serializers.py
"""
CascadeX Serializers
═══════════════════════════════════════════════════════════════
REST API serializers for all data models and responses.
"""

from rest_framework import serializers
from .models import CVERecord, MitigationRecord, ScanHistory


# ═══════════════════════════════════════════════════════════════
# MODEL SERIALIZERS
# ═══════════════════════════════════════════════════════════════

class CVERecordSerializer(serializers.ModelSerializer):
    """Serializer for CVE database records"""
    
    class Meta:
        model = CVERecord
        fields = '__all__'


class MitigationRecordSerializer(serializers.ModelSerializer):
    """Serializer for mitigation records"""
    cve_id = serializers.CharField(source='cve.cve_id', read_only=True)
    
    class Meta:
        model = MitigationRecord
        fields = [
            'id', 'cve_id', 'action', 'status',
            'risk_reduction', 'notes', 'started_at', 'completed_at',
        ]


class ScanHistorySerializer(serializers.ModelSerializer):
    """Serializer for scan history"""
    
    class Meta:
        model = ScanHistory
        fields = '__all__'


# ═══════════════════════════════════════════════════════════════
# REQUEST SERIALIZERS
# ═══════════════════════════════════════════════════════════════

class ScanRequestSerializer(serializers.Serializer):
    """Validates scan request parameters"""
    keywords = serializers.ListField(
        child=serializers.CharField(max_length=100),
        required=False,
        allow_empty=True,
    )
    severity = serializers.ChoiceField(
        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        required=False,
        allow_null=True,
        allow_blank=True,
    )
    days_back = serializers.IntegerField(
        min_value=1,
        max_value=365,
        default=30,
    )
    max_results = serializers.IntegerField(
        min_value=1,
        max_value=500,
        default=50,
    )
    
    # Asset context (NEW)
    assets = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        allow_empty=True,
    )


class MitigationRequestSerializer(serializers.Serializer):
    """Validates mitigation request"""
    cve_id = serializers.CharField(max_length=20)
    action = serializers.ChoiceField(
        choices=['patch', 'isolate', 'block', 'monitor', 'script'],
    )
    notes = serializers.CharField(
        max_length=1000,
        required=False,
        allow_blank=True,
    )


class AssetScanRequestSerializer(serializers.Serializer):
    """Validates asset discovery request"""
    target = serializers.CharField(max_length=100)
    ports = serializers.CharField(max_length=100, default="1-1000")
    aggressive = serializers.BooleanField(default=False)


class ValidationRequestSerializer(serializers.Serializer):
    """Validates vulnerability validation request"""
    cve_id = serializers.CharField(max_length=20)
    target_ip = serializers.IPAddressField()
    target_port = serializers.IntegerField(
        min_value=1,
        max_value=65535,
        required=False,
    )


# ═══════════════════════════════════════════════════════════════
# RESPONSE SERIALIZERS (Read-only, for documentation)
# ═══════════════════════════════════════════════════════════════

class AssetMatchSerializer(serializers.Serializer):
    """Asset match within a vulnerability node"""
    asset_id = serializers.CharField()
    asset_name = serializers.CharField()
    match_type = serializers.CharField()
    confidence = serializers.IntegerField()
    matched_on = serializers.CharField()
    evidence = serializers.CharField()


class ConnectionSerializer(serializers.Serializer):
    """Connection between vulnerability nodes"""
    target = serializers.CharField()
    score = serializers.IntegerField()
    strength = serializers.CharField()
    reasons = serializers.ListField(child=serializers.CharField())
    chain_viable = serializers.BooleanField()
    causal_direction = serializers.CharField()


class RiskFactorsSerializer(serializers.Serializer):
    """Risk calculation breakdown"""
    cvss_component = serializers.FloatField()
    exploitability = serializers.IntegerField()
    exposure = serializers.IntegerField()
    asset_value = serializers.IntegerField()
    chain_amplification = serializers.IntegerField()
    raw_total = serializers.FloatField()
    final_score = serializers.IntegerField()
    breakdown = serializers.ListField(child=serializers.CharField())
    evidence_summary = serializers.DictField()


class TimeToExploitSerializer(serializers.Serializer):
    """Time-to-exploit estimation"""
    estimate = serializers.CharField()
    confidence = serializers.IntegerField()
    factors = serializers.ListField(child=serializers.CharField())


class CascadeNodeSerializer(serializers.Serializer):
    """
    Full enriched vulnerability node
    This is the main output format for intelligence engine
    """
    # Basic CVE data
    cve_id = serializers.CharField()
    description = serializers.CharField()
    cvss_score = serializers.FloatField(allow_null=True)
    severity = serializers.CharField()
    cwe_ids = serializers.ListField(child=serializers.CharField())
    affected_products = serializers.ListField(child=serializers.CharField())
    affected_vendors = serializers.ListField(child=serializers.CharField())
    
    # CVSS details
    attack_vector = serializers.CharField(allow_blank=True)
    attack_complexity = serializers.CharField(allow_blank=True)
    privileges_required = serializers.CharField(allow_blank=True)
    user_interaction = serializers.CharField(allow_blank=True)
    scope = serializers.CharField(allow_blank=True)
    
    # Status
    status = serializers.CharField()
    exploit_available = serializers.BooleanField()
    patch_available = serializers.BooleanField()
    
    # Stage classification
    attack_stage = serializers.CharField()
    stage_confidence = serializers.IntegerField()
    stage_reasons = serializers.ListField(child=serializers.CharField())
    
    # Entry point
    is_entry_point = serializers.BooleanField()
    entry_evidence = serializers.CharField()
    
    # Node classification
    type = serializers.CharField()
    node_type = serializers.CharField()
    
    # Asset matching
    asset_matches = AssetMatchSerializer(many=True)
    asset_relevant = serializers.BooleanField()
    relevance_score = serializers.IntegerField()
    asset_evidence = serializers.CharField()
    
    # Exploit intelligence
    exploit_maturity = serializers.CharField()
    exploit_confidence = serializers.IntegerField()
    exploit_sources = serializers.ListField(child=serializers.CharField())
    exploit_evidence = serializers.CharField()
    
    # Connections
    connections = ConnectionSerializer(many=True)
    connection_count = serializers.IntegerField()
    connected_ids = serializers.ListField(child=serializers.CharField())
    
    # Risk
    risk = serializers.IntegerField()
    risk_explanation = serializers.ListField(child=serializers.CharField())
    risk_factors = RiskFactorsSerializer()
    
    # Time to exploit
    time_to_exploit = TimeToExploitSerializer()
    
    # Stability
    stability = serializers.IntegerField()


class AttackChainStepSerializer(serializers.Serializer):
    """Single step in an attack chain"""
    cve_id = serializers.CharField()
    stage = serializers.CharField()
    stage_order = serializers.IntegerField()
    risk = serializers.IntegerField()
    cvss = serializers.FloatField(allow_null=True)
    exploit_available = serializers.BooleanField()
    exploit_evidence = serializers.CharField()
    patch_available = serializers.BooleanField()
    description = serializers.CharField()
    affected_products = serializers.ListField(child=serializers.CharField())
    time_to_exploit = serializers.CharField()


class AttackChainSerializer(serializers.Serializer):
    """Complete attack chain"""
    chain_id = serializers.CharField()
    steps = AttackChainStepSerializer(many=True)
    length = serializers.IntegerField()
    chain_risk = serializers.IntegerField()
    chain_confidence = serializers.IntegerField()
    fully_exploitable = serializers.BooleanField()
    narrative = serializers.CharField()
    impact_summary = serializers.CharField()
    recommended_break_point = serializers.CharField()
    total_time_estimate = serializers.CharField()
    evidence_quality = serializers.CharField()


class PrioritizedActionSerializer(serializers.Serializer):
    """Prioritized remediation action"""
    rank = serializers.IntegerField()
    cve_id = serializers.CharField()
    action = serializers.CharField()
    urgency = serializers.CharField()
    reason = serializers.CharField()
    impact = serializers.CharField()
    effort = serializers.CharField()
    risk_reduction = serializers.IntegerField()
    chains_broken = serializers.IntegerField()


class SystemStatusSerializer(serializers.Serializer):
    """System security status"""
    overall = serializers.CharField()
    entry_points = serializers.IntegerField()
    full_chains = serializers.IntegerField()
    estimated_compromise = serializers.CharField()
    top_risks = serializers.ListField(child=serializers.CharField())
    attack_surface = serializers.CharField()
    recommendation = serializers.CharField()
    has_asset_context = serializers.BooleanField()
    asset_matches_found = serializers.IntegerField()
    verified_exploitable = serializers.IntegerField()
    data_quality = serializers.CharField()


class AnalyticsSerializer(serializers.Serializer):
    """System analytics"""
    totalVulnerabilities = serializers.IntegerField()
    relevantVulnerabilities = serializers.IntegerField()
    criticalCount = serializers.IntegerField()
    highCount = serializers.IntegerField()
    mediumCount = serializers.IntegerField()
    lowCount = serializers.IntegerField()
    avgCvssScore = serializers.FloatField()
    avgRisk = serializers.FloatField()
    exploitedCount = serializers.IntegerField()
    patchedCount = serializers.IntegerField()
    systemHealth = serializers.IntegerField()
    attackChainCount = serializers.IntegerField()
    connectedNodes = serializers.IntegerField()
    isolatedNodes = serializers.IntegerField()
    patchCoverage = serializers.IntegerField()
    assetCoverage = serializers.IntegerField()
    dataQuality = serializers.CharField()


class RiskPropagationSerializer(serializers.Serializer):
    """Risk propagation edge"""
    source = serializers.CharField(source='from')
    target = serializers.CharField(source='to')
    intensity = serializers.IntegerField()
    type = serializers.CharField()
    strength = serializers.CharField()
    reason = serializers.CharField()
    attack_vector = serializers.CharField()


class FullIntelligenceResponseSerializer(serializers.Serializer):
    """
    Complete intelligence response
    Use this as documentation for the API response
    """
    success = serializers.BooleanField()
    vulnerabilities = CascadeNodeSerializer(many=True)
    attack_chains = AttackChainSerializer(many=True)
    timeline = serializers.DictField()
    risk_propagation = RiskPropagationSerializer(many=True)
    analytics = AnalyticsSerializer()
    system_status = SystemStatusSerializer()
    prioritized_actions = PrioritizedActionSerializer(many=True)
    scan_duration = serializers.FloatField()
    source = serializers.CharField()
    total_processed = serializers.IntegerField()