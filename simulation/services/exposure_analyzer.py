# simulation/services/exposure_analyzer.py
"""
Exposure Analyzer Service
═══════════════════════════════════════════════════════════════
Analyzes network exposure and attack surface.

Determines:
- Internet exposure
- Network path feasibility
- Authentication requirements
- Defense layers
"""

import logging
from typing import List, Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

class ExposureLevel(Enum):
    """Network exposure classification"""
    INTERNET = 'internet'          # Directly reachable from internet
    DMZ = 'dmz'                     # In DMZ, filtered access
    INTERNAL = 'internal'           # Internal network only
    ISOLATED = 'isolated'           # Air-gapped / isolated
    UNKNOWN = 'unknown'


class AttackSurface(Enum):
    """Attack surface classification"""
    CRITICAL = 'critical'     # High exposure + critical asset
    HIGH = 'high'             # Internet-facing services
    MODERATE = 'moderate'     # Internal but accessible
    LOW = 'low'               # Limited exposure
    MINIMAL = 'minimal'       # Very limited attack surface


# Risk multipliers by exposure
EXPOSURE_RISK_MULTIPLIERS = {
    ExposureLevel.INTERNET: 1.0,
    ExposureLevel.DMZ: 0.8,
    ExposureLevel.INTERNAL: 0.5,
    ExposureLevel.ISOLATED: 0.2,
    ExposureLevel.UNKNOWN: 0.6,  # Assume moderate if unknown
}

# Common internet-facing ports
INTERNET_PORTS = {
    20, 21,      # FTP
    22,          # SSH
    23,          # Telnet
    25,          # SMTP
    53,          # DNS
    80, 443,     # HTTP/HTTPS
    110, 995,    # POP3
    143, 993,    # IMAP
    389, 636,    # LDAP
    445,         # SMB
    1433,        # MSSQL
    3306,        # MySQL
    3389,        # RDP
    5432,        # PostgreSQL
    8080, 8443,  # Alt HTTP
    27017,       # MongoDB
}

# High-value target ports
HIGH_VALUE_PORTS = {
    1433,        # MSSQL
    3306,        # MySQL
    5432,        # PostgreSQL
    27017,       # MongoDB
    6379,        # Redis
    11211,       # Memcached
    9200,        # Elasticsearch
}


# ═══════════════════════════════════════════════════════════════
# EXPOSURE ANALYZER
# ═══════════════════════════════════════════════════════════════

class ExposureAnalyzer:
    """
    Analyzes network exposure for vulnerabilities and assets
    """
    
    def __init__(self, network_config: Dict = None):
        """
        Initialize analyzer
        
        Args:
            network_config: Optional network topology configuration
                {
                    'internet_ranges': ['1.2.3.0/24'],
                    'dmz_ranges': ['10.0.1.0/24'],
                    'internal_ranges': ['192.168.0.0/16'],
                }
        """
        self.network_config = network_config or {}
    
    # ───────────────────────────────────────────────────────────
    # VULNERABILITY EXPOSURE ANALYSIS
    # ───────────────────────────────────────────────────────────
    
    def analyze_vulnerability_exposure(
        self,
        vulnerability: Dict,
        asset: Dict = None,
    ) -> Dict:
        """
        Analyze exposure level for a vulnerability
        
        Args:
            vulnerability: CVE data dict
            asset: Optional asset the vulnerability affects
        
        Returns:
            {
                'exposure_level': str,
                'attack_surface': str,
                'exposure_score': int (0-100),
                'factors': [str],
                'network_reachable': bool,
                'authentication_required': bool,
                'defense_layers': int,
                'risk_multiplier': float
            }
        """
        factors = []
        exposure_score = 0
        
        # Extract vulnerability attributes
        attack_vector = vulnerability.get('attack_vector', '').upper()
        privileges_required = vulnerability.get('privileges_required', '').upper()
        user_interaction = vulnerability.get('user_interaction', '').upper()
        scope = vulnerability.get('scope', '').upper()
        
        # ─── Determine network reachability ───
        if attack_vector == 'NETWORK':
            network_reachable = True
            exposure_score += 40
            factors.append('Network attack vector')
        elif attack_vector == 'ADJACENT':
            network_reachable = True  # Requires adjacent network
            exposure_score += 25
            factors.append('Adjacent network attack vector')
        elif attack_vector == 'LOCAL':
            network_reachable = False
            exposure_score += 15
            factors.append('Local attack vector')
        elif attack_vector == 'PHYSICAL':
            network_reachable = False
            exposure_score += 5
            factors.append('Physical attack vector')
        else:
            network_reachable = False  # Unknown = assume not
            factors.append('Unknown attack vector')
        
        # ─── Authentication requirements ───
        if privileges_required in ('NONE', ''):
            authentication_required = False
            exposure_score += 30
            factors.append('No authentication required')
        elif privileges_required == 'LOW':
            authentication_required = True
            exposure_score += 15
            factors.append('Low privileges required')
        else:  # HIGH
            authentication_required = True
            exposure_score += 5
            factors.append('High privileges required')
        
        # ─── User interaction ───
        if user_interaction in ('NONE', ''):
            exposure_score += 15
            factors.append('No user interaction required')
        else:
            exposure_score += 5
            factors.append('User interaction required')
        
        # ─── Scope impact ───
        if scope == 'CHANGED':
            exposure_score += 15
            factors.append('Scope changed (can affect other components)')
        
        # ─── Asset-based adjustments ───
        defense_layers = 0
        exposure_level = ExposureLevel.UNKNOWN
        
        if asset:
            # Check asset exposure
            if asset.get('internet_facing'):
                exposure_level = ExposureLevel.INTERNET
                exposure_score = min(100, exposure_score + 20)
                factors.append('Asset is internet-facing')
            elif asset.get('in_dmz'):
                exposure_level = ExposureLevel.DMZ
                factors.append('Asset is in DMZ')
            elif asset.get('internal'):
                exposure_level = ExposureLevel.INTERNAL
                factors.append('Asset is internal only')
            
            # Defense layers
            if asset.get('behind_firewall'):
                defense_layers += 1
            if asset.get('requires_vpn'):
                defense_layers += 1
            if asset.get('has_waf'):
                defense_layers += 1
            if asset.get('has_ids'):
                defense_layers += 1
            
            # Reduce exposure for defense layers
            exposure_score = max(0, exposure_score - (defense_layers * 5))
            if defense_layers > 0:
                factors.append(f'{defense_layers} defense layer(s) present')
        else:
            # No asset context - infer from attack vector
            if attack_vector == 'NETWORK' and privileges_required in ('NONE', ''):
                exposure_level = ExposureLevel.INTERNET  # Assume worst case
                factors.append('No asset context - assuming internet exposure')
            else:
                exposure_level = ExposureLevel.INTERNAL
        
        # ─── Determine attack surface ───
        if exposure_score >= 80:
            attack_surface = AttackSurface.CRITICAL
        elif exposure_score >= 60:
            attack_surface = AttackSurface.HIGH
        elif exposure_score >= 40:
            attack_surface = AttackSurface.MODERATE
        elif exposure_score >= 20:
            attack_surface = AttackSurface.LOW
        else:
            attack_surface = AttackSurface.MINIMAL
        
        # Risk multiplier
        risk_multiplier = EXPOSURE_RISK_MULTIPLIERS.get(
            exposure_level,
            0.6
        )
        
        return {
            'exposure_level': exposure_level.value,
            'attack_surface': attack_surface.value,
            'exposure_score': min(100, exposure_score),
            'factors': factors,
            'network_reachable': network_reachable,
            'authentication_required': authentication_required,
            'defense_layers': defense_layers,
            'risk_multiplier': risk_multiplier,
        }
    
    # ───────────────────────────────────────────────────────────
    # ASSET EXPOSURE ANALYSIS
    # ───────────────────────────────────────────────────────────
    
    def analyze_asset_exposure(self, asset: Dict) -> Dict:
        """
        Analyze exposure for a specific asset
        
        Args:
            asset: Asset inventory dict
        
        Returns:
            Exposure analysis result
        """
        factors = []
        exposure_score = 0
        
        services = asset.get('services', [])
        ip = asset.get('ip_address', '')
        
        # ─── Check for internet-facing indicators ───
        internet_facing = asset.get('internet_facing', False)
        
        if not internet_facing:
            # Infer from IP
            if not self._is_private_ip(ip):
                internet_facing = True
                factors.append('Public IP address')
        
        if internet_facing:
            exposure_score += 50
            factors.append('Internet-facing asset')
        
        # ─── Analyze services ───
        open_internet_ports = []
        high_value_services = []
        
        for svc in services:
            port = svc.get('port')
            
            if port in INTERNET_PORTS:
                open_internet_ports.append(port)
            
            if port in HIGH_VALUE_PORTS:
                high_value_services.append(svc.get('service', f'port {port}'))
        
        if open_internet_ports:
            exposure_score += min(30, len(open_internet_ports) * 5)
            factors.append(f'{len(open_internet_ports)} common ports open')
        
        if high_value_services:
            exposure_score += 20
            factors.append(f'High-value services: {", ".join(high_value_services[:3])}')
        
        # ─── Defense posture ───
        defense_layers = 0
        
        if asset.get('behind_firewall'):
            defense_layers += 1
            exposure_score -= 10
        
        if asset.get('requires_vpn'):
            defense_layers += 1
            exposure_score -= 15
        
        # ─── Classification ───
        exposure_score = max(0, min(100, exposure_score))
        
        if exposure_score >= 70:
            exposure_level = ExposureLevel.INTERNET
            attack_surface = AttackSurface.HIGH
        elif exposure_score >= 50:
            exposure_level = ExposureLevel.DMZ
            attack_surface = AttackSurface.MODERATE
        elif exposure_score >= 30:
            exposure_level = ExposureLevel.INTERNAL
            attack_surface = AttackSurface.LOW
        else:
            exposure_level = ExposureLevel.ISOLATED
            attack_surface = AttackSurface.MINIMAL
        
        return {
            'asset_id': asset.get('id'),
            'hostname': asset.get('hostname'),
            'exposure_level': exposure_level.value,
            'attack_surface': attack_surface.value,
            'exposure_score': exposure_score,
            'factors': factors,
            'internet_facing': internet_facing,
            'open_ports': open_internet_ports,
            'high_value_services': high_value_services,
            'defense_layers': defense_layers,
        }
    
    # ───────────────────────────────────────────────────────────
    # ATTACK PATH FEASIBILITY
    # ───────────────────────────────────────────────────────────
    
    def assess_attack_path_feasibility(
        self,
        source_asset: Dict,
        target_asset: Dict,
        vulnerability: Dict = None,
    ) -> Dict:
        """
        Assess whether attack can traverse from source to target
        
        Returns:
            {
                'feasible': bool,
                'confidence': int,
                'path_type': str,
                'barriers': [str],
                'requirements': [str]
            }
        """
        barriers = []
        requirements = []
        feasible = True
        confidence = 100
        
        # Check network segmentation
        source_segment = source_asset.get('network_segment', 'unknown')
        target_segment = target_asset.get('network_segment', 'unknown')
        
        if source_segment != target_segment:
            if target_asset.get('isolated'):
                barriers.append('Target is in isolated network')
                feasible = False
                confidence = 10
            elif target_asset.get('requires_vpn') and not source_asset.get('has_vpn_access'):
                barriers.append('VPN required to reach target')
                requirements.append('VPN access')
                confidence -= 30
        
        # Check firewall rules (if known)
        if target_asset.get('behind_firewall'):
            barriers.append('Target behind firewall')
            confidence -= 20
        
        # Check if vulnerability allows lateral movement
        if vulnerability:
            attack_vector = vulnerability.get('attack_vector', '').upper()
            
            if attack_vector == 'LOCAL':
                barriers.append('Vulnerability requires local access')
                requirements.append('Local code execution on target')
                confidence -= 40
            elif attack_vector == 'PHYSICAL':
                barriers.append('Vulnerability requires physical access')
                feasible = False
                confidence = 5
        
        # Determine path type
        if source_asset.get('internet_facing') and target_asset.get('internal'):
            path_type = 'external_to_internal'
        elif source_asset.get('internal') and target_asset.get('internal'):
            path_type = 'lateral'
        else:
            path_type = 'unknown'
        
        return {
            'feasible': feasible,
            'confidence': max(0, confidence),
            'path_type': path_type,
            'barriers': barriers,
            'requirements': requirements,
        }
    
    # ───────────────────────────────────────────────────────────
    # AGGREGATE ANALYSIS
    # ───────────────────────────────────────────────────────────
    
    def analyze_attack_surface(
        self,
        vulnerabilities: List[Dict],
        assets: List[Dict] = None,
    ) -> Dict:
        """
        Aggregate attack surface analysis
        
        Returns:
            {
                'overall_exposure': str,
                'exposure_score': int,
                'internet_entry_points': int,
                'critical_assets_exposed': int,
                'recommendations': [str]
            }
        """
        internet_entries = 0
        critical_exposed = 0
        total_exposure = 0
        
        for vuln in vulnerabilities:
            exposure = self.analyze_vulnerability_exposure(vuln)
            
            if exposure['exposure_level'] == 'internet':
                internet_entries += 1
            
            total_exposure += exposure['exposure_score']
        
        # Analyze assets
        if assets:
            for asset in assets:
                if asset.get('criticality') in ('critical', 'high'):
                    asset_exposure = self.analyze_asset_exposure(asset)
                    if asset_exposure['exposure_level'] == 'internet':
                        critical_exposed += 1
        
        # Average exposure
        avg_exposure = total_exposure // len(vulnerabilities) if vulnerabilities else 0
        
        # Determine overall
        if avg_exposure >= 70 or internet_entries > 5:
            overall = 'critical'
        elif avg_exposure >= 50 or internet_entries > 2:
            overall = 'high'
        elif avg_exposure >= 30:
            overall = 'moderate'
        else:
            overall = 'low'
        
        # Recommendations
        recommendations = []
        
        if internet_entries > 0:
            recommendations.append(
                f"Review {internet_entries} internet-exposed vulnerabilities"
            )
        
        if critical_exposed > 0:
            recommendations.append(
                f"Protect {critical_exposed} critical assets with internet exposure"
            )
        
        if avg_exposure > 50:
            recommendations.append("Consider network segmentation to reduce exposure")
        
        return {
            'overall_exposure': overall,
            'exposure_score': avg_exposure,
            'internet_entry_points': internet_entries,
            'critical_assets_exposed': critical_exposed,
            'recommendations': recommendations,
        }
    
    # ───────────────────────────────────────────────────────────
    # UTILITY METHODS
    # ───────────────────────────────────────────────────────────
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        if not ip:
            return True  # Assume private if unknown
        
        private_prefixes = [
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',
            '127.',
        ]
        
        return any(ip.startswith(prefix) for prefix in private_prefixes)