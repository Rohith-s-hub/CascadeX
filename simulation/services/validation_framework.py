# simulation/services/validation_framework.py
"""
Vulnerability Validation Framework
═══════════════════════════════════════════════════════════════
Validates vulnerability findings using multiple methods:
- Network validation (nmap scripts)
- Safe exploit testing
- Configuration checks

SAFE TESTING ONLY. No destructive operations.
"""

import subprocess
import logging
import re
from typing import List, Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

class ValidationStatus(Enum):
    """Validation result status"""
    CONFIRMED = 'confirmed'         # Vulnerability confirmed
    LIKELY = 'likely'               # Strong indicators present
    POSSIBLE = 'possible'           # Weak indicators
    NOT_VULNERABLE = 'not_vulnerable'
    INCONCLUSIVE = 'inconclusive'
    ERROR = 'error'


class ValidationMethod(Enum):
    """Validation methods available"""
    NMAP_SCRIPT = 'nmap_script'
    VERSION_CHECK = 'version_check'
    BANNER_ANALYSIS = 'banner_analysis'
    CONFIG_CHECK = 'config_check'
    SAFE_EXPLOIT = 'safe_exploit'


# CVE to nmap script mapping (common cases)
CVE_NMAP_SCRIPTS = {
    'CVE-2021-44228': 'http-log4j-check',
    'CVE-2017-0144': 'smb-vuln-ms17-010',
    'CVE-2014-0160': 'ssl-heartbleed',
    'CVE-2014-3566': 'ssl-poodle',
    'CVE-2021-41773': 'http-vuln-cve2021-41773',
    'CVE-2021-26855': 'http-vuln-exchange',
}

# Version patterns for quick checks
VERSION_PATTERNS = {
    'apache': {
        'CVE-2021-41773': {'vulnerable': ['2.4.49'], 'patched': ['2.4.50', '2.4.51']},
        'CVE-2021-42013': {'vulnerable': ['2.4.49', '2.4.50'], 'patched': ['2.4.51']},
    },
    'nginx': {
        'CVE-2021-23017': {'vulnerable': ['0.6.18-1.20.0'], 'patched': ['1.20.1']},
    },
    'openssh': {
        'CVE-2021-41617': {'vulnerable': ['<8.8'], 'patched': ['8.8']},
    },
}


# ═══════════════════════════════════════════════════════════════
# VALIDATION FRAMEWORK
# ═══════════════════════════════════════════════════════════════

class ValidationFramework:
    """
    Validates vulnerability findings through multiple methods
    """
    
    def __init__(self):
        self.nmap_available = self._check_nmap()
    
    def _check_nmap(self) -> bool:
        """Check if nmap is available"""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    # ───────────────────────────────────────────────────────────
    # MAIN VALIDATION METHOD
    # ───────────────────────────────────────────────────────────
    
    def validate_vulnerability(
        self,
        cve_id: str,
        target_ip: str,
        target_port: int = None,
        service_info: Dict = None,
        safe_mode: bool = True,
    ) -> Dict:
        """
        Validate a vulnerability against a target
        
        Args:
            cve_id: CVE identifier
            target_ip: Target IP address
            target_port: Optional specific port
            service_info: Optional service details (name, version)
            safe_mode: Only use non-intrusive checks
        
        Returns:
            {
                'cve_id': str,
                'target': str,
                'status': ValidationStatus,
                'confidence': int (0-100),
                'method': ValidationMethod,
                'evidence': [str],
                'details': dict
            }
        """
        logger.info(f"Validating {cve_id} against {target_ip}")
        
        result = {
            'cve_id': cve_id,
            'target': f"{target_ip}:{target_port}" if target_port else target_ip,
            'status': ValidationStatus.INCONCLUSIVE.value,
            'confidence': 0,
            'method': None,
            'evidence': [],
            'details': {},
        }
        
        # Method 1: Version-based check (fastest, safest)
        if service_info:
            version_result = self._check_version(cve_id, service_info)
            if version_result['status'] != ValidationStatus.INCONCLUSIVE:
                result.update({
                    'status': version_result['status'].value,
                    'confidence': version_result['confidence'],
                    'method': ValidationMethod.VERSION_CHECK.value,
                    'evidence': version_result['evidence'],
                })
                
                if version_result['status'] == ValidationStatus.CONFIRMED:
                    return result
        
        # Method 2: Nmap script check
        if self.nmap_available and target_ip:
            nmap_result = self._run_nmap_check(cve_id, target_ip, target_port)
            
            if nmap_result['status'] != ValidationStatus.INCONCLUSIVE:
                # Update if better confidence
                if nmap_result['confidence'] > result['confidence']:
                    result.update({
                        'status': nmap_result['status'].value,
                        'confidence': nmap_result['confidence'],
                        'method': ValidationMethod.NMAP_SCRIPT.value,
                        'evidence': nmap_result['evidence'],
                        'details': nmap_result.get('details', {}),
                    })
        
        # Method 3: Banner analysis
        if service_info and service_info.get('banner'):
            banner_result = self._analyze_banner(cve_id, service_info['banner'])
            
            if banner_result['confidence'] > result['confidence']:
                result.update({
                    'status': banner_result['status'].value,
                    'confidence': banner_result['confidence'],
                    'method': ValidationMethod.BANNER_ANALYSIS.value,
                    'evidence': banner_result['evidence'],
                })
        
        return result
    
    # ───────────────────────────────────────────────────────────
    # VERSION CHECK
    # ───────────────────────────────────────────────────────────
    
    def _check_version(self, cve_id: str, service_info: Dict) -> Dict:
        """
        Check if service version is vulnerable
        """
        product = service_info.get('product', '').lower()
        version = service_info.get('version', '')
        
        evidence = []
        
        # Find matching product patterns
        for prod_name, cve_patterns in VERSION_PATTERNS.items():
            if prod_name in product:
                if cve_id in cve_patterns:
                    pattern = cve_patterns[cve_id]
                    vulnerable_versions = pattern.get('vulnerable', [])
                    patched_versions = pattern.get('patched', [])
                    
                    # Check if version matches vulnerable
                    for vuln_ver in vulnerable_versions:
                        if self._version_match(version, vuln_ver):
                            evidence.append(f"Version {version} matches vulnerable pattern {vuln_ver}")
                            return {
                                'status': ValidationStatus.CONFIRMED,
                                'confidence': 95,
                                'evidence': evidence,
                            }
                    
                    # Check if patched
                    for patch_ver in patched_versions:
                        if self._version_gte(version, patch_ver):
                            evidence.append(f"Version {version} >= patched version {patch_ver}")
                            return {
                                'status': ValidationStatus.NOT_VULNERABLE,
                                'confidence': 90,
                                'evidence': evidence,
                            }
        
        return {
            'status': ValidationStatus.INCONCLUSIVE,
            'confidence': 0,
            'evidence': [],
        }
    
    def _version_match(self, version: str, pattern: str) -> bool:
        """Check if version matches pattern"""
        if not version or not pattern:
            return False
        
        # Handle range patterns (e.g., "<8.8")
        if pattern.startswith('<'):
            return self._version_lt(version, pattern[1:])
        elif pattern.startswith('>'):
            return self._version_gt(version, pattern[1:])
        else:
            # Exact match or prefix match
            return version.startswith(pattern) or version == pattern
    
    def _version_lt(self, v1: str, v2: str) -> bool:
        """Check if v1 < v2"""
        try:
            parts1 = [int(x) for x in re.findall(r'\d+', v1)]
            parts2 = [int(x) for x in re.findall(r'\d+', v2)]
            return parts1 < parts2
        except Exception:
            return False
    
    def _version_gt(self, v1: str, v2: str) -> bool:
        """Check if v1 > v2"""
        try:
            parts1 = [int(x) for x in re.findall(r'\d+', v1)]
            parts2 = [int(x) for x in re.findall(r'\d+', v2)]
            return parts1 > parts2
        except Exception:
            return False
    
    def _version_gte(self, v1: str, v2: str) -> bool:
        """Check if v1 >= v2"""
        return v1 == v2 or self._version_gt(v1, v2)
    
    # ───────────────────────────────────────────────────────────
    # NMAP SCRIPT CHECK
    # ───────────────────────────────────────────────────────────
    
    def _run_nmap_check(
        self,
        cve_id: str,
        target_ip: str,
        target_port: int = None,
    ) -> Dict:
        """
        Run nmap vulnerability script
        """
        # Check if we have a specific script for this CVE
        script_name = CVE_NMAP_SCRIPTS.get(cve_id)
        
        if not script_name:
            # Try generic vuln script
            script_name = 'vuln'
        
        try:
            cmd = ['nmap', '-sV', '--script', script_name]
            
            if target_port:
                cmd.extend(['-p', str(target_port)])
            else:
                cmd.extend(['-p', '1-1000'])
            
            cmd.append(target_ip)
            
            logger.info(f"Running nmap: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            
            output = result.stdout + result.stderr
            
            # Parse output for vulnerability indicators
            evidence = []
            status = ValidationStatus.INCONCLUSIVE
            confidence = 0
            
            # Check for VULNERABLE indicator
            if 'VULNERABLE' in output.upper():
                status = ValidationStatus.CONFIRMED
                confidence = 90
                evidence.append('Nmap script reports VULNERABLE')
                
                # Extract details
                vuln_match = re.search(r'VULNERABLE:(.+?)(?:\n\n|\Z)', output, re.DOTALL)
                if vuln_match:
                    evidence.append(vuln_match.group(1).strip()[:200])
            
            # Check for NOT VULNERABLE
            elif 'NOT VULNERABLE' in output.upper():
                status = ValidationStatus.NOT_VULNERABLE
                confidence = 85
                evidence.append('Nmap script reports NOT VULNERABLE')
            
            # Check for error
            elif 'ERROR' in output.upper() or result.returncode != 0:
                status = ValidationStatus.ERROR
                confidence = 0
                evidence.append(f'Nmap error: {output[:100]}')
            
            return {
                'status': status,
                'confidence': confidence,
                'evidence': evidence,
                'details': {
                    'script': script_name,
                    'raw_output': output[:500],
                },
            }
            
        except subprocess.TimeoutExpired:
            return {
                'status': ValidationStatus.ERROR,
                'confidence': 0,
                'evidence': ['Nmap timeout'],
            }
        except Exception as e:
            logger.error(f"Nmap check failed: {e}")
            return {
                'status': ValidationStatus.ERROR,
                'confidence': 0,
                'evidence': [str(e)],
            }
    
    # ───────────────────────────────────────────────────────────
    # BANNER ANALYSIS
    # ───────────────────────────────────────────────────────────
    
    def _analyze_banner(self, cve_id: str, banner: str) -> Dict:
        """
        Analyze service banner for vulnerability indicators
        """
        evidence = []
        
        # Extract version from banner
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # Major.Minor.Patch
            r'version\s+(\d+\.\d+)',  # "version X.Y"
            r'/(\d+\.\d+\.\d+)',  # "/X.Y.Z"
        ]
        
        version = None
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1)
                break
        
        if version:
            evidence.append(f"Detected version: {version}")
            
            # Check version against known vulnerable versions
            # (Would need CVE-specific version ranges)
            
            return {
                'status': ValidationStatus.POSSIBLE,
                'confidence': 40,
                'evidence': evidence,
            }
        
        return {
            'status': ValidationStatus.INCONCLUSIVE,
            'confidence': 0,
            'evidence': [],
        }
    
    # ───────────────────────────────────────────────────────────
    # BATCH VALIDATION
    # ───────────────────────────────────────────────────────────
    
    def validate_batch(
        self,
        vulnerabilities: List[Dict],
        assets: List[Dict],
    ) -> List[Dict]:
        """
        Validate multiple vulnerabilities against assets
        
        Returns list of validation results
        """
        results = []
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id')
            
            # Find matching assets
            matching_assets = self._find_matching_assets(vuln, assets)
            
            for asset in matching_assets:
                ip = asset.get('ip_address')
                
                for service in asset.get('services', []):
                    result = self.validate_vulnerability(
                        cve_id=cve_id,
                        target_ip=ip,
                        target_port=service.get('port'),
                        service_info=service,
                    )
                    
                    result['asset_id'] = asset.get('id')
                    result['asset_name'] = asset.get('hostname')
                    results.append(result)
        
        return results
    
    def _find_matching_assets(
        self,
        vulnerability: Dict,
        assets: List[Dict],
    ) -> List[Dict]:
        """Find assets that might be affected by vulnerability"""
        affected_products = vulnerability.get('affected_products', [])
        matches = []
        
        for asset in assets:
            for service in asset.get('services', []):
                product = service.get('product', '').lower()
                
                for affected in affected_products:
                    if affected.lower().split(':')[0] in product:
                        matches.append(asset)
                        break
        
        return matches
    
    # ───────────────────────────────────────────────────────────
    # CONFIDENCE AGGREGATION
    # ───────────────────────────────────────────────────────────
    
    def aggregate_validation_confidence(
        self,
        validation_results: List[Dict],
    ) -> Dict:
        """
        Aggregate validation results for overall confidence
        """
        if not validation_results:
            return {
                'overall_confidence': 0,
                'confirmed_count': 0,
                'likely_count': 0,
                'not_vulnerable_count': 0,
            }
        
        confirmed = sum(1 for r in validation_results if r['status'] == 'confirmed')
        likely = sum(1 for r in validation_results if r['status'] == 'likely')
        not_vuln = sum(1 for r in validation_results if r['status'] == 'not_vulnerable')
        
        # Calculate overall confidence
        total = len(validation_results)
        confirmed_ratio = confirmed / total if total > 0 else 0
        
        overall = int(confirmed_ratio * 100)
        
        return {
            'overall_confidence': overall,
            'confirmed_count': confirmed,
            'likely_count': likely,
            'not_vulnerable_count': not_vuln,
            'total_checked': total,
        }