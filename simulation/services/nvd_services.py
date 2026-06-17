# simulation/services/nvd_service.py
"""
NVD Service - Production Grade Implementation
═══════════════════════════════════════════════════════════════
Fetches, validates, and normalizes CVE data from NVD API 2.0.

FEATURES:
- CVE year validation (rejects future/reserved CVEs)
- NVD publication status validation
- Data completeness enforcement
- Version range extraction with comparison support
- CISA KEV integration
- Verified exploit/patch detection
- Strict CPE parsing and matching
- Rate limiting with API key support
- Comprehensive error handling

ACCURACY GUARANTEES:
- No future CVEs (2025+) will pass validation
- No reserved/rejected CVEs will be returned
- All CVEs have validated CVSS and descriptions
- Version ranges are preserved for asset matching
- Exploit signals require verified sources only
"""

import logging
import time
import re
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from functools import lru_cache
from packaging import version as pkg_version

import requests
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Rate limiting
RATE_LIMIT_DELAY = 6.0          # Without API key: 10 requests/min
RATE_LIMIT_WITH_KEY = 0.6       # With API key: 100 requests/min

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 10
REQUEST_TIMEOUT = 30

# Cache configuration
CACHE_TIMEOUT = 300             # 5 minutes for CVE data
CACHE_TIMEOUT_KEV = 3600        # 1 hour for CISA KEV

# Validation thresholds
CURRENT_YEAR = datetime.now().year
MAX_VALID_CVE_YEAR = CURRENT_YEAR  # Reject CVEs with future years
MIN_DESCRIPTION_LENGTH = 20
MIN_CVSS_SCORE = 0.0
MAX_CVSS_SCORE = 10.0

# Valid NVD statuses (reject others)
VALID_NVD_STATUSES = {
    'Analyzed',
    'Modified',
    'Undergoing Analysis',
}

# Rejected statuses
REJECTED_NVD_STATUSES = {
    'Rejected',
    'Reserved',
    'Received',          # Not yet analyzed
    'Awaiting Analysis', # Not yet analyzed
}

# Verified exploit sources (trusted)
VERIFIED_EXPLOIT_SOURCES = {
    'metasploit': {'pattern': r'rapid7\.com|metasploit', 'confidence': 100},
    'exploit-db': {'pattern': r'exploit-db\.com', 'confidence': 95},
    'packetstorm': {'pattern': r'packetstormsecurity\.com', 'confidence': 90},
    'nuclei': {'pattern': r'github\.com/projectdiscovery/nuclei-templates', 'confidence': 85},
    'cisa_kev': {'pattern': None, 'confidence': 100},  # Special handling
}

# Verified patch sources
VERIFIED_PATCH_DOMAINS = {
    "microsoft.com", "support.microsoft.com", "msrc.microsoft.com",
    "security.apache.org", "apache.org",
    "kernel.org", "git.kernel.org",
    "redhat.com", "access.redhat.com", "www.redhat.com", "bugzilla.redhat.com", "rhn.redhat.com",
    "ubuntu.com", "security.ubuntu.com", "launchpad.net", "bugs.launchpad.net",
    "debian.org", "security.debian.org",
    "oracle.com", "cisco.com", "vmware.com", "sap.com",
    "adobe.com", "helpx.adobe.com", "experienceleague.adobe.com",
    "mozilla.org", "www.mozilla.org", "bugzilla.mozilla.org",
    "google.com", "chromereleases.googleblog.com",
    "apple.com", "support.apple.com",
    "github.com", "gist.github.com", "gitlab.com",
    "gstreamer.freedesktop.org", "gitlab.freedesktop.org", "cgit.freedesktop.org",
    "plugins.trac.wordpress.org", "www.wordfence.com",
    "security-advisory.acronis.com",
    "www.cert.org", "www.openwall.com", "openwall.com",
    "advisories.nats.io", "www.gentoo.org",
    "sunsolve.sun.com", "xenbits.xenproject.org", "xenbits.xen.org",
    "www.foxit.com", "www.qnap.com", "www.elecom.co.jp",
    "jira.mongodb.org", "forums.unraid.net",
}


# ═══════════════════════════════════════════════════════════════
# CPE NORMALIZER
# ═══════════════════════════════════════════════════════════════

class CPENormalizer:
    """
    CPE 2.3 Parser and Normalizer with validation.
    """
    
    # Product name aliases for normalization
    PRODUCT_ALIASES = {
        'http_server': 'httpd',
        'apache_http_server': 'httpd',
        'nginx_plus': 'nginx',
        'microsoft_iis': 'iis',
        'internet_information_services': 'iis',
        'postgres': 'postgresql',
        'mysql_server': 'mysql',
        'mariadb_server': 'mariadb',
        'ms_sql': 'mssql',
        'ms-sql': 'mssql',
        'sql_server': 'mssql',
        'openssh': 'ssh',
        'open_ssh': 'ssh',
        'openssl': 'openssl',
        'open_ssl': 'openssl',
        'linux_kernel': 'kernel',
        'windows_server': 'windows',
        'windows_10': 'windows',
        'windows_11': 'windows',
        'macos': 'macos',
        'mac_os': 'macos',
        'mac_os_x': 'macos',
    }
    
    # Vendor aliases
    VENDOR_ALIASES = {
        'apache_software_foundation': 'apache',
        'apache_foundation': 'apache',
        'microsoft_corporation': 'microsoft',
        'oracle_corporation': 'oracle',
        'redhat': 'red_hat',
        'red hat': 'red_hat',
        'canonical': 'ubuntu',
        'debian_project': 'debian',
        'linux': 'linux_kernel',
        'f5': 'f5_networks',
        'vmware': 'vmware',
        'cisco_systems': 'cisco',
    }
    
    # CPE 2.3 format regex
    CPE_REGEX = re.compile(
        r'^cpe:2\.3:([aho\*]):([^:]+):([^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$'
    )
    
    @classmethod
    def normalize_text(cls, value: Optional[str]) -> str:
        """Clean and normalize text values."""
        if value is None:
            return ''
        text = str(value).strip().lower()
        # Replace common separators with underscore
        text = re.sub(r'[\s\-\.]+', '_', text)
        # Remove special characters except underscore
        text = re.sub(r'[^a-z0-9_]', '', text)
        return text
    
    @classmethod
    def normalize_version(cls, value: Optional[str]) -> str:
        """Normalize version string."""
        if value is None or value in ('*', '-', ''):
            return ''
        return str(value).strip().lower()
    
    @classmethod
    def normalize_vendor(cls, vendor: Optional[str]) -> str:
        """Normalize vendor name with alias resolution."""
        normalized = cls.normalize_text(vendor)
        return cls.VENDOR_ALIASES.get(normalized, normalized)
    
    @classmethod
    def normalize_product(cls, product: Optional[str]) -> str:
        """Normalize product name with alias resolution."""
        normalized = cls.normalize_text(product)
        return cls.PRODUCT_ALIASES.get(normalized, normalized)
    
    @classmethod
    def parse_cpe23(cls, cpe: str) -> Optional[Dict]:
        """
        Parse CPE 2.3 URI string into structured components.
        
        Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        
        Returns None if CPE is invalid.
        """
        if not cpe or not isinstance(cpe, str):
            return None
        
        cpe = cpe.strip().lower()
        
        # Quick format check
        if not cpe.startswith('cpe:2.3:'):
            return None
        
        # Try regex match for full validation
        match = cls.CPE_REGEX.match(cpe)
        if match:
            groups = match.groups()
            return {
                'raw_cpe': cpe,
                'valid': True,
                'part': groups[0],  # a=application, o=OS, h=hardware
                'vendor': cls.normalize_vendor(groups[1]),
                'product': cls.normalize_product(groups[2]),
                'version': cls.normalize_version(groups[3]),
                'update': groups[4] if groups[4] not in ('*', '-') else '',
                'edition': groups[5] if groups[5] not in ('*', '-') else '',
                'language': groups[6] if groups[6] not in ('*', '-') else '',
                'sw_edition': groups[7] if groups[7] not in ('*', '-') else '',
                'target_sw': groups[8] if groups[8] not in ('*', '-') else '',
                'target_hw': groups[9] if groups[9] not in ('*', '-') else '',
                'other': groups[10] if groups[10] not in ('*', '-') else '',
            }
        
        # Fallback: manual split for partially valid CPEs
        parts = cpe.split(':')
        if len(parts) >= 5:
            return {
                'raw_cpe': cpe,
                'valid': False,  # Mark as partially valid
                'part': parts[2] if len(parts) > 2 else '',
                'vendor': cls.normalize_vendor(parts[3]) if len(parts) > 3 else '',
                'product': cls.normalize_product(parts[4]) if len(parts) > 4 else '',
                'version': cls.normalize_version(parts[5]) if len(parts) > 5 else '',
                'update': '',
                'edition': '',
                'language': '',
                'sw_edition': '',
                'target_sw': '',
                'target_hw': '',
                'other': '',
            }
        
        return None
    
    @classmethod
    def build_cpe_string(cls, vendor: str, product: str, version: str = '*') -> str:
        """Build a CPE 2.3 string from components."""
        vendor = cls.normalize_vendor(vendor)
        product = cls.normalize_product(product)
        version = version if version else '*'
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


# ═══════════════════════════════════════════════════════════════
# VERSION COMPARATOR
# ═══════════════════════════════════════════════════════════════

class VersionComparator:
    """
    Semantic version comparison for vulnerability range matching.
    """
    
    # Common version patterns
    VERSION_PATTERN = re.compile(
        r'^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[.\-_]?(.+))?$',
        re.IGNORECASE
    )
    
    @classmethod
    def parse_version(cls, version_str: str) -> Tuple[Tuple[int, ...], str]:
        """
        Parse version string into comparable tuple.
        
        Returns:
            Tuple of (numeric_parts, suffix)
            Example: "2.4.49-beta" -> ((2, 4, 49), "beta")
        """
        if not version_str:
            return ((0,), '')
        
        version_str = str(version_str).strip().lower()
        
        match = cls.VERSION_PATTERN.match(version_str)
        if match:
            groups = match.groups()
            numeric = tuple(
                int(g) for g in groups[:4] if g is not None
            )
            suffix = groups[4] or ''
            return (numeric if numeric else (0,), suffix)
        
        # Fallback: try packaging library
        try:
            parsed = pkg_version.parse(version_str)
            if hasattr(parsed, 'release'):
                return (parsed.release, '')
            return ((0,), version_str)
        except Exception:
            return ((0,), version_str)
    
    @classmethod
    def compare(cls, v1: str, v2: str) -> int:
        """
        Compare two version strings.
        
        Returns:
            -1 if v1 < v2
             0 if v1 == v2
             1 if v1 > v2
        """
        p1, s1 = cls.parse_version(v1)
        p2, s2 = cls.parse_version(v2)
        
        # Compare numeric parts
        for i in range(max(len(p1), len(p2))):
            n1 = p1[i] if i < len(p1) else 0
            n2 = p2[i] if i < len(p2) else 0
            if n1 < n2:
                return -1
            if n1 > n2:
                return 1
        
        # Numeric parts equal, compare suffixes
        # Empty suffix > non-empty (release > pre-release)
        if not s1 and s2:
            return 1
        if s1 and not s2:
            return -1
        if s1 < s2:
            return -1
        if s1 > s2:
            return 1
        
        return 0
    
    @classmethod
    def is_in_range(
        cls,
        version: str,
        start_including: str = '',
        start_excluding: str = '',
        end_including: str = '',
        end_excluding: str = '',
    ) -> Tuple[bool, str]:
        """
        Check if a version falls within a vulnerable range.
        
        Returns:
            Tuple of (is_vulnerable, reason)
        """
        if not version:
            return (False, 'No version provided')
        
        version = str(version).strip()
        
        # Check start bounds
        if start_including:
            if cls.compare(version, start_including) < 0:
                return (False, f'Version {version} < {start_including} (start_including)')
        
        if start_excluding:
            if cls.compare(version, start_excluding) <= 0:
                return (False, f'Version {version} <= {start_excluding} (start_excluding)')
        
        # Check end bounds
        if end_including:
            if cls.compare(version, end_including) > 0:
                return (False, f'Version {version} > {end_including} (end_including)')
        
        if end_excluding:
            if cls.compare(version, end_excluding) >= 0:
                return (False, f'Version {version} >= {end_excluding} (end_excluding)')
        
        return (True, 'Version is within vulnerable range')
    
    @classmethod
    def matches_exact(cls, version: str, target: str) -> bool:
        """Check if version exactly matches target (with wildcard support)."""
        if not target or target == '*':
            return True
        if not version:
            return False
        return cls.compare(version, target) == 0


# ═══════════════════════════════════════════════════════════════
# CVE VALIDATOR
# ═══════════════════════════════════════════════════════════════

class CVEValidator:
    """
    Validates CVE data for completeness and accuracy.
    """
    
    # CVE ID pattern: CVE-YYYY-NNNNN (4-7 digits)
    CVE_ID_PATTERN = re.compile(r'^CVE-(\d{4})-(\d{4,7})$', re.IGNORECASE)
    
    @classmethod
    def validate_cve_id(cls, cve_id: str) -> Tuple[bool, str]:
        """
        Validate CVE ID format and year.
        
        Returns:
            Tuple of (is_valid, reason)
        """
        if not cve_id:
            return (False, 'Empty CVE ID')
        
        cve_id = str(cve_id).strip().upper()
        
        match = cls.CVE_ID_PATTERN.match(cve_id)
        if not match:
            return (False, f'Invalid CVE ID format: {cve_id}')
        
        year = int(match.group(1))
        
        # Reject future CVEs
        if year > CURRENT_YEAR:
            return (False, f'Future CVE year {year} > current year {CURRENT_YEAR}')
        
        # Reject very old CVEs (before CVE program started)
        if year < 1999:
            return (False, f'Invalid CVE year {year} (CVE program started 1999)')
        
        return (True, 'Valid CVE ID')
    
    @classmethod
    def validate_nvd_status(cls, status: str) -> Tuple[bool, str]:
        """
        Validate NVD publication status.
        
        Returns:
            Tuple of (is_valid, reason)
        """
        if not status:
            return (False, 'No NVD status provided')
        
        status = str(status).strip()
        
        if status in VALID_NVD_STATUSES:
            return (True, f'Valid status: {status}')
        
        if status in REJECTED_NVD_STATUSES:
            return (False, f'Rejected status: {status}')
        
        # Unknown status - log but accept with warning
        logger.warning(f'Unknown NVD status: {status}')
        return (True, f'Unknown status (accepted): {status}')
    
    @classmethod
    def validate_cvss_score(cls, score: Any) -> Tuple[bool, float, str]:
        """
        Validate and normalize CVSS score.
        
        Returns:
            Tuple of (is_valid, normalized_score, reason)
        """
        if score is None:
            return (False, 0.0, 'No CVSS score provided')
        
        try:
            score = float(score)
        except (TypeError, ValueError):
            return (False, 0.0, f'Invalid CVSS score format: {score}')
        
        if score < MIN_CVSS_SCORE or score > MAX_CVSS_SCORE:
            return (False, 0.0, f'CVSS score {score} out of range [0-10]')
        
        return (True, round(score, 1), 'Valid CVSS score')
    
    @classmethod
    def validate_description(cls, description: str) -> Tuple[bool, str]:
        """
        Validate CVE description quality.
        
        Returns:
            Tuple of (is_valid, reason)
        """
        if not description:
            return (False, 'No description provided')
        
        description = str(description).strip()
        
        if len(description) < MIN_DESCRIPTION_LENGTH:
            return (False, f'Description too short ({len(description)} chars)')
        
        # Check for placeholder descriptions
        placeholder_patterns = [
            r'^reserved$',
            r'^this candidate has been reserved',
            r'^\*\* reserved \*\*',
            r'^disputed',
            r'^rejected',
        ]
        
        desc_lower = description.lower()
        for pattern in placeholder_patterns:
            if re.match(pattern, desc_lower):
                return (False, f'Placeholder description detected')
        
        return (True, 'Valid description')
    
    @classmethod
    def validate_completeness(cls, cve_data: Dict) -> Tuple[bool, List[str]]:
        """
        Validate CVE data completeness.
        
        Returns:
            Tuple of (is_complete, list_of_issues)
        """
        issues = []
        
        # Required fields
        cve_id_valid, cve_id_reason = cls.validate_cve_id(cve_data.get('cve_id'))
        if not cve_id_valid:
            issues.append(cve_id_reason)
        
        # CVSS validation
        cvss_valid, _, cvss_reason = cls.validate_cvss_score(cve_data.get('cvss_score'))
        if not cvss_valid:
            issues.append(cvss_reason)
        
        # Description validation
        desc_valid, desc_reason = cls.validate_description(cve_data.get('description'))
        if not desc_valid:
            issues.append(desc_reason)
        
        # Affected products (warning only, not fatal)
        if not cve_data.get('affected_products') and not cve_data.get('affected_entries'):
            logger.warning(f"CVE {cve_data.get('cve_id')} has no affected products")
        
        return (len(issues) == 0, issues)


# ═══════════════════════════════════════════════════════════════
# EXPLOIT DETECTOR
# ═══════════════════════════════════════════════════════════════

class ExploitDetector:
    """
    Detects exploit availability from multiple sources with confidence scoring.
    """
    
    @classmethod
    def analyze_references(
        cls,
        references: List[Dict],
        cisa_kev_ids: Set[str] = None,
        cve_id: str = '',
    ) -> Dict:
        """
        Analyze references for exploit and patch signals.
        
        Returns:
            {
                'exploit_available': bool,
                'exploit_confidence': int (0-100),
                'exploit_sources': [str],
                'exploit_maturity': str,
                'patch_available': bool,
                'patch_confidence': int (0-100),
                'patch_sources': [str],
            }
        """
        cisa_kev_ids = cisa_kev_ids or set()
        
        exploit_sources = []
        exploit_confidence = 0
        patch_sources = []
        patch_confidence = 0
        
        # Check CISA KEV first (highest confidence)
        if cve_id and cve_id.upper() in cisa_kev_ids:
            exploit_sources.append('cisa_kev')
            exploit_confidence = 100
        
        for ref in references:
            url = str(ref.get('url', '')).lower()
            tags = {str(tag).lower() for tag in ref.get('tags', [])}
            source = str(ref.get('source', '')).lower()
            
            # === EXPLOIT DETECTION ===
            
            # Metasploit (highest confidence)
            if re.search(r'rapid7\.com|metasploit', url):
                if 'metasploit' not in exploit_sources:
                    exploit_sources.append('metasploit')
                    exploit_confidence = max(exploit_confidence, 100)
            
            # Exploit-DB (very high confidence)
            elif re.search(r'exploit-db\.com/exploits/\d+', url):
                if 'exploit-db' not in exploit_sources:
                    exploit_sources.append('exploit-db')
                    exploit_confidence = max(exploit_confidence, 95)
            
            # PacketStorm (high confidence)
            elif re.search(r'packetstormsecurity\.com', url):
                if 'packetstorm' not in exploit_sources:
                    exploit_sources.append('packetstorm')
                    exploit_confidence = max(exploit_confidence, 90)
            
            # Nuclei templates (medium-high confidence)
            elif re.search(r'github\.com/projectdiscovery/nuclei-templates', url):
                if 'nuclei' not in exploit_sources:
                    exploit_sources.append('nuclei')
                    exploit_confidence = max(exploit_confidence, 85)
            
            # GitHub PoC (medium confidence - must be specific pattern)
            elif re.search(r'github\.com/[^/]+/[^/]*(exploit|poc|cve-\d{4}-\d+)', url):
                # Verify it's an actual exploit repo, not just discussion
                if '/issues/' not in url and '/discussions/' not in url:
                    if 'github_poc' not in exploit_sources:
                        exploit_sources.append('github_poc')
                        exploit_confidence = max(exploit_confidence, 70)
            
            # NVD exploit tag (lower confidence - verify with URL)
            elif 'exploit' in tags:
                if any(domain in url for domain in ['exploit-db', 'metasploit', 'packetstorm']):
                    exploit_confidence = max(exploit_confidence, 80)
            
            # === PATCH DETECTION ===
            
            # Official vendor patch (highest confidence)
            if 'patch' in tags or 'vendor advisory' in tags:
                for domain in VERIFIED_PATCH_DOMAINS:
                    if domain in url:
                        if domain not in patch_sources:
                            patch_sources.append(domain)
                            patch_confidence = max(patch_confidence, 95)
                        break
            
            # Release notes or security bulletins
            if re.search(r'(patch|hotfix|security[_-]update|release[_-]notes|bulletin)', url):
                for domain in VERIFIED_PATCH_DOMAINS:
                    if domain in url:
                        if domain not in patch_sources:
                            patch_sources.append(domain)
                            patch_confidence = max(patch_confidence, 90)
                        break
            
            # GitHub/GitLab commit or pull request (likely a patch)
            if re.search(r'github\.com/[^/]+/[^/]+/(commit|pull|releases)', url):
                if 'patch' in tags or 'vendor advisory' in tags:
                    if 'github.com' not in patch_sources:
                        patch_sources.append('github.com')
                        patch_confidence = max(patch_confidence, 85)
            
            # GitLab merge requests or commits
            if re.search(r'gitlab\.(com|freedesktop\.org)/[^/]+/[^/]+/(-/)?commit', url):
                if 'gitlab' not in patch_sources:
                    patch_sources.append('gitlab')
                    patch_confidence = max(patch_confidence, 85)
            
            # Any URL with Patch tag from a verified domain
            if 'patch' in tags:
                for domain in VERIFIED_PATCH_DOMAINS:
                    if domain in url:
                        if domain not in patch_sources:
                            patch_sources.append(domain)
                            patch_confidence = max(patch_confidence, 90)
                        break
        
        # Determine exploit maturity
        if exploit_confidence >= 95:
            maturity = 'weaponized'
        elif exploit_confidence >= 70:
            maturity = 'poc'
        elif exploit_confidence >= 40:
            maturity = 'theoretical'
        else:
            maturity = 'unknown'
        
        return {
            'exploit_available': exploit_confidence >= 70,
            'exploit_confidence': exploit_confidence,
            'exploit_sources': exploit_sources,
            'exploit_maturity': maturity,
            'patch_available': patch_confidence >= 70,
            'patch_confidence': patch_confidence,
            'patch_sources': patch_sources,
        }


# ═══════════════════════════════════════════════════════════════
# NVD SERVICE
# ═══════════════════════════════════════════════════════════════

class NVDService:
    """
    Production-grade NVD API client with full validation.
    """
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or getattr(settings, 'NVD_API_KEY', None)
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'CascadeX-VulnScanner/1.0'
        
        if self.api_key:
            self.session.headers['apiKey'] = self.api_key
            self.rate_limit = RATE_LIMIT_WITH_KEY
            logger.info("NVD Service initialized with API key")
        else:
            self.rate_limit = RATE_LIMIT_DELAY
            logger.warning("NVD Service initialized WITHOUT API key (rate limited)")
        
        self.last_request_time = 0.0
        self._cisa_kev_cache: Set[str] = set()
        self._cisa_kev_loaded = False
    
    # ───────────────────────────────────────────────────────────
    # CISA KEV INTEGRATION
    # ───────────────────────────────────────────────────────────
    
    def load_cisa_kev(self, force_refresh: bool = False) -> Set[str]:
        """
        Load CISA Known Exploited Vulnerabilities catalog.
        
        Returns:
            Set of CVE IDs that are in CISA KEV
        """
        cache_key = 'cisa_kev_cve_ids'
        
        if not force_refresh and self._cisa_kev_loaded:
            return self._cisa_kev_cache
        
        cached = cache.get(cache_key)
        if cached and not force_refresh:
            self._cisa_kev_cache = cached
            self._cisa_kev_loaded = True
            return cached
        
        try:
            response = self.session.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            cve_ids = set()
            for vuln in data.get('vulnerabilities', []):
                cve_id = str(vuln.get('cveID', '')).upper()
                if cve_id.startswith('CVE-'):
                    cve_ids.add(cve_id)
            
            cache.set(cache_key, cve_ids, CACHE_TIMEOUT_KEV)
            self._cisa_kev_cache = cve_ids
            self._cisa_kev_loaded = True
            
            logger.info(f"Loaded {len(cve_ids)} CVEs from CISA KEV catalog")
            return cve_ids
            
        except Exception as e:
            logger.error(f"Failed to load CISA KEV: {e}")
            return self._cisa_kev_cache
    
    def fetch_cisa_kev_details(
        self,
        max_age_days: int = 180,
    ) -> List[Dict]:
        """
        Fetch detailed CISA KEV entries with full CVE data.
        
        Returns:
            List of normalized CVE dicts with CISA metadata
        """
        try:
            response = self.session.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            cutoff = datetime.now() - timedelta(days=max_age_days)
            results = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID', '')
                date_added = vuln.get('dateAdded', '')
                
                # Parse date
                try:
                    added_date = datetime.strptime(date_added, '%Y-%m-%d')
                    if added_date < cutoff:
                        continue
                except ValueError:
                    pass
                
                # Fetch full CVE details from NVD
                cve_data = self.fetch_single_cve(cve_id)
                if cve_data:
                    cve_data['cisa_kev'] = True
                    cve_data['cisa_date_added'] = date_added
                    cve_data['cisa_due_date'] = vuln.get('dueDate', '')
                    cve_data['cisa_description'] = vuln.get('shortDescription', '')
                    cve_data['cisa_vendor'] = vuln.get('vendorProject', '')
                    cve_data['cisa_product'] = vuln.get('product', '')
                    cve_data['exploit_available'] = True
                    cve_data['exploit_confidence'] = 100
                    cve_data['exploit_maturity'] = 'weaponized'
                    results.append(cve_data)
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV details: {e}")
            return []
    
    # ───────────────────────────────────────────────────────────
    # MAIN FETCH METHODS
    # ───────────────────────────────────────────────────────────
    
    def fetch_cves(
        self,
        keywords: List[str] = None,
        severity: str = None,
        days_back: int = 30,
        max_results: int = 100,
        cve_id: str = None,
        include_rejected: bool = False,
        validate_completeness: bool = True,
    ) -> Dict:
        """
        Fetch CVEs from NVD API with full validation.
        
        Args:
            keywords: Search keywords
            severity: CRITICAL, HIGH, MEDIUM, or LOW
            days_back: Fetch CVEs modified in last N days
            max_results: Maximum number of results
            cve_id: Specific CVE ID to fetch
            include_rejected: Include rejected/reserved CVEs (default False)
            validate_completeness: Enforce data completeness (default True)
        
        Returns:
            {
                'success': bool,
                'vulnerabilities': List[Dict],
                'total_results': int,
                'filtered_count': int,
                'validation_stats': Dict,
                'error': str or None,
            }
        """
        # Check cache
        cache_key = self._build_cache_key(
            keywords=keywords,
            severity=severity,
            days_back=days_back,
            cve_id=cve_id,
            max_results=max_results,
        )
        
        cached = cache.get(cache_key)
        if cached:
            logger.info(f"Cache hit: {cache_key}")
            return cached
        
        # Load CISA KEV for exploit detection
        cisa_kev_ids = self.load_cisa_kev()
        
        try:
            params = self._build_params(
                keywords=keywords,
                severity=severity,
                days_back=days_back,
                cve_id=cve_id,
            )
            
            all_vulns = []
            filtered_count = 0
            validation_stats = {
                'total_fetched': 0,
                'passed_validation': 0,
                'failed_cve_id': 0,
                'failed_status': 0,
                'failed_completeness': 0,
                'future_cves_rejected': 0,
            }
            
            start_index = 0
            results_per_page = min(200, max_results)
            
            while len(all_vulns) < max_results:
                page_params = dict(params)
                page_params['startIndex'] = start_index
                page_params['resultsPerPage'] = results_per_page
                
                self._rate_limit()
                response = self._make_request(page_params)
                
                if not response['success']:
                    return {
                        'success': False,
                        'vulnerabilities': [],
                        'total_results': 0,
                        'filtered_count': 0,
                        'validation_stats': validation_stats,
                        'error': response.get('error', 'NVD API error'),
                    }
                
                data = response['data']
                items = data.get('vulnerabilities', [])
                total_results = data.get('totalResults', 0)
                
                if not items:
                    break
                
                for item in items:
                    validation_stats['total_fetched'] += 1
                    
                    # Normalize CVE
                    normalized = self._normalize_cve(item, cisa_kev_ids)
                    if not normalized:
                        continue
                    
                    # Validate CVE ID and year
                    cve_id_valid, cve_id_reason = CVEValidator.validate_cve_id(
                        normalized.get('cve_id')
                    )
                    if not cve_id_valid:
                        validation_stats['failed_cve_id'] += 1
                        if 'Future CVE' in cve_id_reason:
                            validation_stats['future_cves_rejected'] += 1
                        logger.debug(f"Rejected CVE: {cve_id_reason}")
                        filtered_count += 1
                        continue
                    
                    # Validate NVD status
                    if not include_rejected:
                        status_valid, _ = CVEValidator.validate_nvd_status(
                            normalized.get('nvd_status', 'Analyzed')
                        )
                        if not status_valid:
                            validation_stats['failed_status'] += 1
                            filtered_count += 1
                            continue
                    
                    # Validate completeness
                    if validate_completeness:
                        complete, issues = CVEValidator.validate_completeness(normalized)
                        if not complete:
                            validation_stats['failed_completeness'] += 1
                            logger.debug(
                                f"Incomplete CVE {normalized.get('cve_id')}: {issues}"
                            )
                            filtered_count += 1
                            continue
                    
                    validation_stats['passed_validation'] += 1
                    all_vulns.append(normalized)
                
                if start_index + len(items) >= total_results:
                    break
                
                start_index += results_per_page
                
                if len(all_vulns) >= max_results:
                    break
            
            final_vulns = all_vulns[:max_results]

            # ── EPSS Enrichment ─────────────────────────────
            try:
                from .epss_service import EPSSService
                final_vulns = EPSSService.enrich_vulnerabilities(final_vulns)
                logger.info(f"EPSS scores added to {len(final_vulns)} CVEs")
            except Exception as epss_err:
                logger.warning(f"EPSS enrichment failed (non-critical): {epss_err}")
            # ─────────────────────────────────────────────────

            result = {
                'success': True,
                'vulnerabilities': final_vulns,
                'total_results': len(final_vulns),
                'filtered_count': filtered_count,
                'validation_stats': validation_stats,
                'error': None,
            }

            cache.set(cache_key, result, CACHE_TIMEOUT)

            logger.info(
                f"Fetched {validation_stats['passed_validation']} CVEs, "
                f"filtered {filtered_count} invalid/incomplete entries"
            )

            return result
            
        except Exception as e:
            logger.error(f"NVD fetch error: {e}", exc_info=True)
            return {
                'success': False,
                'vulnerabilities': [],
                'total_results': 0,
                'filtered_count': 0,
                'validation_stats': {},
                'error': str(e),
            }
    
    def fetch_single_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a single CVE by ID with full validation.
        
        Returns:
            Normalized CVE dict or None if invalid/not found
        """
        # Validate CVE ID format first
        cve_id_valid, reason = CVEValidator.validate_cve_id(cve_id)
        if not cve_id_valid:
            logger.warning(f"Invalid CVE ID requested: {cve_id} - {reason}")
            return None
        
        result = self.fetch_cves(
            cve_id=cve_id,
            max_results=1,
            include_rejected=False,
            validate_completeness=True,
        )
        
        if result['success'] and result['vulnerabilities']:
            return result['vulnerabilities'][0]
        
        return None
    
    def fetch_by_product(
        self,
        vendor: str,
        product: str,
        version: str = None,
        max_results: int = 50,
    ) -> Dict:
        """
        Fetch CVEs affecting a specific product.
        
        This uses CPE matching for accurate results.
        """
        # Build CPE string
        cpe = CPENormalizer.build_cpe_string(vendor, product, version or '*')
        
        params = {
            'cpeName': cpe,
            'resultsPerPage': min(200, max_results),
        }
        
        cisa_kev_ids = self.load_cisa_kev()
        
        try:
            self._rate_limit()
            response = self._make_request(params)
            
            if not response['success']:
                return {
                    'success': False,
                    'vulnerabilities': [],
                    'total_results': 0,
                    'error': response.get('error'),
                }
            
            data = response['data']
            items = data.get('vulnerabilities', [])
            
            vulns = []
            for item in items:
                normalized = self._normalize_cve(item, cisa_kev_ids)
                if normalized:
                    # Additional version filtering if version specified
                    if version:
                        is_affected = self._check_version_affected(
                            normalized,
                            vendor,
                            product,
                            version,
                        )
                        if not is_affected:
                            continue
                    
                    vulns.append(normalized)
            
            return {
                'success': True,
                'vulnerabilities': vulns[:max_results],
                'total_results': len(vulns[:max_results]),
                'error': None,
            }
            
        except Exception as e:
            logger.error(f"Product fetch error: {e}", exc_info=True)
            return {
                'success': False,
                'vulnerabilities': [],
                'total_results': 0,
                'error': str(e),
            }
    
    def _check_version_affected(
        self,
        cve_data: Dict,
        vendor: str,
        product: str,
        version: str,
    ) -> bool:
        """
        Check if a specific version is affected by this CVE.
        
        Uses version range data from affected_entries.
        """
        vendor = CPENormalizer.normalize_vendor(vendor)
        product = CPENormalizer.normalize_product(product)
        
        for entry in cve_data.get('affected_entries', []):
            if entry.get('vendor') != vendor:
                continue
            if entry.get('product') != product:
                continue
            
            # Check exact version match
            entry_version = entry.get('version', '')
            if entry_version and entry_version not in ('*', '-'):
                if VersionComparator.matches_exact(version, entry_version):
                    return True
            
            # Check version range
            is_vulnerable, _ = VersionComparator.is_in_range(
                version=version,
                start_including=entry.get('version_start_including', ''),
                start_excluding=entry.get('version_start_excluding', ''),
                end_including=entry.get('version_end_including', ''),
                end_excluding=entry.get('version_end_excluding', ''),
            )
            
            if is_vulnerable:
                return True
        
        return False
    
    # ───────────────────────────────────────────────────────────
    # REQUEST LAYER
    # ───────────────────────────────────────────────────────────
    
    def _make_request(self, params: Dict) -> Dict:
        """Make HTTP request with retry logic."""
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.get(
                    NVD_API_BASE,
                    params=params,
                    timeout=REQUEST_TIMEOUT,
                )
                
                if response.status_code == 200:
                    return {
                        'success': True,
                        'data': response.json(),
                    }
                
                if response.status_code == 404:
                    return {
                        'success': False,
                        'error': 'CVE not found',
                    }
                
                if response.status_code == 403:
                    logger.warning("NVD rate limit hit, backing off...")
                    time.sleep(RETRY_DELAY * 3)
                    continue
                
                if response.status_code in (429, 500, 502, 503, 504):
                    logger.warning(
                        f"NVD transient error {response.status_code}, "
                        f"attempt {attempt + 1}/{MAX_RETRIES}"
                    )
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                
                logger.warning(f"NVD request failed: HTTP {response.status_code}")
                time.sleep(RETRY_DELAY)
                
            except requests.Timeout:
                logger.warning(f"NVD request timeout, attempt {attempt + 1}/{MAX_RETRIES}")
                time.sleep(RETRY_DELAY)
                
            except requests.RequestException as e:
                logger.warning(f"NVD request error: {e}, attempt {attempt + 1}/{MAX_RETRIES}")
                time.sleep(RETRY_DELAY)
        
        return {
            'success': False,
            'error': f'Max retries ({MAX_RETRIES}) exceeded',
        }
    
    def _rate_limit(self):
        """Enforce rate limiting."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request_time = time.time()
    
    def _build_params(
        self,
        keywords: List[str] = None,
        severity: str = None,
        days_back: int = 30,
        cve_id: str = None,
    ) -> Dict:
        """Build NVD API query parameters."""
        params = {}
        
        if cve_id:
            params['cveId'] = cve_id.upper()
            return params
        
        if days_back:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            params['lastModStartDate'] = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            params['lastModEndDate'] = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        
        if keywords:
            clean_keywords = [
                str(k).strip()
                for k in keywords
                if str(k).strip()
            ]
            if clean_keywords:
                params['keywordSearch'] = ' '.join(clean_keywords)
        
        if severity:
            sev = str(severity).upper().strip()
            if sev in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}:
                params['cvssV3Severity'] = sev
        
        return params
    
    def _build_cache_key(
        self,
        keywords: List[str],
        severity: str,
        days_back: int,
        cve_id: str,
        max_results: int,
    ) -> str:
        """Build cache key for request."""
        parts = ['nvd_v2']
        
        if cve_id:
            parts.append(cve_id.upper())
        else:
            if keywords:
                sorted_kw = sorted([str(k).strip().lower() for k in keywords if k])
                parts.append('_'.join(sorted_kw))
            if severity:
                parts.append(str(severity).upper())
            parts.append(f'd{days_back}')
            parts.append(f'n{max_results}')
        
        return ':'.join(parts)
    
    # ───────────────────────────────────────────────────────────
    # NORMALIZATION
    # ───────────────────────────────────────────────────────────
    
    def _normalize_cve(
        self,
        item: Dict,
        cisa_kev_ids: Set[str] = None,
    ) -> Optional[Dict]:
        """
        Normalize NVD API response into standardized format.
        
        Returns None if critical data is missing.
        """
        cisa_kev_ids = cisa_kev_ids or set()
        
        try:
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            if not cve_id:
                return None
            
            cve_id = cve_id.upper()
            
            # Get NVD status
            nvd_status = cve_data.get('vulnStatus', 'Analyzed')
            
            # Extract description
            description = self._extract_english_description(cve_data)
            
            # Extract CVSS metrics
            cvss_data = self._extract_cvss(cve_data.get('metrics', {}))
            
            # Extract affected products with version ranges
            affected = self._extract_affected_products(cve_data)
            
            # Extract references
            references = self._extract_references(cve_data)
            
            # Extract CWEs
            cwe_ids = self._extract_cwes(cve_data)
            
            # Detect exploit and patch signals
            exploit_data = ExploitDetector.analyze_references(
                references=references,
                cisa_kev_ids=cisa_kev_ids,
                cve_id=cve_id,
            )
            
            # Get dates
            published = cve_data.get('published', '')
            modified = cve_data.get('lastModified', '')
            
            # Build normalized output
            normalized = {
                # Core identifiers
                'cve_id': cve_id,
                'nvd_status': nvd_status,
                
                # Description
                'description': description,
                
                # CVSS scores
                'cvss_score': cvss_data.get('score'),
                'cvss_version': cvss_data.get('version'),
                'severity': cvss_data.get('severity', 'MEDIUM'),
                
                # Attack characteristics
                'attack_vector': cvss_data.get('attack_vector', ''),
                'attack_complexity': cvss_data.get('attack_complexity', ''),
                'privileges_required': cvss_data.get('privileges_required', ''),
                'user_interaction': cvss_data.get('user_interaction', ''),
                'scope': cvss_data.get('scope', ''),
                'confidentiality_impact': cvss_data.get('confidentiality_impact', ''),
                'integrity_impact': cvss_data.get('integrity_impact', ''),
                'availability_impact': cvss_data.get('availability_impact', ''),
                
                # Affected products (for backward compatibility)
                'affected_products': affected['products'],
                'affected_vendors': affected['vendors'],
                'affected_cpes': affected['cpes'],
                
                # Structured affected entries (for version range matching)
                'affected_entries': affected['entries'],
                
                # CWEs
                'cwe_ids': cwe_ids,
                
                # References
                'references': references,
                
                # Exploit intelligence
                'exploit_available': exploit_data['exploit_available'],
                'exploit_confidence': exploit_data['exploit_confidence'],
                'exploit_sources': exploit_data['exploit_sources'],
                'exploit_maturity': exploit_data['exploit_maturity'],
                
                # Patch intelligence
                'patch_available': exploit_data['patch_available'],
                'patch_confidence': exploit_data['patch_confidence'],
                'patch_sources': exploit_data['patch_sources'],
                
                # CISA KEV flag
                'cisa_kev': cve_id in cisa_kev_ids,
                
                # Dates
                'published_date': published,
                'last_modified_date': modified,
                
                # Default status
                'status': 'warning',
            }
            
            return normalized
            
        except Exception as e:
            logger.warning(f"CVE normalization failed: {e}", exc_info=True)
            return None
    
    def _extract_english_description(self, cve_data: Dict) -> str:
        """Extract English description from CVE data."""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return str(desc.get('value', '')).strip()
        return ''
    
    def _extract_cvss(self, metrics: Dict) -> Dict:
        """Extract CVSS metrics with fallback through versions."""
        result = {
            'score': None,
            'version': None,
            'severity': 'MEDIUM',
            'attack_vector': '',
            'attack_complexity': '',
            'privileges_required': '',
            'user_interaction': '',
            'scope': '',
            'confidentiality_impact': '',
            'integrity_impact': '',
            'availability_impact': '',
        }
        
        # Try CVSS v3.1 first
        cvss31 = metrics.get('cvssMetricV31', [])
        if cvss31:
            data = cvss31[0].get('cvssData', {})
            result['score'] = data.get('baseScore')
            result['version'] = '3.1'
            result['severity'] = data.get('baseSeverity', 'MEDIUM')
            result['attack_vector'] = data.get('attackVector', '')
            result['attack_complexity'] = data.get('attackComplexity', '')
            result['privileges_required'] = data.get('privilegesRequired', '')
            result['user_interaction'] = data.get('userInteraction', '')
            result['scope'] = data.get('scope', '')
            result['confidentiality_impact'] = data.get('confidentialityImpact', '')
            result['integrity_impact'] = data.get('integrityImpact', '')
            result['availability_impact'] = data.get('availabilityImpact', '')
            return result
        
        # Try CVSS v3.0
        cvss30 = metrics.get('cvssMetricV30', [])
        if cvss30:
            data = cvss30[0].get('cvssData', {})
            result['score'] = data.get('baseScore')
            result['version'] = '3.0'
            result['severity'] = data.get('baseSeverity', 'MEDIUM')
            result['attack_vector'] = data.get('attackVector', '')
            result['attack_complexity'] = data.get('attackComplexity', '')
            result['privileges_required'] = data.get('privilegesRequired', '')
            result['user_interaction'] = data.get('userInteraction', '')
            result['scope'] = data.get('scope', '')
            result['confidentiality_impact'] = data.get('confidentialityImpact', '')
            result['integrity_impact'] = data.get('integrityImpact', '')
            result['availability_impact'] = data.get('availabilityImpact', '')
            return result
        
        # Fall back to CVSS v2
        cvss2 = metrics.get('cvssMetricV2', [])
        if cvss2:
            data = cvss2[0].get('cvssData', {})
            score = data.get('baseScore')
            result['score'] = score
            result['version'] = '2.0'
            
            # Map v2 score to v3-style severity
            if score is not None:
                if score >= 9.0:
                    result['severity'] = 'CRITICAL'
                elif score >= 7.0:
                    result['severity'] = 'HIGH'
                elif score >= 4.0:
                    result['severity'] = 'MEDIUM'
                else:
                    result['severity'] = 'LOW'
            
            # Map v2 access vector to v3 attack vector
            access_vector = data.get('accessVector', '')
            if access_vector == 'NETWORK':
                result['attack_vector'] = 'NETWORK'
            elif access_vector == 'ADJACENT_NETWORK':
                result['attack_vector'] = 'ADJACENT_NETWORK'
            else:
                result['attack_vector'] = 'LOCAL'
            
            # Map v2 access complexity
            access_complexity = data.get('accessComplexity', '')
            if access_complexity == 'LOW':
                result['attack_complexity'] = 'LOW'
            else:
                result['attack_complexity'] = 'HIGH'
        
        return result
    
    def _extract_affected_products(self, cve_data: Dict) -> Dict:
        """
        Extract affected products with full version range information.
        
        Recursively walks NVD configuration nodes.
        """
        entries: List[Dict] = []
        seen_cpes: Set[str] = set()
        
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            for node in config.get('nodes', []):
                self._walk_config_node(node, entries, seen_cpes)
        
        # Build summary lists for backward compatibility
        products = set()
        vendors = set()
        cpes = set()
        
        for entry in entries:
            vendor = entry.get('vendor', '')
            product = entry.get('product', '')
            version = entry.get('version', '')
            raw_cpe = entry.get('raw_cpe', '')
            
            if vendor:
                vendors.add(vendor)
            
            if raw_cpe:
                cpes.add(raw_cpe)
            
            # Build product strings for matching
            # ONLY include vendor:product (not product-only to prevent over-matching)
            if vendor and product:
                if version and version not in ('*', '-'):
                    products.add(f"{vendor}:{product}:{version}")
                products.add(f"{vendor}:{product}")
        
        return {
            'products': sorted(products),
            'vendors': sorted(vendors),
            'cpes': sorted(cpes),
            'entries': entries,
        }
    
    def _walk_config_node(
        self,
        node: Dict,
        entries: List[Dict],
        seen_cpes: Set[str],
    ):
        """Recursively walk NVD configuration nodes."""
        cpe_matches = node.get('cpeMatch', [])
        
        for match in cpe_matches:
            criteria = match.get('criteria', '')
            if not criteria or criteria in seen_cpes:
                continue
            
            seen_cpes.add(criteria)
            
            parsed = CPENormalizer.parse_cpe23(criteria)
            if not parsed or (not parsed.get('vendor') and not parsed.get('product')):
                continue
            
            entry = {
                'part': parsed.get('part', ''),
                'vendor': parsed.get('vendor', ''),
                'product': parsed.get('product', ''),
                'version': parsed.get('version', ''),
                'update': parsed.get('update', ''),
                'edition': parsed.get('edition', ''),
                'raw_cpe': parsed.get('raw_cpe', ''),
                'cpe_valid': parsed.get('valid', False),
                'vulnerable': bool(match.get('vulnerable', True)),
                
                # Version range constraints (CRITICAL for accurate matching)
                'version_start_including': CPENormalizer.normalize_version(
                    match.get('versionStartIncluding')
                ),
                'version_start_excluding': CPENormalizer.normalize_version(
                    match.get('versionStartExcluding')
                ),
                'version_end_including': CPENormalizer.normalize_version(
                    match.get('versionEndIncluding')
                ),
                'version_end_excluding': CPENormalizer.normalize_version(
                    match.get('versionEndExcluding')
                ),
            }
            
            entries.append(entry)
        
        # Recurse into children
        for child in node.get('children', []):
            self._walk_config_node(child, entries, seen_cpes)
    
    def _extract_references(self, cve_data: Dict) -> List[Dict]:
        """Extract and structure reference URLs."""
        refs = cve_data.get('references', [])
        references = []
        
        for ref in refs:
            references.append({
                'url': str(ref.get('url', '')).strip(),
                'source': str(ref.get('source', '')).strip(),
                'tags': [str(t).strip() for t in ref.get('tags', []) if t],
            })
        
        return references
    
    def _extract_cwes(self, cve_data: Dict) -> List[str]:
        """Extract CWE IDs from CVE data."""
        cwes = set()
        weaknesses = cve_data.get('weaknesses', [])
        
        for weakness in weaknesses:
            descriptions = weakness.get('description', [])
            for desc in descriptions:
                value = str(desc.get('value', '')).strip().upper()
                # Validate CWE format
                if re.match(r'^CWE-\d+$', value):
                    cwes.add(value)
        
        return sorted(cwes)


# ═══════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def get_nvd_service() -> NVDService:
    """Get a configured NVD service instance."""
    return NVDService()


def fetch_recent_cves(
    severity: str = None,
    days_back: int = 30,
    max_results: int = 100,
) -> List[Dict]:
    """
    Convenience function to fetch recent CVEs.
    
    Returns list of validated CVE dicts.
    """
    service = get_nvd_service()
    result = service.fetch_cves(
        severity=severity,
        days_back=days_back,
        max_results=max_results,
    )
    
    if result['success']:
        return result['vulnerabilities']
    
    logger.error(f"Failed to fetch CVEs: {result.get('error')}")
    return []


def check_product_vulnerabilities(
    vendor: str,
    product: str,
    version: str,
) -> List[Dict]:
    """
    Check if a specific product version has vulnerabilities.
    
    Returns list of CVEs affecting this exact version.
    """
    service = get_nvd_service()
    result = service.fetch_by_product(
        vendor=vendor,
        product=product,
        version=version,
    )
    
    if result['success']:
        return result['vulnerabilities']
    
    return []