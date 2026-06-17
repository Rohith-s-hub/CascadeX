"""
Active Vulnerability Scanner
═══════════════════════════════════════════════════════════════
Production-grade network scanning using nmap with vulnerability
detection. Integrates with asset inventory and CVE matching.

Improvements in this version
----------------------------
- safer and stronger CVE-to-asset correlation
- better service normalization
- CPE-aware matching
- token-based fuzzy matching
- version-aware confidence scoring
- asset persistence with normalized service data
"""

import ipaddress
import logging
import re
import subprocess
import threading
import uuid
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# EXCEPTIONS
# ═══════════════════════════════════════════════════════════════


class ScanError(Exception):
    pass


class InvalidTargetError(ScanError):
    pass


class InvalidPortError(ScanError):
    pass


class RateLimitError(ScanError):
    pass


# ═══════════════════════════════════════════════════════════════
# VALIDATION
# ═══════════════════════════════════════════════════════════════


class InputValidator:
    _HOSTNAME_RE = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    _PORT_RANGE_RE = re.compile(r'^[\d,\-]+$')
    _SAFE_SCRIPT_RE = re.compile(r'^[a-zA-Z0-9\-_]+$')

    _BLOCKED_TARGETS: Set[str] = {
        '0.0.0.0',
        '0.0.0.0/0',
        '255.255.255.255',
        '::/0',
        '::',
    }

    _MAX_CIDR_V4 = 16
    _MAX_CIDR_V6 = 112

    @classmethod
    def validate_target(cls, target: str) -> str:
        if not target or not isinstance(target, str):
            raise InvalidTargetError("Target cannot be empty")

        target = target.strip()

        if len(target) > 253:
            raise InvalidTargetError("Target too long (max 253 characters)")

        if target in cls._BLOCKED_TARGETS:
            raise InvalidTargetError(f"Target '{target}' is blocked")

        try:
            addr = ipaddress.ip_address(target)
            if addr.is_multicast:
                raise InvalidTargetError(f"Multicast address not allowed: {target}")
            return str(addr)
        except ValueError:
            pass

        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.version == 4 and network.prefixlen < cls._MAX_CIDR_V4:
                raise InvalidTargetError(
                    f"CIDR range too broad: {target} (minimum /{cls._MAX_CIDR_V4})"
                )
            if network.version == 6 and network.prefixlen < cls._MAX_CIDR_V6:
                raise InvalidTargetError(
                    f"CIDR range too broad: {target} (minimum /{cls._MAX_CIDR_V6})"
                )
            return str(network)
        except ValueError:
            pass

        if cls._HOSTNAME_RE.match(target):
            return target

        raise InvalidTargetError(
            f"Invalid target format: '{target}'. Use IP, CIDR, or hostname."
        )

    @classmethod
    def validate_ports(cls, ports: str) -> str:
        if not ports or not isinstance(ports, str):
            raise InvalidPortError("Port specification cannot be empty")

        ports = ports.strip()

        if len(ports) > 100:
            raise InvalidPortError("Port specification too long")

        if not cls._PORT_RANGE_RE.match(ports):
            raise InvalidPortError(
                f"Invalid port format: '{ports}'. Use digits, commas, and dashes only."
            )

        for segment in ports.split(','):
            segment = segment.strip()
            if '-' in segment:
                parts = segment.split('-', 1)
                if len(parts) != 2:
                    raise InvalidPortError(f"Invalid range: '{segment}'")
                try:
                    start, end = int(parts[0]), int(parts[1])
                except ValueError:
                    raise InvalidPortError(f"Non-numeric range: '{segment}'")
                if not (0 < start <= 65535 and 0 < end <= 65535):
                    raise InvalidPortError(f"Port out of range: '{segment}'")
                if start > end:
                    raise InvalidPortError(f"Invalid range: '{segment}'")
            else:
                try:
                    port_num = int(segment)
                except ValueError:
                    raise InvalidPortError(f"Non-numeric port: '{segment}'")
                if not 0 < port_num <= 65535:
                    raise InvalidPortError(f"Port out of range: '{segment}'")

        return ports

    @classmethod
    def validate_scripts(cls, scripts: List[str]) -> List[str]:
        if not scripts:
            return []

        validated = []
        for script in scripts:
            script = script.strip()
            if not cls._SAFE_SCRIPT_RE.match(script):
                raise ScanError(
                    f"Invalid script name: '{script}'. "
                    f"Only alphanumeric, dashes, underscores allowed."
                )
            if len(script) > 64:
                raise ScanError(f"Script name too long: '{script}'")
            validated.append(script)

        if len(validated) > 20:
            raise ScanError("Too many scripts (max 20)")

        return validated

    @classmethod
    def validate_top_ports(cls, count: int) -> int:
        if not isinstance(count, int) or count < 1:
            raise InvalidPortError(f"Invalid top-ports count: {count}")
        if count > 10000:
            raise InvalidPortError("Top-ports count too high (max 10000)")
        return count


# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════


class ScanConfig:
    TIMEOUTS: Dict[str, int] = {
        'quick': 120,
        'full': 900,
        'vulnerability': 600,
        'stealth': 300,
        'custom': 600,
    }

    MAX_CONCURRENT_SCANS: int = 3
    MIN_SCAN_INTERVAL: int = 60
    MAX_HISTORY_SIZE: int = 200
    MAX_OUTPUT_SIZE: int = 50 * 1024 * 1024
    NMAP_BINARY: str = 'nmap'


# ═══════════════════════════════════════════════════════════════
# NORMALIZATION HELPERS
# ═══════════════════════════════════════════════════════════════


class ServiceNormalizer:
    """
    Normalizes service/product/CPE values for stronger matching.
    """

    NOISE_WORDS = {
        'server', 'service', 'services', 'httpd', 'daemon',
        'version', 'release', 'update', 'community', 'edition',
        'build', 'software', 'application',
    }

    PRODUCT_ALIASES = {
        'http': 'http',
        'https': 'http',
        'apache': 'apache',
        'http_server': 'apache',
        'apache_http_server': 'apache',
        'nginx': 'nginx',
        'iis': 'iis',
        'microsoft_iis': 'iis',
        'tomcat': 'tomcat',
        'mysql': 'mysql',
        'mariadb': 'mariadb',
        'postgres': 'postgresql',
        'postgresql': 'postgresql',
        'mongodb': 'mongodb',
        'redis': 'redis',
        'openssh': 'ssh',
        'ssh': 'ssh',
        'smb': 'smb',
        'microsoft-ds': 'smb',
        'ms-sql-s': 'mssql',
        'mssql': 'mssql',
        'ms_sql': 'mssql',
        'oracle': 'oracle',
        'docker': 'docker',
        'kubernetes': 'kubernetes',
        'ldap': 'ldap',
        'kerberos': 'kerberos',
        'ftp': 'ftp',
        'smtp': 'smtp',
        'imap': 'imap',
        'pop3': 'pop3',
    }

    @classmethod
    def normalize_text(cls, value: str) -> str:
        return str(value or '').strip().lower()

    @classmethod
    def tokenize(cls, value: str) -> List[str]:
        raw_tokens = re.split(r'[\s/:_\-\.]+', cls.normalize_text(value))
        tokens = []
        for token in raw_tokens:
            token = token.strip()
            if (
                len(token) > 1
                and token not in cls.NOISE_WORDS
                and not token.replace('.', '').isdigit()
            ):
                tokens.append(cls.PRODUCT_ALIASES.get(token, token))
        return sorted(set(tokens))

    @classmethod
    def normalize_product(cls, product: str, service: str = '') -> str:
        product_tokens = cls.tokenize(product)
        service_tokens = cls.tokenize(service)

        if product_tokens:
            return product_tokens[0]
        if service_tokens:
            return service_tokens[0]
        return ''

    @classmethod
    def normalize_version(cls, version: str) -> str:
        version = cls.normalize_text(version)
        version = re.sub(r'[^0-9a-zA-Z\.\-_]', '', version)
        return version

    @classmethod
    def parse_cpe(cls, cpe: str) -> Dict:
        """
        Parse basic CPE 2.3 string:
        cpe:2.3:a:vendor:product:version:...
        """
        cpe = cls.normalize_text(cpe)
        parts = cpe.split(':')
        if len(parts) < 6 or not cpe.startswith('cpe:2.3:'):
            return {
                'raw': cpe,
                'vendor': '',
                'product': '',
                'version': '',
                'part': '',
            }

        return {
            'raw': cpe,
            'part': parts[2],
            'vendor': cls.PRODUCT_ALIASES.get(parts[3], parts[3]),
            'product': cls.PRODUCT_ALIASES.get(parts[4], parts[4]),
            'version': parts[5] if parts[5] not in ('*', '-') else '',
        }

    @classmethod
    def service_fingerprint(cls, svc: Dict) -> Dict:
        service_name = cls.normalize_text(svc.get('service', ''))
        product = cls.normalize_text(svc.get('product', ''))
        version = cls.normalize_version(svc.get('version', ''))

        normalized_product = cls.normalize_product(product, service_name)

        cpes = []
        for cpe in svc.get('cpe', []) or []:
            parsed = cls.parse_cpe(cpe)
            if parsed['vendor'] or parsed['product']:
                cpes.append(parsed)

        tokens = set(cls.tokenize(service_name))
        tokens.update(cls.tokenize(product))
        for parsed in cpes:
            if parsed['vendor']:
                tokens.add(parsed['vendor'])
            if parsed['product']:
                tokens.add(parsed['product'])

        return {
            'service': service_name,
            'product': product,
            'normalized_product': normalized_product,
            'version': version,
            'tokens': sorted(tokens),
            'cpes': cpes,
        }

    @classmethod
    def normalize_affected_product(cls, product_str: str) -> Dict:
        """
        Normalizes freeform or CPE-like affected product strings.
        """
        raw = cls.normalize_text(product_str)

        if raw.startswith('cpe:2.3:'):
            parsed = cls.parse_cpe(raw)
            tokens = set()
            if parsed['vendor']:
                tokens.add(parsed['vendor'])
            if parsed['product']:
                tokens.add(parsed['product'])
            if parsed['version']:
                tokens.add(parsed['version'])
            return {
                'raw': raw,
                'vendor': parsed['vendor'],
                'product': parsed['product'],
                'version': parsed['version'],
                'tokens': sorted(tokens),
                'cpes': [parsed],
            }

        tokens = cls.tokenize(raw)

        vendor = tokens[0] if len(tokens) >= 1 else ''
        product = tokens[1] if len(tokens) >= 2 else (tokens[0] if len(tokens) == 1 else '')
        version_match = re.search(r'\b\d+(?:\.\d+){0,3}\b', raw)
        version = version_match.group(0) if version_match else ''

        return {
            'raw': raw,
            'vendor': vendor,
            'product': cls.PRODUCT_ALIASES.get(product, product),
            'version': cls.normalize_version(version),
            'tokens': tokens,
            'cpes': [],
        }


# ═══════════════════════════════════════════════════════════════
# XML PARSER
# ═══════════════════════════════════════════════════════════════


class NmapXMLParser:
    @staticmethod
    def parse_hosts(xml_str: str) -> List[Dict]:
        hosts = []

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return hosts

        for host_elem in root.findall('.//host'):
            host = NmapXMLParser._parse_single_host(host_elem)
            if host is not None:
                hosts.append(host)

        return hosts

    @staticmethod
    def _parse_single_host(host_elem: ET.Element) -> Optional[Dict]:
        status = host_elem.find('status')
        if status is None or status.get('state') != 'up':
            return None

        ip = NmapXMLParser._extract_ip(host_elem)
        if ip is None:
            return None

        hostname = NmapXMLParser._extract_hostname(host_elem, ip)
        os_type, os_accuracy = NmapXMLParser._extract_os(host_elem)
        services = NmapXMLParser._extract_services(host_elem)
        scripts = NmapXMLParser._extract_host_scripts(host_elem)

        return {
            'ip': ip,
            'hostname': hostname,
            'os': os_type,
            'os_accuracy': os_accuracy,
            'services': services,
            'service_count': len(services),
            'scripts': scripts,
        }

    @staticmethod
    def _extract_ip(host_elem: ET.Element) -> Optional[str]:
        addr = host_elem.find('.//address[@addrtype="ipv4"]')
        if addr is not None:
            return addr.get('addr')

        addr = host_elem.find('.//address[@addrtype="ipv6"]')
        if addr is not None:
            return addr.get('addr')

        return None

    @staticmethod
    def _extract_hostname(host_elem: ET.Element, fallback: str) -> str:
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            hn = hostnames.find('hostname')
            if hn is not None:
                name = hn.get('name', '').strip()
                if name:
                    return name
        return fallback

    @staticmethod
    def _extract_os(host_elem: ET.Element) -> Tuple[str, int]:
        os_elem = host_elem.find('.//osmatch')
        if os_elem is not None:
            os_name = os_elem.get('name', '').strip()
            try:
                accuracy = int(os_elem.get('accuracy', 0))
            except (ValueError, TypeError):
                accuracy = 0
            return os_name, accuracy
        return '', 0

    @staticmethod
    def _extract_services(host_elem: ET.Element) -> List[Dict]:
        services = []
        ports_elem = host_elem.find('ports')
        if ports_elem is None:
            return services

        for port_elem in ports_elem.findall('port'):
            service = NmapXMLParser._parse_port(port_elem)
            if service is not None:
                services.append(service)

        return services

    @staticmethod
    def _parse_port(port_elem: ET.Element) -> Optional[Dict]:
        state_elem = port_elem.find('state')
        if state_elem is None or state_elem.get('state') != 'open':
            return None

        try:
            port_id = int(port_elem.get('portid', 0))
        except (ValueError, TypeError):
            return None

        if port_id < 1 or port_id > 65535:
            return None

        protocol = port_elem.get('protocol', 'tcp')

        svc_elem = port_elem.find('service')
        if svc_elem is not None:
            service_name = svc_elem.get('name', 'unknown')
            product = svc_elem.get('product', '')
            version = svc_elem.get('version', '')
            extra_info = svc_elem.get('extrainfo', '')
            cpes = [c.text for c in svc_elem.findall('cpe') if c.text]
            try:
                confidence = int(svc_elem.get('conf', 0))
            except (ValueError, TypeError):
                confidence = 0
        else:
            service_name = 'unknown'
            product = ''
            version = ''
            extra_info = ''
            cpes = []
            confidence = 0

        port_scripts = []
        for script_elem in port_elem.findall('script'):
            port_scripts.append({
                'id': script_elem.get('id', ''),
                'output': script_elem.get('output', '')[:1000],
            })

        normalized = ServiceNormalizer.service_fingerprint({
            'service': service_name,
            'product': product,
            'version': version,
            'cpe': cpes,
        })

        return {
            'port': port_id,
            'protocol': protocol,
            'state': 'open',
            'service': service_name,
            'product': product,
            'version': version,
            'extra_info': extra_info,
            'cpe': cpes,
            'confidence': confidence,
            'scripts': port_scripts,
            'normalized_product': normalized['normalized_product'],
            'tokens': normalized['tokens'],
        }

    @staticmethod
    def _extract_host_scripts(host_elem: ET.Element) -> List[Dict]:
        scripts = []
        hostscript = host_elem.find('hostscript')
        if hostscript is not None:
            for script_elem in hostscript.findall('script'):
                scripts.append({
                    'id': script_elem.get('id', ''),
                    'output': script_elem.get('output', '')[:1000],
                })
        return scripts

    @staticmethod
    def extract_vulnerabilities(xml_str: str) -> List[Dict]:
        vulns = []

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML for vulns: {e}")
            return vulns

        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')

        for host_elem in root.findall('.//host'):
            host_ip = NmapXMLParser._extract_ip(host_elem) or 'unknown'

            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    try:
                        port_id = int(port_elem.get('portid', 0))
                    except (ValueError, TypeError):
                        port_id = 0

                    for script_elem in port_elem.findall('script'):
                        vuln = NmapXMLParser._check_vuln_script(script_elem, cve_pattern)
                        if vuln is not None:
                            vuln['host'] = host_ip
                            vuln['port'] = port_id
                            vulns.append(vuln)

            hostscript = host_elem.find('hostscript')
            if hostscript is not None:
                for script_elem in hostscript.findall('script'):
                    vuln = NmapXMLParser._check_vuln_script(script_elem, cve_pattern)
                    if vuln is not None:
                        vuln['host'] = host_ip
                        vuln['port'] = None
                        vulns.append(vuln)

        return vulns

    @staticmethod
    def _check_vuln_script(script_elem: ET.Element, cve_pattern: re.Pattern) -> Optional[Dict]:
        output = script_elem.get('output', '')
        if 'VULNERABLE' not in output.upper():
            return None

        cve_matches = cve_pattern.findall(output)

        return {
            'script': script_elem.get('id', ''),
            'status': 'vulnerable',
            'cves': list(set(cve_matches)),
            'details': output[:1000],
        }


# ═══════════════════════════════════════════════════════════════
# ASSET CLASSIFIER
# ═══════════════════════════════════════════════════════════════


class AssetClassifier:
    DB_INDICATORS: Set[str] = {
        'mysql', 'postgresql', 'postgres', 'mongodb',
        'oracle', 'mssql', 'redis', 'mariadb',
        'elasticsearch', 'cassandra', 'couchdb',
    }

    WEB_INDICATORS: Set[str] = {
        'http', 'apache', 'nginx', 'tomcat', 'iis',
    }

    INFRA_INDICATORS: Set[str] = {
        'domain', 'dns', 'ldap', 'kerberos',
        'dhcp', 'ntp', 'snmp', 'ssh',
    }

    @classmethod
    def classify_criticality(cls, services: List[Dict]) -> str:
        if not services:
            return 'low'

        max_criticality = 'low'

        for svc in services:
            tokens = set(svc.get('tokens', []) or [])
            tokens.update(ServiceNormalizer.tokenize(svc.get('service', '')))
            tokens.update(ServiceNormalizer.tokenize(svc.get('product', '')))

            if tokens & cls.DB_INDICATORS:
                return 'critical'
            if tokens & cls.WEB_INDICATORS:
                max_criticality = 'high'
            elif tokens & cls.INFRA_INDICATORS and max_criticality != 'high':
                max_criticality = 'medium'

        return max_criticality

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            logger.warning(f"Could not parse IP: {ip_str}")
            return False


# ═══════════════════════════════════════════════════════════════
# PORT SPEC BUILDER
# ═══════════════════════════════════════════════════════════════


class PortSpec:
    @staticmethod
    def top_ports(count: int) -> List[str]:
        count = InputValidator.validate_top_ports(count)
        return ['--top-ports', str(count)]

    @staticmethod
    def all_ports() -> List[str]:
        return ['-p-']

    @staticmethod
    def port_range(ports: str) -> List[str]:
        validated = InputValidator.validate_ports(ports)
        return ['-p', validated]


# ═══════════════════════════════════════════════════════════════
# ACTIVE SCANNER
# ═══════════════════════════════════════════════════════════════


class ActiveScanner:
    def __init__(self, config: Optional[ScanConfig] = None):
        self._config = config or ScanConfig()
        self._nmap_available: Optional[bool] = None
        self._nmap_version: str = ''
        self._parser = NmapXMLParser()

        self.scan_history: deque = deque(maxlen=self._config.MAX_HISTORY_SIZE)
        self._semaphore = threading.Semaphore(self._config.MAX_CONCURRENT_SCANS)
        self._rate_lock = threading.Lock()
        self._last_scan_times: Dict[str, datetime] = {}
        self._process_lock = threading.Lock()
        self._active_processes: Dict[str, subprocess.Popen] = {}

    # ───────────────────────────────────────────────────────────
    # NMAP DETECTION
    # ───────────────────────────────────────────────────────────

    @property
    def nmap_available(self) -> bool:
        if self._nmap_available is None:
            self._nmap_available, self._nmap_version = self._detect_nmap()
        return self._nmap_available

    @property
    def nmap_version(self) -> str:
        if self._nmap_available is None:
            _ = self.nmap_available
        return self._nmap_version

    def _detect_nmap(self) -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                [self._config.NMAP_BINARY, '--version'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version_match = re.search(r'Nmap version ([\d.]+)', result.stdout)
                version = version_match.group(1) if version_match else 'unknown'
                logger.info(f"Nmap detected: version {version}")
                return True, version
        except FileNotFoundError:
            logger.error(f"Nmap binary not found: {self._config.NMAP_BINARY}")
        except subprocess.TimeoutExpired:
            logger.error("Nmap version check timed out")
        except Exception as e:
            logger.error(f"Nmap detection failed: {e}")

        return False, ''

    # ───────────────────────────────────────────────────────────
    # PUBLIC SCAN METHODS
    # ───────────────────────────────────────────────────────────

    def quick_scan(self, target: str) -> Dict:
        return self._run_scan(
            target=target,
            port_args=PortSpec.top_ports(100),
            scan_type='quick',
            extra_args=['-sV', '-T4'],
        )

    def full_scan(self, target: str) -> Dict:
        return self._run_scan(
            target=target,
            port_args=PortSpec.all_ports(),
            scan_type='full',
            extra_args=['-sV', '-O', '-A', '-T3'],
        )

    def vuln_scan(self, target: str) -> Dict:
        return self._run_scan(
            target=target,
            port_args=PortSpec.top_ports(1000),
            scan_type='vulnerability',
            extra_args=['-sV', '--script', 'vuln', '--script-timeout', '60s'],
        )

    def stealth_scan(self, target: str) -> Dict:
        return self._run_scan(
            target=target,
            port_args=PortSpec.top_ports(1000),
            scan_type='stealth',
            extra_args=['-sS', '-T2', '-f'],
        )

    def custom_scan(
        self,
        target: str,
        ports: str = '1-1000',
        scripts: Optional[List[str]] = None,
        os_detect: bool = False,
        aggressive: bool = False,
    ) -> Dict:
        args = ['-sV']
        if os_detect:
            args.append('-O')
        if aggressive:
            args.append('-A')
        if scripts:
            validated_scripts = InputValidator.validate_scripts(scripts)
            args.extend(['--script', ','.join(validated_scripts)])

        return self._run_scan(
            target=target,
            port_args=PortSpec.port_range(ports),
            scan_type='custom',
            extra_args=args,
        )

    # ───────────────────────────────────────────────────────────
    # BATCH
    # ───────────────────────────────────────────────────────────

    def batch_scan(
        self,
        targets: List[str],
        scan_type: str = 'quick',
        max_workers: int = 3,
    ) -> List[Dict]:
        if not targets:
            return []

        max_workers = min(
            max_workers,
            self._config.MAX_CONCURRENT_SCANS,
            len(targets),
        )

        scan_fn = self._get_scan_function(scan_type)
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_target = {
                pool.submit(scan_fn, target): target
                for target in targets
            }

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results.append(future.result(timeout=660))
                except Exception as e:
                    logger.error(f"Batch scan failed for {target}: {e}")
                    results.append({
                        'success': False,
                        'target': target,
                        'scan_type': scan_type,
                        'error': str(e),
                    })

        return results

    # ───────────────────────────────────────────────────────────
    # CANCELLATION
    # ───────────────────────────────────────────────────────────

    def cancel_scan(self, scan_id: str) -> bool:
        with self._process_lock:
            proc = self._active_processes.get(scan_id)
            if proc is None:
                logger.warning(f"Scan {scan_id} not found")
                return False
            if proc.poll() is not None:
                self._active_processes.pop(scan_id, None)
                return False

        logger.info(f"Cancelling scan {scan_id}")

        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        except Exception as e:
            logger.error(f"Error cancelling scan {scan_id}: {e}")
            return False
        finally:
            with self._process_lock:
                self._active_processes.pop(scan_id, None)

        return True

    def get_active_scans(self) -> List[str]:
        with self._process_lock:
            return [
                scan_id
                for scan_id, proc in self._active_processes.items()
                if proc.poll() is None
            ]

    # ───────────────────────────────────────────────────────────
    # CORE SCAN
    # ───────────────────────────────────────────────────────────

    def _run_scan(
        self,
        target: str,
        port_args: List[str],
        scan_type: str,
        extra_args: Optional[List[str]] = None,
    ) -> Dict:
        scan_id = str(uuid.uuid4())

        if not self.nmap_available:
            return self._error_result(
                scan_id=scan_id,
                scan_type=scan_type,
                target=target,
                error=f"Nmap not available at '{self._config.NMAP_BINARY}'",
            )

        try:
            validated_target = InputValidator.validate_target(target)
        except InvalidTargetError as e:
            return self._error_result(
                scan_id=scan_id,
                scan_type=scan_type,
                target=target,
                error=str(e),
            )

        try:
            self._check_rate_limit(validated_target)
        except RateLimitError as e:
            return self._error_result(
                scan_id=scan_id,
                scan_type=scan_type,
                target=validated_target,
                error=str(e),
            )

        acquired = self._semaphore.acquire(timeout=30)
        if not acquired:
            return self._error_result(
                scan_id=scan_id,
                scan_type=scan_type,
                target=validated_target,
                error=f"Too many concurrent scans (max {self._config.MAX_CONCURRENT_SCANS})",
            )

        try:
            return self._execute_scan(
                scan_id=scan_id,
                target=validated_target,
                port_args=port_args,
                scan_type=scan_type,
                extra_args=list(extra_args) if extra_args else [],
            )
        finally:
            self._semaphore.release()

    def _execute_scan(
        self,
        scan_id: str,
        target: str,
        port_args: List[str],
        scan_type: str,
        extra_args: List[str],
    ) -> Dict:
        start_time = datetime.utcnow()
        cmd = [self._config.NMAP_BINARY]
        cmd.extend(extra_args)
        cmd.extend(port_args)
        cmd.extend(['-oX', '-', target])

        timeout = self._config.TIMEOUTS.get(scan_type, 600)

        logger.info(f"[{scan_id}] Starting {scan_type} scan: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            with self._process_lock:
                self._active_processes[scan_id] = proc

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
                return self._error_result(
                    scan_id=scan_id,
                    scan_type=scan_type,
                    target=target,
                    error=f"Scan timed out after {timeout} seconds",
                    duration=(datetime.utcnow() - start_time).total_seconds(),
                )

            duration = (datetime.utcnow() - start_time).total_seconds()

            if proc.returncode == -15:
                return self._error_result(
                    scan_id=scan_id,
                    scan_type=scan_type,
                    target=target,
                    error="Scan was cancelled",
                    duration=duration,
                )

            if proc.returncode != 0:
                error_msg = stderr[:500] if stderr else "Unknown nmap error"
                return self._error_result(
                    scan_id=scan_id,
                    scan_type=scan_type,
                    target=target,
                    error=error_msg,
                    duration=duration,
                )

            if len(stdout) > self._config.MAX_OUTPUT_SIZE:
                return self._error_result(
                    scan_id=scan_id,
                    scan_type=scan_type,
                    target=target,
                    error=f"Scan output too large ({len(stdout)} bytes)",
                    duration=duration,
                )

            hosts = self._parser.parse_hosts(stdout)
            vulns = self._parser.extract_vulnerabilities(stdout)

            result = {
                'success': True,
                'scan_id': scan_id,
                'scan_type': scan_type,
                'target': target,
                'hosts': hosts,
                'host_count': len(hosts),
                'total_services': sum(h.get('service_count', 0) for h in hosts),
                'vulnerabilities_found': vulns,
                'vuln_count': len(vulns),
                'duration': round(duration, 2),
                'timestamp': start_time.isoformat() + 'Z',
                'command': ' '.join(cmd),
                'nmap_version': self._nmap_version,
            }

            self.scan_history.append(result)

            logger.info(
                f"[{scan_id}] Scan complete: {len(hosts)} hosts, "
                f"{result['total_services']} services, {len(vulns)} vulns"
            )

            return result

        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"[{scan_id}] Scan failed: {e}", exc_info=True)
            return self._error_result(
                scan_id=scan_id,
                scan_type=scan_type,
                target=target,
                error=str(e),
                duration=duration,
            )
        finally:
            with self._process_lock:
                self._active_processes.pop(scan_id, None)

    # ───────────────────────────────────────────────────────────
    # RATE LIMITING
    # ───────────────────────────────────────────────────────────

    def _check_rate_limit(self, target: str) -> None:
        with self._rate_lock:
            now = datetime.utcnow()
            cutoff = now - timedelta(minutes=10)

            expired = [
                t for t, ts in self._last_scan_times.items()
                if ts < cutoff
            ]
            for t in expired:
                del self._last_scan_times[t]

            last_time = self._last_scan_times.get(target)
            if last_time is not None:
                elapsed = (now - last_time).total_seconds()
                remaining = self._config.MIN_SCAN_INTERVAL - elapsed
                if remaining > 0:
                    raise RateLimitError(
                        f"Rate limited: wait {remaining:.0f}s before scanning {target} again"
                    )

            self._last_scan_times[target] = now

    # ───────────────────────────────────────────────────────────
    # DISCOVERY & SAVE
    # ───────────────────────────────────────────────────────────

    def discover_and_save(self, target: str, scan_type: str = 'quick') -> Dict:
        scan_fn = self._get_scan_function(scan_type)
        result = scan_fn(target)

        if not result.get('success'):
            return result

        saved_count = self._persist_hosts(result.get('hosts', []))
        result['assets_saved'] = saved_count
        return result

    def _persist_hosts(self, hosts: List[Dict]) -> int:
        from simulation.models import AssetInventory

        saved = 0

        for host in hosts:
            ip = host.get('ip')
            if not ip:
                continue

            try:
                services = self._normalize_services_for_storage(host.get('services', []))
                is_private = AssetClassifier.is_private_ip(ip)
                criticality = AssetClassifier.classify_criticality(services)

                hostname = host.get('hostname', ip)[:253]
                os_type = host.get('os', '')[:255]

                AssetInventory.objects.update_or_create(
                    ip_address=ip,
                    defaults={
                        'hostname': hostname,
                        'os_type': os_type,
                        'services': services,
                        'internet_facing': not is_private,
                        'behind_firewall': is_private,
                        'criticality': criticality,
                        'scan_method': 'nmap_discovery',
                    },
                )
                saved += 1

            except Exception as e:
                logger.error(f"Failed to save asset {ip}: {e}", exc_info=True)

        logger.info(f"Persisted {saved}/{len(hosts)} discovered assets")
        return saved

    def _normalize_services_for_storage(self, services: List[Dict]) -> List[Dict]:
        normalized = []
        for svc in services:
            fp = ServiceNormalizer.service_fingerprint(svc)
            normalized.append({
                **svc,
                'normalized_product': fp['normalized_product'],
                'tokens': fp['tokens'],
                'normalized_version': fp['version'],
                'parsed_cpes': fp['cpes'],
            })
        return normalized

    # ───────────────────────────────────────────────────────────
    # CVE ↔ ASSET MATCHING
    # ───────────────────────────────────────────────────────────

    def match_cves_to_assets(self) -> List[Dict]:
        """
        Match stored CVEs against discovered assets using:
        1. exact/partial CPE matching
        2. normalized product matching
        3. token overlap matching
        4. service-name fallback matching

        This is the critical correlation layer for real asset context.
        """
        from simulation.models import AssetInventory, CVERecord, CVEAssetMapping

        cves = list(CVERecord.objects.exclude(status='mitigated'))
        assets = list(AssetInventory.objects.all())

        if not cves:
            logger.info("No CVEs available for matching")
            return []

        if not assets:
            logger.info("No assets available for matching")
            return []

        cve_index = self._build_cve_match_index(cves)
        mappings_created = []
        seen_pairs: Set[Tuple[str, str, str]] = set()

        for asset in assets:
            services = asset.services or []
            for svc in services:
                service_fp = ServiceNormalizer.service_fingerprint(svc)
                candidates = self._find_candidate_cves(service_fp, cve_index)

                for cve, affected in candidates:
                    pair_key = (
                        cve.cve_id,
                        str(asset.ip_address),
                        affected['raw'],
                    )
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)

                    confidence, match_reason = self._score_service_to_cve_match(
                        service_fp=service_fp,
                        affected=affected,
                    )

                    if confidence < 45:
                        continue

                    try:
                        mapping, created = CVEAssetMapping.objects.get_or_create(
                            cve=cve,
                            asset=asset,
                            matched_product=affected['raw'],
                            defaults={
                                'matched_service': svc,
                                'confidence_score': confidence,
                                'is_exploitable': bool(cve.exploit_available),
                            },
                        )

                        if created:
                            mappings_created.append({
                                'cve_id': cve.cve_id,
                                'asset': getattr(asset, 'hostname', '') or asset.ip_address,
                                'ip': asset.ip_address,
                                'product': affected['raw'],
                                'confidence': confidence,
                                'reason': match_reason,
                                'is_exploitable': bool(cve.exploit_available),
                            })

                    except Exception as e:
                        logger.error(
                            f"CVE mapping failed {cve.cve_id} → {asset.ip_address}: {e}",
                            exc_info=True,
                        )

        logger.info(f"CVE matching complete: {len(mappings_created)} new mappings created")
        return mappings_created

    def _build_cve_match_index(self, cves: List) -> Dict[str, List[Tuple]]:
        """
        Build multiple lookup indices for stronger matching.
        """
        index = {
            'cpe_vendor_product': {},
            'product': {},
            'token': {},
        }

        for cve in cves:
            affected_products = cve.affected_products or []
            for raw_product in affected_products:
                affected = ServiceNormalizer.normalize_affected_product(raw_product)

                # CPE-style vendor/product exact index
                if affected['vendor'] and affected['product']:
                    key = f"{affected['vendor']}:{affected['product']}"
                    index['cpe_vendor_product'].setdefault(key, []).append((cve, affected))

                # Product index
                if affected['product']:
                    index['product'].setdefault(affected['product'], []).append((cve, affected))

                # Token index
                for token in affected['tokens']:
                    index['token'].setdefault(token, []).append((cve, affected))

        return index

    def _find_candidate_cves(self, service_fp: Dict, cve_index: Dict) -> List[Tuple]:
        """
        Find likely candidate CVEs using multiple indices.
        """
        candidates = []
        seen: Set[Tuple[str, str]] = set()

        # 1. Exact/partial CPE vendor:product
        for cpe in service_fp.get('cpes', []):
            if cpe.get('vendor') and cpe.get('product'):
                key = f"{cpe['vendor']}:{cpe['product']}"
                for cve, affected in cve_index['cpe_vendor_product'].get(key, []):
                    marker = (cve.cve_id, affected['raw'])
                    if marker not in seen:
                        candidates.append((cve, affected))
                        seen.add(marker)

        # 2. Normalized product
        np = service_fp.get('normalized_product')
        if np:
            for cve, affected in cve_index['product'].get(np, []):
                marker = (cve.cve_id, affected['raw'])
                if marker not in seen:
                    candidates.append((cve, affected))
                    seen.add(marker)

        # 3. Token overlap
        for token in service_fp.get('tokens', []):
            for cve, affected in cve_index['token'].get(token, []):
                marker = (cve.cve_id, affected['raw'])
                if marker not in seen:
                    candidates.append((cve, affected))
                    seen.add(marker)

        return candidates

    def _score_service_to_cve_match(self, service_fp: Dict, affected: Dict) -> Tuple[int, str]:
        """
        Calculate confidence score using:
        - CPE vendor/product exact
        - product equality
        - version equality
        - token overlap
        """
        reasons = []
        score = 0

        service_tokens = set(service_fp.get('tokens', []))
        affected_tokens = set(affected.get('tokens', []))

        # CPE exact / vendor product
        service_cpes = service_fp.get('cpes', [])
        for scpe in service_cpes:
            if (
                scpe.get('vendor') and affected.get('vendor') and
                scpe.get('product') and affected.get('product')
            ):
                if (
                    scpe['vendor'] == affected['vendor'] and
                    scpe['product'] == affected['product']
                ):
                    score = max(score, 90)
                    reasons.append("Exact vendor/product CPE match")

                    if (
                        scpe.get('version') and affected.get('version') and
                        scpe['version'] == affected['version']
                    ):
                        score = max(score, 98)
                        reasons.append("Exact CPE version match")

        # Normalized product exact
        if (
            service_fp.get('normalized_product') and
            affected.get('product') and
            service_fp['normalized_product'] == affected['product']
        ):
            score = max(score, 75)
            reasons.append("Normalized product match")

        # Version
        if (
            service_fp.get('version') and affected.get('version') and
            service_fp['version'] == affected['version']
        ):
            score += 15
            reasons.append("Exact version match")
        elif (
            service_fp.get('version') and affected.get('version') and
            service_fp['version'].startswith(affected['version'])
        ):
            score += 8
            reasons.append("Partial version prefix match")

        # Token overlap
        overlap = service_tokens & affected_tokens
        if overlap:
            overlap_ratio = len(overlap) / max(1, len(affected_tokens))
            if overlap_ratio >= 0.75:
                score = max(score, 70)
                reasons.append(f"Strong token overlap: {', '.join(sorted(overlap)[:3])}")
            elif overlap_ratio >= 0.5:
                score = max(score, 55)
                reasons.append(f"Moderate token overlap: {', '.join(sorted(overlap)[:3])}")

        # Service-name fallback
        if (
            service_fp.get('service') and
            service_fp['service'] in affected_tokens
        ):
            score = max(score, 50)
            reasons.append("Service name matched affected product tokens")

        score = min(score, 100)

        if not reasons:
            return 0, "No meaningful match"

        return score, '; '.join(reasons)

    # ───────────────────────────────────────────────────────────
    # HELPERS
    # ───────────────────────────────────────────────────────────

    def _get_scan_function(self, scan_type: str):
        scan_map = {
            'quick': self.quick_scan,
            'full': self.full_scan,
            'vuln': self.vuln_scan,
            'vulnerability': self.vuln_scan,
            'stealth': self.stealth_scan,
        }
        fn = scan_map.get(scan_type)
        if fn is None:
            logger.warning(f"Unknown scan type '{scan_type}', defaulting to quick")
            fn = self.quick_scan
        return fn

    @staticmethod
    def _error_result(
        scan_id: str,
        scan_type: str,
        target: str,
        error: str,
        duration: float = 0.0,
    ) -> Dict:
        return {
            'success': False,
            'scan_id': scan_id,
            'scan_type': scan_type,
            'target': target,
            'error': error,
            'duration': round(duration, 2),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'hosts': [],
            'host_count': 0,
            'total_services': 0,
            'vulnerabilities_found': [],
            'vuln_count': 0,
        }

    def get_scan_history(
        self,
        limit: int = 50,
        scan_type: Optional[str] = None,
        success_only: bool = False,
    ) -> List[Dict]:
        history = list(self.scan_history)
        history.reverse()

        if scan_type:
            history = [h for h in history if h.get('scan_type') == scan_type]
        if success_only:
            history = [h for h in history if h.get('success') is True]

        return history[:limit]

    def get_stats(self) -> Dict:
        history = list(self.scan_history)
        successful = [h for h in history if h.get('success')]
        failed = [h for h in history if not h.get('success')]

        total_hosts = sum(h.get('host_count', 0) for h in successful)
        total_vulns = sum(h.get('vuln_count', 0) for h in successful)
        total_services = sum(h.get('total_services', 0) for h in successful)

        avg_duration = 0.0
        if successful:
            avg_duration = sum(h.get('duration', 0) for h in successful) / len(successful)

        return {
            'nmap_available': self.nmap_available,
            'nmap_version': self.nmap_version,
            'total_scans': len(history),
            'successful_scans': len(successful),
            'failed_scans': len(failed),
            'total_hosts_discovered': total_hosts,
            'total_services_found': total_services,
            'total_vulns_found': total_vulns,
            'average_duration': round(avg_duration, 2),
            'active_scans': len(self.get_active_scans()),
            'history_capacity': f"{len(history)}/{self._config.MAX_HISTORY_SIZE}",
        }