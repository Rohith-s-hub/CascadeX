# simulation/services/asset_intelligence.py
# Change line 5 FROM:
#   from simulation.models import AssetInventory
# TO:

import subprocess
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict

logger = logging.getLogger(__name__)


class AssetIntelligence:
    """
    Production-Grade Asset Intelligence
    Maps physical network reality to logical vulnerability records.
    """

    def __init__(self):
        self.nmap_available = self._check_nmap()

    def _check_nmap(self) -> bool:
        """Verify Nmap is installed"""
        try:
            subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning(
                "Nmap not found. Asset discovery disabled."
            )
            return False

    def discover_network_assets(
        self,
        target: str,
        ports: str = "1-1000",
        aggressive: bool = False,
    ) -> List[Dict]:
        """Executes Nmap scan and parses output"""
        if not self.nmap_available:
            return []

        cmd = ['nmap', '-sV', '-p', ports, '-oX', '-', target]
        if aggressive:
            cmd.extend(['-O', '-A'])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return self._parse_nmap_xml(result.stdout)
        except Exception as e:
            logger.error(f"Nmap scan failed for {target}: {e}")
            return []

    def _parse_nmap_xml(self, xml_string: str) -> List[Dict]:
        """Parses raw Nmap XML into asset dictionaries"""
        assets = []
        try:
            root = ET.fromstring(xml_string)
            for host in root.findall('.//host'):
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                address = host.find('.//address[@addrtype="ipv4"]')
                ip = address.get('addr') if address is not None else 'unknown'

                hostname_elem = host.find('.//hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else ip

                os_elem = host.find('.//osmatch')
                os_type = os_elem.get('name', '') if os_elem is not None else ''

                services = []
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is None or state.get('state') != 'open':
                        continue

                    svc = port.find('service')
                    services.append({
                        'port': int(port.get('portid')),
                        'service': svc.get('name', 'unknown') if svc is not None else 'unknown',
                        'product': svc.get('product', '') if svc is not None else '',
                        'version': svc.get('version', '') if svc is not None else '',
                    })

                assets.append({
                    'hostname': hostname,
                    'ip_address': ip,
                    'os_type': os_type,
                    'services': services,
                })
        except ET.ParseError:
            logger.error("Failed to parse Nmap XML output.")
        return assets

    def save_to_inventory(self, assets: List[Dict]) -> int:
        """
        Persists discovered assets to Django database.
        Import is done HERE (inside function) to avoid
        circular import issues at module load time.
        """
        # Late import to prevent crash during Django startup
        from simulation.models import AssetInventory

        saved_count = 0
        for asset in assets:
            try:
                ip = asset['ip_address']
                is_private = ip.startswith(
                    ('192.168.', '10.', '172.16.', '172.17.',
                     '172.18.', '172.19.', '172.20.', '172.21.',
                     '172.22.', '172.23.', '172.24.', '172.25.',
                     '172.26.', '172.27.', '172.28.', '172.29.',
                     '172.30.', '172.31.',)
                )

                # Determine criticality from services
                criticality = 'medium'
                for svc in asset.get('services', []):
                    svc_name = svc.get('service', '').lower()
                    product = svc.get('product', '').lower()

                    if any(db in svc_name or db in product
                           for db in ['mysql', 'postgresql',
                                      'mongodb', 'oracle',
                                      'mssql', 'redis']):
                        criticality = 'critical'
                        break
                    elif any(web in svc_name or web in product
                             for web in ['http', 'apache',
                                         'nginx', 'tomcat']):
                        criticality = 'high'

                AssetInventory.objects.update_or_create(
                    ip_address=ip,
                    defaults={
                        'hostname': asset.get('hostname', ip),
                        'os_type': asset.get('os_type', ''),
                        'services': asset.get('services', []),
                        'internet_facing': not is_private,
                        'behind_firewall': is_private,
                        'criticality': criticality,
                        'scan_method': 'nmap',
                    },
                )
                saved_count += 1
            except Exception as e:
                logger.error(
                    f"Error saving asset {asset.get('ip_address')}: {e}"
                )
        return saved_count