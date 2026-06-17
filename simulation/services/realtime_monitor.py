# simulation/services/realtime_monitor.py
"""
Real-Time Vulnerability Monitor
═══════════════════════════════════════════════════════════════
Background monitoring for new CVEs, exploit releases,
and asset changes.

Improved behavior:
- No empty alerts
- Deduplicated repetitive alerts
- Better severity mapping
- Timezone-aware timestamps
- Proper logging
"""

import logging
import threading
import time
from datetime import timedelta
from typing import List, Dict, Callable, Optional

from django.utils import timezone

logger = logging.getLogger(__name__)


class ThreatFeed:
    """
    Monitors multiple threat intelligence sources
    """

    def __init__(self):
        self.feeds = {
            'nvd': {
                'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                'interval': 300,
                'last_check': None,
            },
            'cisa_kev': {
                'url': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                'interval': 3600,
                'last_check': None,
            },
        }
        self.callbacks: List[Callable] = []

    def register_callback(self, callback: Callable):
        self.callbacks.append(callback)

    def _notify(self, event_type: str, data: Dict):
        for cb in self.callbacks:
            try:
                cb(event_type, data)
            except Exception as e:
                logger.error(f"ThreatFeed callback failed: {e}", exc_info=True)


class RealtimeMonitor:
    """
    Background monitoring service
    """

    ALERT_DEDUP_WINDOWS = {
        'new_critical_cves': 3600,  # 1 hour
        'stale_assets': 21600,      # 6 hours
        'kev_update': 86400,        # 24 hours
    }

    def __init__(self):
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.check_interval = 300
        self.alert_threshold_cvss = 7.0
        self.alert_callbacks: List[Callable] = []
        self.last_check = None
        self.stats = {
            'checks_performed': 0,
            'new_cves_found': 0,
            'alerts_sent': 0,
            'errors': 0,
        }

        # dedup cache: alert_key -> timestamp
        self._recent_alerts: Dict[str, float] = {}

    def start(self):
        if self.running:
            logger.warning("Monitor already running")
            return

        self.running = True
        self.thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="cascadex-realtime-monitor",
        )
        self.thread.start()
        logger.info("Real-time monitor started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)
        logger.info("Real-time monitor stopped")

    def register_alert(self, callback: Callable):
        self.alert_callbacks.append(callback)

    def get_status(self) -> Dict:
        return {
            'running': self.running,
            'last_check': (
                self.last_check.isoformat()
                if self.last_check else None
            ),
            'check_interval': self.check_interval,
            'stats': self.stats,
        }

    def _monitor_loop(self):
        while self.running:
            try:
                self._check_new_cves()
                self._check_kev_updates()
                self._check_asset_changes()

                self.last_check = timezone.now()
                self.stats['checks_performed'] += 1
                self._cleanup_recent_alerts()

            except Exception as e:
                logger.error(
                    f"Monitor error: {e}",
                    exc_info=True,
                )
                self.stats['errors'] += 1

            for _ in range(self.check_interval):
                if not self.running:
                    break
                time.sleep(1)

    def _check_new_cves(self):
        from simulation.services.nvd_services import NVDService
        from simulation.models import CVERecord

        try:
            nvd = NVDService()
            result = nvd.fetch_cves(days_back=1, max_results=20)

            if not result.get('success'):
                return

            new_cves = result.get('vulnerabilities', [])
            if not new_cves:
                return

            existing_ids = set(
                CVERecord.objects.values_list('cve_id', flat=True)
            )

            truly_new = [
                c for c in new_cves
                if c.get('cve_id') not in existing_ids
            ]

            if not truly_new:
                return

            self.stats['new_cves_found'] += len(truly_new)
            logger.info(f"Found {len(truly_new)} new CVEs")

            for cve in truly_new:
                try:
                    CVERecord.objects.update_or_create(
                        cve_id=cve['cve_id'],
                        defaults={
                            'description': cve.get('description', ''),
                            'cvss_score': cve.get('cvss_score'),
                            'severity': cve.get('severity', 'MEDIUM'),
                            'attack_vector': cve.get('attack_vector', ''),
                            'attack_complexity': cve.get('attack_complexity', ''),
                            'privileges_required': cve.get('privileges_required', ''),
                            'exploit_available': cve.get('exploit_available', False),
                            'patch_available': cve.get('patch_available', False),
                            'affected_products': cve.get('affected_products', []),
                            'cwe_ids': cve.get('cwe_ids', []),
                            'references': cve.get('references', []),
                        },
                    )
                except Exception as e:
                    logger.warning(f"Save failed for {cve.get('cve_id')}: {e}")

            critical = [
                c for c in truly_new
                if (c.get('cvss_score') or 0) >= self.alert_threshold_cvss
            ]

            if critical:
                critical_ids = [c['cve_id'] for c in critical[:5]]
                alert_key = f"new_critical_cves:{','.join(sorted(critical_ids))}"

                self._send_alert({
                    'type': 'new_critical_cves',
                    'count': len(critical),
                    'message': (
                        f"{len(critical)} new critical CVE(s) detected: "
                        f"{', '.join(critical_ids)}"
                    ),
                    'cves': [
                        {
                            'cve_id': c['cve_id'],
                            'cvss': c.get('cvss_score'),
                            'severity': c.get('severity'),
                            'description': c.get('description', '')[:200],
                        }
                        for c in critical
                    ],
                    'timestamp': timezone.now().isoformat(),
                    'severity': 'critical',
                    'dedup_key': alert_key,
                })

        except Exception as e:
            logger.error(f"CVE check failed: {e}", exc_info=True)

    def _check_kev_updates(self):
        import requests
        from simulation.models import CVERecord

        try:
            response = requests.get(
                'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                timeout=30,
            )

            if response.status_code != 200:
                return

            data = response.json()
            kev_cves = {
                v['cveID']
                for v in data.get('vulnerabilities', [])
            }

            our_cves = CVERecord.objects.filter(
                cve_id__in=list(kev_cves),
                exploit_available=False,
            )

            for cve in our_cves:
                cve.exploit_available = True
                cve.save(update_fields=['exploit_available'])

                self._send_alert({
                    'type': 'kev_update',
                    'cve_id': cve.cve_id,
                    'message': (
                        f'{cve.cve_id} added to CISA KEV — active exploitation confirmed'
                    ),
                    'timestamp': timezone.now().isoformat(),
                    'severity': 'high',
                    'dedup_key': f'kev_update:{cve.cve_id}',
                })

        except Exception as e:
            logger.error(f"KEV check failed: {e}", exc_info=True)

    def _check_asset_changes(self):
        from simulation.models import AssetInventory

        try:
            stale_threshold = timezone.now() - timedelta(hours=24)

            stale_qs = AssetInventory.objects.filter(
                last_scanned__lt=stale_threshold,
            )

            stale_count = stale_qs.count()
            if stale_count <= 0:
                return

            top_assets = list(
                stale_qs.values_list('hostname', 'ip_address')[:5]
            )
            asset_labels = [
                host or ip or 'unknown'
                for host, ip in top_assets
            ]

            self._send_alert({
                'type': 'stale_assets',
                'count': stale_count,
                'message': (
                    f'{stale_count} asset(s) have not been scanned in the last 24 hours'
                ),
                'assets': asset_labels,
                'timestamp': timezone.now().isoformat(),
                'severity': 'info' if stale_count < 5 else 'medium',
                'dedup_key': f'stale_assets:{stale_count}',
            })

        except Exception as e:
            logger.error(f"Asset check failed: {e}", exc_info=True)

    def _should_send_alert(self, alert: Dict) -> bool:
        """
        Suppress repeated identical alerts for a cooldown window.
        """
        dedup_key = alert.get('dedup_key')
        if not dedup_key:
            return True

        now_ts = time.time()
        alert_type = alert.get('type', '')
        ttl = self.ALERT_DEDUP_WINDOWS.get(alert_type, 1800)

        last_seen = self._recent_alerts.get(dedup_key)
        if last_seen and (now_ts - last_seen) < ttl:
            logger.info(
                f"Suppressing duplicate alert: {dedup_key}"
            )
            return False

        self._recent_alerts[dedup_key] = now_ts
        return True

    def _cleanup_recent_alerts(self):
        now_ts = time.time()
        max_ttl = max(self.ALERT_DEDUP_WINDOWS.values(), default=3600)

        expired = [
            key for key, ts in self._recent_alerts.items()
            if (now_ts - ts) > max_ttl
        ]
        for key in expired:
            self._recent_alerts.pop(key, None)

    def _send_alert(self, alert: Dict):
        """
        Send alert through DB + callbacks, but only if valid and not duplicate.
        """
        if not alert.get('message'):
            logger.warning(
                f"Skipping invalid alert without message: {alert}"
            )
            return

        if not self._should_send_alert(alert):
            return

        self.stats['alerts_sent'] += 1
        logger.info(
            f"Alert: {alert.get('type')} — {alert.get('message')}"
        )

        try:
            from simulation.models import AlertRecord

            AlertRecord.objects.create(
                alert_type=alert['type'],
                message=alert['message'],
                data=alert,
                severity=alert.get('severity', 'info'),
            )
        except Exception as e:
            logger.error(
                f"Failed to persist alert: {e}",
                exc_info=True,
            )

        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.error(
                    f"Alert callback failed: {e}",
                    exc_info=True,
                )


_monitor = None


def get_monitor() -> RealtimeMonitor:
    global _monitor
    if _monitor is None:
        _monitor = RealtimeMonitor()
    return _monitor