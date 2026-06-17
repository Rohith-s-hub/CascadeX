"""
EPSS Service — Exploit Prediction Scoring System
═══════════════════════════════════════════════════════════════
Fetches real exploit probability scores from FIRST.org API.

EPSS = probability a CVE will be exploited in next 30 days
Range: 0.0 to 1.0 (0% to 100%)
Source: https://api.first.org/data/1.0/epss

FREE API — No key required.
Maintained by FIRST.org (Forum of Incident Response and Security Teams)
Trained on real exploit data from millions of sensors worldwide.

Why EPSS matters:
- NVD CVSS tells you HOW SEVERE a vulnerability is
- EPSS tells you HOW LIKELY it will be exploited
- Together they give the most accurate risk picture

Example:
  CVE-2024-1234: CVSS=9.8, EPSS=0.02 → Severe but rarely exploited
  CVE-2024-5678: CVSS=5.5, EPSS=0.94 → Moderate but actively exploited
  → Fix CVE-5678 first despite lower CVSS
"""

import logging
import time
from typing import Dict, List, Optional, Tuple
import requests
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)

EPSS_API_BASE = "https://api.first.org/data/v1/epss"
EPSS_CACHE_TIMEOUT = 3600 * 6  # 6 hours
EPSS_BATCH_SIZE = 100          # API supports up to 100 CVEs per request
EPSS_REQUEST_TIMEOUT = 15


class EPSSService:
    """
    Fetches and caches EPSS scores from FIRST.org API.
    """

    @classmethod
    def get_scores(cls, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Fetch EPSS scores for a list of CVE IDs.

        Returns dict: {cve_id: {'epss': float, 'percentile': float}}
        """
        if not cve_ids:
            return {}

        results = {}
        uncached = []

        # Check cache first
        for cve_id in cve_ids:
            cache_key = f"epss:{cve_id}"
            cached = cache.get(cache_key)
            if cached is not None:
                results[cve_id] = cached
            else:
                uncached.append(cve_id)

        if not uncached:
            logger.debug(f"EPSS: all {len(cve_ids)} scores from cache")
            return results

        # Fetch in batches
        for i in range(0, len(uncached), EPSS_BATCH_SIZE):
            batch = uncached[i:i + EPSS_BATCH_SIZE]
            batch_results = cls._fetch_batch(batch)
            results.update(batch_results)

            # Cache each result
            for cve_id, score_data in batch_results.items():
                cache.set(f"epss:{cve_id}", score_data, EPSS_CACHE_TIMEOUT)

            # For CVEs not in response, cache as 0
            for cve_id in batch:
                if cve_id not in batch_results:
                    zero_data = {'epss': 0.0, 'percentile': 0.0}
                    results[cve_id] = zero_data
                    cache.set(f"epss:{cve_id}", zero_data, EPSS_CACHE_TIMEOUT)

            if i + EPSS_BATCH_SIZE < len(uncached):
                time.sleep(0.5)  # Be respectful to the free API

        logger.info(f"EPSS: fetched {len(uncached)} scores, {len(results)} total")
        return results

    @classmethod
    def get_score(cls, cve_id: str) -> Tuple[float, float]:
        """
        Get EPSS score and percentile for a single CVE.
        Returns (epss_score, percentile) — both 0.0 to 1.0
        """
        results = cls.get_scores([cve_id])
        data = results.get(cve_id, {'epss': 0.0, 'percentile': 0.0})
        return float(data.get('epss', 0.0)), float(data.get('percentile', 0.0))

    @classmethod
    def _fetch_batch(cls, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Fetch a batch of EPSS scores from FIRST.org API.
        """
        try:
            # Build comma-separated CVE list
            cve_param = ','.join(cve_ids)

            response = requests.get(
                EPSS_API_BASE,
                params={'cve': cve_param},
                timeout=EPSS_REQUEST_TIMEOUT,
                headers={'User-Agent': 'CascadeX-Security-Platform/4.0'},
            )

            if not response.ok:
                logger.warning(f"EPSS API returned {response.status_code}")
                return {}

            data = response.json()
            results = {}

            for item in data.get('data', []):
                cve_id = item.get('cve', '').upper()
                if cve_id:
                    results[cve_id] = {
                        'epss': float(item.get('epss', 0.0)),
                        'percentile': float(item.get('percentile', 0.0)),
                    }

            return results

        except requests.Timeout:
            logger.warning("EPSS API timeout — using zero scores")
            return {}
        except Exception as e:
            logger.warning(f"EPSS fetch failed: {e}")
            return {}

    @classmethod
    def enrich_vulnerabilities(cls, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Add EPSS scores to a list of vulnerability dicts.
        Modifies in place and returns the list.
        """
        if not vulnerabilities:
            return vulnerabilities

        cve_ids = [v.get('cve_id', '') for v in vulnerabilities if v.get('cve_id')]
        scores = cls.get_scores(cve_ids)

        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', '').upper()
            score_data = scores.get(cve_id, {'epss': 0.0, 'percentile': 0.0})
            vuln['epss_score'] = score_data.get('epss', 0.0)
            vuln['epss_percentile'] = score_data.get('percentile', 0.0)

        return vulnerabilities

    @classmethod
    def update_db_scores(cls, cve_ids: List[str]) -> int:
        """
        Fetch EPSS scores and save them to CVERecord DB.
        Returns number of records updated.
        """
        from simulation.models import CVERecord

        if not cve_ids:
            return 0

        scores = cls.get_scores(cve_ids)
        updated = 0

        for cve_id, score_data in scores.items():
            try:
                rows = CVERecord.objects.filter(cve_id=cve_id).update(
                    epss_score=score_data.get('epss', 0.0),
                    epss_percentile=score_data.get('percentile', 0.0),
                    epss_updated_at=timezone.now(),
                )
                updated += rows
            except Exception as e:
                logger.warning(f"Failed to update EPSS for {cve_id}: {e}")

        logger.info(f"EPSS: updated {updated} CVERecord entries in DB")
        return updated


def get_epss_service() -> EPSSService:
    return EPSSService()
