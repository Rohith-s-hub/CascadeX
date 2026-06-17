"""
Risk Trending Service
═══════════════════════════════════════════════════════════════
Event-driven risk snapshot capture and historical trend analysis.

Purpose
-------
This service maintains a historical timeline of the system's
risk posture. It is designed to support:

- manual snapshot capture
- automatic snapshot capture after scan completion
- near-real-time trend updates for frontend dashboards
- delta comparison between snapshots
- trend direction analysis
- backend-friendly polling and future websocket integration

How it works
------------
1. Collect current CVEs and assets
2. Build intelligence using IntelligenceEngine
3. Persist a RiskSnapshot row
4. Return structured data for frontend consumption

Recommended usage
-----------------
Call `capture_snapshot_for_scan(...)` immediately after:
- active network scan completes
- CVE enrichment completes
- asset discovery completes
- exploit intelligence refresh completes

This makes the trend chart update automatically whenever
new scan results are available.
"""

import logging
from typing import Dict, List, Optional, Tuple
from decimal import Decimal, InvalidOperation

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


class RiskTrending:
    """
    Captures and analyzes risk trends over time.

    Features:
    - Manual snapshot capture
    - Automatic snapshot capture after scan completion
    - Snapshot cooldown / deduplication
    - Trend direction calculation
    - Delta analysis between snapshots
    - Frontend-friendly response format
    """

    SNAPSHOT_COOLDOWN_SECONDS = 30
    MAX_CVES_FOR_INTELLIGENCE = 500
    MAX_ASSETS_FOR_INTELLIGENCE = 1000

    # ──────────────────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────────────────

    def capture_snapshot(
        self,
        trigger: str = "manual",
        metadata: Optional[Dict] = None,
        force: bool = False,
    ) -> Dict:
        """
        Capture current system state as a snapshot.

        Parameters
        ----------
        trigger:
            Reason the snapshot is being taken.
            Examples:
                - manual
                - active_scan
                - vuln_scan
                - cve_refresh
                - monitor_update
                - scheduled
        metadata:
            Optional event metadata to store in snapshot.data.
            Example:
                {
                    "scan_id": "...",
                    "scan_type": "quick",
                    "target": "192.168.1.0/24"
                }
        force:
            If True, bypass cooldown deduplication.

        Returns
        -------
        Dict
            Snapshot details including whether it was created
            or skipped due to cooldown.
        """
        from simulation.models import RiskSnapshot

        metadata = metadata or {}

        # Dedup / cooldown logic
        if not force:
            last_snapshot = (
                RiskSnapshot.objects.order_by("-timestamp").first()
            )
            if last_snapshot:
                elapsed = (
                    timezone.now() - last_snapshot.timestamp
                ).total_seconds()
                if elapsed < self.SNAPSHOT_COOLDOWN_SECONDS:
                    logger.info(
                        "Skipping snapshot capture due to cooldown "
                        f"({elapsed:.1f}s < {self.SNAPSHOT_COOLDOWN_SECONDS}s)"
                    )
                    return {
                        "success": True,
                        "created": False,
                        "reason": "cooldown_active",
                        "cooldown_seconds": self.SNAPSHOT_COOLDOWN_SECONDS,
                        "last_snapshot_id": last_snapshot.id,
                        "last_snapshot_timestamp": (
                            last_snapshot.timestamp.isoformat()
                        ),
                    }

        try:
            snapshot_payload = self._build_snapshot_payload()
        except Exception as exc:
            logger.error(
                f"Failed to build risk snapshot payload: {exc}",
                exc_info=True,
            )
            return {
                "success": False,
                "created": False,
                "error": str(exc),
            }

        analytics = snapshot_payload["analytics"]
        system_status = snapshot_payload["system_status"]
        assets = snapshot_payload["assets"]
        vulns = snapshot_payload["vulns"]

        try:
            with transaction.atomic():
                snapshot = RiskSnapshot.objects.create(
                    total_cves=analytics.get("totalVulnerabilities", 0),
                    critical_count=analytics.get("criticalCount", 0),
                    high_count=analytics.get("highCount", 0),
                    medium_count=analytics.get("mediumCount", 0),
                    low_count=analytics.get("lowCount", 0),
                    avg_risk=self._safe_decimal(
                        analytics.get("avgRisk", 0)
                    ),
                    system_health=analytics.get("systemHealth", 100),
                    entry_points=system_status.get("entry_points", 0),
                    assets_scanned=len(assets),
                    asset_matches=system_status.get(
                        "asset_matches_found", 0
                    ),
                    exploit_count=system_status.get(
                        "verified_exploitable", 0
                    ),
                    data={
                        "trigger": trigger,
                        "metadata": metadata,
                        "analytics": analytics,
                        "system_status": system_status,
                        "summary": {
                            "asset_count": len(assets),
                            "vulnerability_count": len(vulns),
                        },
                    },
                )
        except Exception as exc:
            logger.error(
                f"Failed to persist risk snapshot: {exc}",
                exc_info=True,
            )
            return {
                "success": False,
                "created": False,
                "error": str(exc),
            }

        logger.info(
            f"Risk snapshot created successfully: id={snapshot.id}, "
            f"trigger={trigger}, health={snapshot.system_health}, "
            f"cves={snapshot.total_cves}"
        )

        delta = self._build_snapshot_delta(snapshot)

        return {
            "success": True,
            "created": True,
            "snapshot_id": snapshot.id,
            "timestamp": snapshot.timestamp.isoformat(),
            "trigger": trigger,
            "system_health": snapshot.system_health,
            "total_cves": snapshot.total_cves,
            "critical_count": snapshot.critical_count,
            "high_count": snapshot.high_count,
            "medium_count": snapshot.medium_count,
            "low_count": snapshot.low_count,
            "avg_risk": float(snapshot.avg_risk),
            "entry_points": snapshot.entry_points,
            "assets_scanned": snapshot.assets_scanned,
            "asset_matches": snapshot.asset_matches,
            "exploit_count": snapshot.exploit_count,
            "delta": delta,
        }

    def capture_snapshot_for_scan(
        self,
        scan_result: Optional[Dict] = None,
        trigger: str = "active_scan",
        force: bool = False,
    ) -> Dict:
        """
        Capture a snapshot automatically when scan results are available.

        Call this right after your scan pipeline finishes and data has
        already been saved to DB.

        Example usage:
            result = scanner.discover_and_save(target, scan_type="quick")
            if result.get("success"):
                RiskTrending().capture_snapshot_for_scan(result)

        Parameters
        ----------
        scan_result:
            Optional scan result dict from ActiveScanner.
        trigger:
            Event type, e.g. active_scan / vuln_scan / full_scan
        force:
            Force snapshot creation even if cooldown is active
        """
        metadata = {}

        if scan_result:
            metadata = {
                "scan_id": scan_result.get("scan_id"),
                "scan_type": scan_result.get("scan_type"),
                "target": scan_result.get("target"),
                "host_count": scan_result.get("host_count", 0),
                "service_count": scan_result.get("total_services", 0),
                "vuln_count": scan_result.get("vuln_count", 0),
                "duration": scan_result.get("duration", 0),
                "timestamp": scan_result.get("timestamp"),
            }

            if not scan_result.get("success", False):
                logger.info(
                    "Skipping automatic snapshot because scan was not successful"
                )
                return {
                    "success": False,
                    "created": False,
                    "reason": "scan_not_successful",
                    "metadata": metadata,
                }

        return self.capture_snapshot(
            trigger=trigger,
            metadata=metadata,
            force=force,
        )

    def get_trend(
        self,
        days: int = 30,
        limit: Optional[int] = None,
    ) -> Dict:
        """
        Get trend timeline for the specified period.

        Returns:
        - timeline points
        - trend direction
        - summary stats
        - change between first and last snapshot
        """
        from simulation.models import RiskSnapshot

        days = self._normalize_days(days)
        since = timezone.now() - timezone.timedelta(days=days)

        queryset = RiskSnapshot.objects.filter(
            timestamp__gte=since
        ).order_by("timestamp")

        if limit and limit > 0:
            snapshots = list(queryset[:limit])
        else:
            snapshots = list(queryset)

        if not snapshots:
            return {
                "success": True,
                "period_days": days,
                "data_points": 0,
                "trend_direction": "no_data",
                "latest_health": None,
                "change": None,
                "trend": [],
            }

        trend = [self._serialize_snapshot_point(s) for s in snapshots]

        direction = self._calculate_trend_direction(trend)
        change = self._calculate_change_summary(trend)

        latest = trend[-1]
        previous = trend[-2] if len(trend) >= 2 else None

        return {
            "success": True,
            "period_days": days,
            "data_points": len(trend),
            "trend_direction": direction,
            "latest_health": latest["system_health"],
            "latest_timestamp": latest["timestamp"],
            "latest_snapshot_id": latest["snapshot_id"],
            "previous_health": (
                previous["system_health"] if previous else None
            ),
            "change": change,
            "trend": trend,
        }

    def get_latest_snapshot(self) -> Dict:
        """
        Return the latest stored snapshot in frontend-friendly format.
        Useful for dashboard polling.
        """
        from simulation.models import RiskSnapshot

        snapshot = RiskSnapshot.objects.order_by("-timestamp").first()
        if not snapshot:
            return {
                "success": True,
                "exists": False,
                "snapshot": None,
            }

        return {
            "success": True,
            "exists": True,
            "snapshot": self._serialize_snapshot_detail(snapshot),
            "delta": self._build_snapshot_delta(snapshot),
        }

    def get_realtime_dashboard_payload(
        self,
        days: int = 30,
    ) -> Dict:
        """
        Combined API response for frontend dashboards.

        Includes:
        - latest snapshot
        - trend timeline
        - quick summary
        """
        latest = self.get_latest_snapshot()
        trend = self.get_trend(days=days)

        return {
            "success": True,
            "latest": latest,
            "trend": trend,
        }

    # ──────────────────────────────────────────────────────────
    # INTERNAL SNAPSHOT BUILDERS
    # ──────────────────────────────────────────────────────────

    def _build_snapshot_payload(self) -> Dict:
        """
        Gather CVEs and assets and generate intelligence payload.
        """
        from simulation.services.reporting import build_report

        report = build_report(
            include_compliance=False,
            include_trending=False,
            sync_mappings=False,
        )

        assets = report.get("assets", []) or []
        vulns = report.get("vulnerabilities", []) or []
        analytics = report.get("analytics", {}) or {}
        system_status = report.get("system_status", {}) or {}

        return {
            "assets": assets,
            "cves": vulns,
            "vulns": vulns,
            "analytics": analytics,
            "system_status": system_status,
        }

    def _load_current_cves(self):
        """
        Fetch active CVEs used in trend snapshot generation.
        """
        from simulation.models import CVERecord

        return list(
            CVERecord.objects.exclude(status="mitigated")
            .order_by("-published_date", "-id")[
                : self.MAX_CVES_FOR_INTELLIGENCE
            ]
        )

    def _load_current_assets(self) -> List[Dict]:
        """
        Fetch assets in a normalized shape expected by IntelligenceEngine.
        """
        from simulation.models import AssetInventory

        assets = []

        queryset = AssetInventory.objects.all().order_by("id")[
            : self.MAX_ASSETS_FOR_INTELLIGENCE
        ]

        for asset in queryset:
            services = asset.services or []
            primary_service = services[0] if services else {}

            assets.append({
                "id": str(asset.id),
                "name": asset.hostname or asset.ip_address,
                "vendor": "",
                "product": primary_service.get("product", "") or "",
                "version": primary_service.get("version", "") or "",
                "ip_address": asset.ip_address,
                "os_type": getattr(asset, "os_type", "") or "",
                "criticality": getattr(asset, "criticality", "") or "",
                "services": services,
            })

        return assets

    def _build_vulnerability_payload(
        self,
        cves,
    ) -> List[Dict]:
        """
        Normalize CVE records into intelligence engine input.
        """
        vulns: List[Dict] = []

        for cve in cves:
            vendors = self._extract_vendors(
                cve.affected_products or []
            )

            vulns.append({
                "cve_id": cve.cve_id,
                "description": cve.description or "",
                "cvss_score": self._safe_float(
                    cve.cvss_score, default=5.0
                ),
                "severity": cve.severity or "medium",
                "attack_vector": cve.attack_vector or "",
                "attack_complexity": cve.attack_complexity or "",
                "privileges_required": (
                    cve.privileges_required or ""
                ),
                "exploit_available": bool(
                    cve.exploit_available
                ),
                "patch_available": bool(
                    cve.patch_available
                ),
                "affected_products": cve.affected_products or [],
                "affected_vendors": sorted(vendors),
                "cwe_ids": cve.cwe_ids or [],
                "references": cve.references or [],
                "status": cve.status or "",
            })

        return vulns

    # ──────────────────────────────────────────────────────────
    # TREND / DELTA / ANALYSIS
    # ──────────────────────────────────────────────────────────

    def _build_snapshot_delta(
        self,
        snapshot,
    ) -> Optional[Dict]:
        """
        Compare the given snapshot with the previous one.
        """
        from simulation.models import RiskSnapshot

        previous = (
            RiskSnapshot.objects.filter(
                timestamp__lt=snapshot.timestamp
            )
            .order_by("-timestamp")
            .first()
        )

        if not previous:
            return None

        return {
            "vs_snapshot_id": previous.id,
            "health_change": (
                snapshot.system_health - previous.system_health
            ),
            "total_cves_change": (
                snapshot.total_cves - previous.total_cves
            ),
            "critical_change": (
                snapshot.critical_count - previous.critical_count
            ),
            "high_change": (
                snapshot.high_count - previous.high_count
            ),
            "medium_change": (
                snapshot.medium_count - previous.medium_count
            ),
            "low_change": (
                snapshot.low_count - previous.low_count
            ),
            "avg_risk_change": (
                float(snapshot.avg_risk) - float(previous.avg_risk)
            ),
            "entry_points_change": (
                snapshot.entry_points - previous.entry_points
            ),
            "assets_scanned_change": (
                snapshot.assets_scanned - previous.assets_scanned
            ),
            "asset_matches_change": (
                snapshot.asset_matches - previous.asset_matches
            ),
            "exploit_count_change": (
                snapshot.exploit_count - previous.exploit_count
            ),
        }

    def _calculate_trend_direction(
        self,
        trend: List[Dict],
    ) -> str:
        """
        Determine if posture is improving, degrading, or stable.

        Uses health delta from first to last point.
        """
        if len(trend) < 2:
            return "insufficient_data"

        first = trend[0]["system_health"]
        last = trend[-1]["system_health"]
        delta = last - first

        if delta >= 5:
            return "improving"
        if delta <= -5:
            return "degrading"
        return "stable"

    def _calculate_change_summary(
        self,
        trend: List[Dict],
    ) -> Optional[Dict]:
        """
        Summarize change between first and last point.
        """
        if len(trend) < 2:
            return None

        first = trend[0]
        last = trend[-1]

        return {
            "health_change": (
                last["system_health"] - first["system_health"]
            ),
            "total_cves_change": (
                last["total_cves"] - first["total_cves"]
            ),
            "critical_change": (
                last["critical"] - first["critical"]
            ),
            "high_change": (
                last["high"] - first["high"]
            ),
            "avg_risk_change": (
                last["avg_risk"] - first["avg_risk"]
            ),
            "entry_points_change": (
                last["entry_points"] - first["entry_points"]
            ),
            "exploit_count_change": (
                last["exploit_count"] - first["exploit_count"]
            ),
        }

    # ──────────────────────────────────────────────────────────
    # SERIALIZERS
    # ──────────────────────────────────────────────────────────

    def _serialize_snapshot_point(self, snapshot) -> Dict:
        """
        Compact serialization for chart/timeline.
        """
        return {
            "snapshot_id": snapshot.id,
            "timestamp": snapshot.timestamp.isoformat(),
            "system_health": snapshot.system_health,
            "total_cves": snapshot.total_cves,
            "critical": snapshot.critical_count,
            "high": snapshot.high_count,
            "medium": snapshot.medium_count,
            "low": snapshot.low_count,
            "avg_risk": float(snapshot.avg_risk),
            "entry_points": snapshot.entry_points,
            "assets_scanned": snapshot.assets_scanned,
            "asset_matches": snapshot.asset_matches,
            "exploit_count": snapshot.exploit_count,
            "trigger": (snapshot.data or {}).get("trigger", "unknown"),
        }

    def _serialize_snapshot_detail(self, snapshot) -> Dict:
        """
        Detailed serialization for the latest snapshot panel.
        """
        data = snapshot.data or {}

        return {
            "snapshot_id": snapshot.id,
            "timestamp": snapshot.timestamp.isoformat(),
            "total_cves": snapshot.total_cves,
            "critical_count": snapshot.critical_count,
            "high_count": snapshot.high_count,
            "medium_count": snapshot.medium_count,
            "low_count": snapshot.low_count,
            "avg_risk": float(snapshot.avg_risk),
            "system_health": snapshot.system_health,
            "entry_points": snapshot.entry_points,
            "assets_scanned": snapshot.assets_scanned,
            "asset_matches": snapshot.asset_matches,
            "exploit_count": snapshot.exploit_count,
            "trigger": data.get("trigger", "unknown"),
            "metadata": data.get("metadata", {}),
            "analytics": data.get("analytics", {}),
            "system_status": data.get("system_status", {}),
        }

    # ──────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────

    def _extract_vendors(
        self,
        affected_products: List[str],
    ) -> set:
        """
        Extract vendor names from affected_products entries.
        Supports loose formats like:
        - vendor:product
        - cpe:2.3:a:vendor:product:version
        - vendor/product/version
        """
        vendors = set()

        for product in affected_products:
            if not product:
                continue

            if product.startswith("cpe:2.3:"):
                parts = product.split(":")
                if len(parts) >= 5 and parts[3]:
                    vendors.add(parts[3].strip())
                continue

            if ":" in product:
                parts = product.split(":")
                if parts[0].strip():
                    vendors.add(parts[0].strip())
                continue

            if "/" in product:
                parts = product.split("/")
                if parts[0].strip():
                    vendors.add(parts[0].strip())

        return vendors

    def _safe_float(
        self,
        value,
        default: float = 0.0,
    ) -> float:
        """
        Safely convert to float.
        """
        try:
            if value is None or value == "":
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def _safe_decimal(
        self,
        value,
        default: str = "0",
    ) -> Decimal:
        """
        Safely convert numeric values to Decimal for DB fields.
        """
        try:
            if value is None or value == "":
                return Decimal(default)
            return Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            return Decimal(default)

    def _normalize_days(self, days: int) -> int:
        """
        Validate and normalize trend query window.
        """
        try:
            days = int(days)
        except (TypeError, ValueError):
            days = 30

        if days < 1:
            days = 1
        if days > 365:
            days = 365

        return days
