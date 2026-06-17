"""
Canonical reporting helpers for CascadeX.

This module centralizes the transformation from persisted CVEs + assets into
the intelligence/compliance/export payloads used by the UI and JSON export.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from simulation.models import CVERecord
from simulation.services.compliance_engine import ComplianceEngine
from simulation.services.intelligence_engine import IntelligenceEngine

try:
    from simulation.models import AssetInventory, CVEAssetMapping
    ASSET_MODELS_AVAILABLE = True
except Exception:
    ASSET_MODELS_AVAILABLE = False
    AssetInventory = None
    CVEAssetMapping = None


DEFAULT_CVE_LIMIT = 500
DEFAULT_ASSET_LIMIT = 1000


def _parse_datetime_value(value):
    if not value:
        return None
    if hasattr(value, "isoformat"):
        return value
    return parse_datetime(str(value))


def load_asset_inventory(limit: int = DEFAULT_ASSET_LIMIT, user=None) -> List[Dict]:
    if not ASSET_MODELS_AVAILABLE:
        return []

    assets: List[Dict] = []
    if user is not None and not getattr(user, 'is_superuser', False):
        queryset = AssetInventory.objects.filter(owner=user).order_by("id")[:limit]
    elif user is not None and user.is_superuser:
        queryset = AssetInventory.objects.all().order_by("id")[:limit]
    else:
        # No user context — return empty to prevent data leakage
        return []

    for asset in queryset:
        services = asset.services or []
        primary_service = services[0] if services else {}

        if asset.internet_facing:
            exposure = "internet"
        elif asset.requires_vpn:
            exposure = "isolated"
        elif asset.behind_firewall:
            exposure = "internal"
        else:
            exposure = "dmz"

        assets.append({
            "id": str(asset.id),
            "name": asset.hostname or asset.ip_address,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "vendor": str(primary_service.get("vendor", "") or primary_service.get("product", "")).strip().lower(),
            "product": str(primary_service.get("product", "") or asset.os_type or asset.hostname or "").strip().lower().replace(" ", "_"),
            "version": str(primary_service.get("version", "") or asset.os_version or "").strip(),
            "cpe": str(primary_service.get("cpe", "")).strip(),
            "services": services,
            "criticality": asset.criticality or "medium",
            "exposure": exposure,
            "environment": asset.environment or "production",
            "os_type": asset.os_type or "",
            "os_version": asset.os_version or "",
            "internet_facing": bool(asset.internet_facing),
            "behind_firewall": bool(asset.behind_firewall),
            "requires_vpn": bool(asset.requires_vpn),
        })

    return assets


def cve_record_to_dict(cve: CVERecord) -> Dict:
    vendors = set(cve.affected_vendors or [])
    for product_str in (cve.affected_products or []):
        parts = str(product_str).split(":")
        if len(parts) >= 2 and parts[0]:
            vendors.add(parts[0])

    return {
        "cve_id": cve.cve_id,
        "nvd_status": getattr(cve, "nvd_status", "Analyzed"),
        "description": cve.description or "",
        "cvss_score": float(cve.cvss_score) if cve.cvss_score is not None else None,
        "cvss_version": getattr(cve, "cvss_version", "3.1"),
        "severity": cve.severity or "MEDIUM",
        "attack_vector": cve.attack_vector or "",
        "attack_complexity": cve.attack_complexity or "",
        "privileges_required": cve.privileges_required or "",
        "user_interaction": cve.user_interaction or "",
        "scope": cve.scope or "",
        "affected_products": cve.affected_products or [],
        "affected_vendors": sorted(vendors),
        "affected_entries": getattr(cve, "affected_entries", []) or [],
        "cwe_ids": cve.cwe_ids or [],
        "references": cve.references or [],
        "exploit_available": bool(cve.exploit_available),
        "exploit_maturity": getattr(cve, "exploit_maturity", "unknown"),
        "exploit_confidence": getattr(cve, "exploit_confidence", 0),
        "exploit_sources": getattr(cve, "exploit_sources", []) or [],
        "patch_available": bool(cve.patch_available),
        "patch_confidence": getattr(cve, "patch_confidence", 0),
        "patch_sources": getattr(cve, "patch_sources", []) or [],
        "cisa_kev": bool(getattr(cve, "cisa_kev", False)),
        "published_date": cve.published_date.isoformat() if cve.published_date else None,
        "last_modified_date": cve.last_modified_date.isoformat() if cve.last_modified_date else None,
        "status": cve.status or "warning",
        "epss_score": float(cve.epss_score) if cve.epss_score is not None else 0.0,
        "epss_percentile": float(cve.epss_percentile) if cve.epss_percentile is not None else 0.0,
    }


def load_current_vulnerability_payload(
    limit: int = DEFAULT_CVE_LIMIT,
    exclude_mitigated: bool = True,
) -> List[Dict]:
    queryset = CVERecord.objects.all().order_by("-published_date", "-id")
    if exclude_mitigated:
        queryset = queryset.exclude(status="mitigated")
    return [cve_record_to_dict(cve) for cve in queryset[:limit]]


def load_vulnerability_payload_by_ids(cve_ids: Sequence[str]) -> List[Dict]:
    ordered_ids = [str(cve_id).upper() for cve_id in cve_ids if cve_id]
    if not ordered_ids:
        return []

    records = {
        cve.cve_id: cve
        for cve in CVERecord.objects.filter(cve_id__in=ordered_ids)
    }
    return [cve_record_to_dict(records[cve_id]) for cve_id in ordered_ids if cve_id in records]


def persist_vulnerabilities(vulnerabilities: Iterable[Dict]) -> Dict:
    saved = 0
    created = 0
    updated = 0

    for vuln in vulnerabilities:
        cve_id = str(vuln.get("cve_id", "")).upper().strip()
        if not cve_id:
            continue

        defaults = {
            "description": vuln.get("description", ""),
            "nvd_status": vuln.get("nvd_status", "Analyzed"),
            "cvss_score": vuln.get("cvss_score"),
            "cvss_version": vuln.get("cvss_version") or "3.1",
            "severity": vuln.get("severity", "MEDIUM"),
            "attack_vector": vuln.get("attack_vector", ""),
            "attack_complexity": vuln.get("attack_complexity", ""),
            "privileges_required": vuln.get("privileges_required", ""),
            "user_interaction": vuln.get("user_interaction", ""),
            "scope": vuln.get("scope", ""),
            "exploit_available": bool(vuln.get("exploit_available", False)),
            "exploit_maturity": vuln.get("exploit_maturity", "unknown"),
            "exploit_confidence": int(vuln.get("exploit_confidence", 0) or 0),
            "exploit_sources": vuln.get("exploit_sources", []) or [],
            "patch_available": bool(vuln.get("patch_available", False)),
            "patch_confidence": int(vuln.get("patch_confidence", 0) or 0),
            "patch_sources": vuln.get("patch_sources", []) or [],
            "cisa_kev": bool(vuln.get("cisa_kev", False)),
            "affected_products": vuln.get("affected_products", []) or [],
            "affected_vendors": vuln.get("affected_vendors", []) or [],
            "affected_entries": vuln.get("affected_entries", []) or [],
            "cwe_ids": vuln.get("cwe_ids", []) or [],
            "references": vuln.get("references", []) or [],
            "published_date": _parse_datetime_value(vuln.get("published_date")),
            "last_modified_date": _parse_datetime_value(vuln.get("last_modified_date")),
        }

        record, was_created = CVERecord.objects.get_or_create(
            cve_id=cve_id,
            defaults={
                **defaults,
                "status": vuln.get("status", "warning"),
            },
        )

        if was_created:
            created += 1
            saved += 1
            continue

        defaults["status"] = (
            record.status
            if record.status == "mitigated"
            else vuln.get("status", record.status or "warning")
        )

        # ── EPSS: never overwrite existing DB scores with None ───────
        # EPSS scores are fetched separately by EPSSService.
        # Only update if incoming data actually carries a score.
        incoming_epss = vuln.get("epss_score")
        if incoming_epss is not None:
            defaults["epss_score"] = float(incoming_epss)
            defaults["epss_percentile"] = (
                float(vuln["epss_percentile"])
                if vuln.get("epss_percentile") is not None
                else record.epss_percentile
            )
        # If incoming_epss is None, leave DB value untouched.
        # ─────────────────────────────────────────────────────────────

        changed = False
        for field, value in defaults.items():
            if getattr(record, field) != value:
                setattr(record, field, value)
                changed = True

        if changed:
            record.save()
            updated += 1
        saved += 1

    return {
        "saved": saved,
        "created": created,
        "updated": updated,
    }


def _strength_label(score: int) -> str:
    if score >= 80:
        return "strong"
    if score >= 60:
        return "medium"
    return "weak"


def _estimate_compromise(system_status: Dict) -> str:
    overall = system_status.get("overall")
    exploitable = int(system_status.get("exploitable_count", 0) or 0)
    entry_points = int(system_status.get("entry_points", 0) or 0)

    if overall == "critical" or (overall == "at_risk" and exploitable >= 2):
        return "imminent"
    if overall == "at_risk" or entry_points >= 5:
        return "high"
    if overall == "elevated" or exploitable >= 1:
        return "medium"
    return "low"


def _attack_surface_label(entry_points: int) -> str:
    if entry_points >= 10:
        return "High"
    if entry_points >= 3:
        return "Moderate"
    if entry_points >= 1:
        return "Low"
    return "Minimal"


def _augment_system_status(system_status: Dict, attack_chains: List[Dict], nodes: List[Dict]) -> Dict:
    augmented = dict(system_status)
    entry_points = int(augmented.get("entry_points", 0) or 0)

    augmented["full_chains"] = sum(
        1 for chain in attack_chains if chain.get("fully_exploitable")
    )
    augmented["estimated_compromise"] = _estimate_compromise(augmented)
    augmented["attack_surface"] = _attack_surface_label(entry_points)
    augmented["recommendation"] = (
        augmented.get("recommendations")
        or ["Continue monitoring and maintain patch schedule"]
    )[0]
    augmented["asset_matches_found"] = sum(
        len(node.get("asset_matches", []))
        for node in nodes
    )
    augmented["verified_exploitable"] = int(
        augmented.get("exploitable_count", 0) or 0
    )
    return augmented


def _augment_analytics(analytics: Dict, nodes: List[Dict], attack_chains: List[Dict], assets: List[Dict]) -> Dict:
    augmented = dict(analytics)

    applicable = [node for node in nodes if node.get("status") != "not_applicable"]
    matched = [node for node in applicable if node.get("has_asset_match")]
    with_patch = [node for node in applicable if node.get("patch_available")]
    connected = [node for node in applicable if node.get("connection_count", 0) > 0]

    augmented.setdefault("relevant_vulnerabilities", augmented.get("matched_vulnerabilities", 0))
    augmented.setdefault("patched_count", len(with_patch))
    augmented.setdefault("attack_chain_count", len(attack_chains))
    augmented.setdefault("connected_nodes", len(connected))
    augmented.setdefault("isolated_nodes", max(0, len(applicable) - len(connected)))
    augmented.setdefault(
        "asset_coverage",
        int(round((len(matched) / max(1, len(applicable))) * 100)) if assets else 0,
    )

    augmented["totalVulnerabilities"] = augmented.get("total_vulnerabilities", 0)
    augmented["applicableVulnerabilities"] = augmented.get("applicable_vulnerabilities", 0)
    augmented["relevantVulnerabilities"] = augmented.get("relevant_vulnerabilities", 0)
    augmented["matchedVulnerabilities"] = augmented.get("matched_vulnerabilities", 0)
    augmented["unmatchedVulnerabilities"] = augmented.get("unmatched_vulnerabilities", 0)
    augmented["criticalCount"] = augmented.get("critical_count", 0)
    augmented["highCount"] = augmented.get("high_count", 0)
    augmented["mediumCount"] = augmented.get("medium_count", 0)
    augmented["lowCount"] = augmented.get("low_count", 0)
    augmented["avgCvssScore"] = augmented.get("avg_cvss", 0)
    augmented["avgRealRisk"] = augmented.get("avg_risk", 0)
    augmented["avgRisk"] = augmented.get("avg_risk", 0)
    augmented["exploitedCount"] = augmented.get("exploitable_count", 0)
    augmented["patchedCount"] = augmented.get("patched_count", 0)
    augmented["systemHealth"] = augmented.get("system_health", 100)
    augmented["attackChainCount"] = augmented.get("attack_chain_count", 0)
    augmented["connectedNodes"] = augmented.get("connected_nodes", 0)
    augmented["isolatedNodes"] = augmented.get("isolated_nodes", 0)
    augmented["patchCoverage"] = augmented.get("patch_coverage", 100)
    augmented["assetCoverage"] = augmented.get("asset_coverage", 0)
    return augmented


def _compliance_inputs_from_nodes(nodes: List[Dict]) -> List[Dict]:
    inputs: List[Dict] = []

    for node in nodes:
        if node.get("status") == "mitigated":
            continue

        base = {
            "cve_id": node.get("cve_id"),
            "description": node.get("description", ""),
            "severity": node.get("severity", "MEDIUM"),
            "cvss_score": node.get("cvss_score"),
            "attack_stage": node.get("attack_stage", ""),
            "cwe_ids": node.get("cwe_ids", []),
            "exploit_available": bool(node.get("exploit_available")),
            "patch_available": bool(node.get("patch_available")),
            "confidence_score": int(
                node.get("risk_factors", {}).get("evidence_confidence")
                or node.get("relevance_score")
                or 35
            ),
        }

        asset_matches = node.get("asset_matches", []) or []
        if asset_matches:
            for match in asset_matches:
                exposure = str(match.get("asset_exposure", "")).lower()
                inputs.append({
                    **base,
                    "asset_id": str(match.get("asset_id", "")),
                    "asset_name": match.get("asset_name", ""),
                    "matched_product": match.get("matched_cpe") or match.get("asset_product") or "",
                    "internet_facing": exposure in {"internet", "external", "public", "dmz"},
                    "asset_criticality": str(match.get("asset_criticality", "medium")).lower(),
                    "has_asset_match": True,
                    "confidence_score": int(match.get("confidence", base["confidence_score"]) or base["confidence_score"]),
                })
        else:
            inputs.append({
                **base,
                "internet_facing": bool(node.get("is_entry_point")),
                "asset_criticality": "medium",
                "has_asset_match": False,
            })

    return inputs


def build_compliance_assessment_from_nodes(
    nodes: List[Dict],
    frameworks: Optional[List[str]] = None,
) -> Dict:
    engine = ComplianceEngine(frameworks=frameworks)
    assessment = engine.assess_batch(_compliance_inputs_from_nodes(nodes))
    assessment["data_sources"] = {
        "vulnerability_count": len(nodes),
        "frameworks": frameworks or engine.active_frameworks,
        "realtime": True,
        "refreshed_at": timezone.now().isoformat(),
        "asset_matched_vulnerabilities": sum(
            1 for node in nodes if node.get("has_asset_match")
        ),
    }
    return assessment


def sync_asset_mappings(nodes: List[Dict]) -> Dict:
    if not ASSET_MODELS_AVAILABLE:
        return {"created": 0, "updated": 0, "deleted": 0}

    cve_ids = sorted({
        str(node.get("cve_id", "")).upper()
        for node in nodes
        if node.get("cve_id")
    })
    if not cve_ids:
        return {"created": 0, "updated": 0, "deleted": 0}

    cves = {
        cve.cve_id: cve
        for cve in CVERecord.objects.filter(cve_id__in=cve_ids)
    }
    asset_ids = {
        str(match.get("asset_id"))
        for node in nodes
        for match in (node.get("asset_matches") or [])
        if match.get("asset_id") is not None
    }
    assets = {
        str(asset.id): asset
        for asset in AssetInventory.objects.filter(id__in=list(asset_ids))
    }

    desired = {}
    for node in nodes:
        cve_id = str(node.get("cve_id", "")).upper()
        for match in (node.get("asset_matches") or []):
            asset_id = str(match.get("asset_id", "")).strip()
            if cve_id not in cves or asset_id not in assets:
                continue

            matched_product = (
                str(
                    match.get("matched_cpe")
                    or match.get("asset_product")
                    or match.get("asset_name")
                    or ""
                ).strip()
                or "unknown"
            )
            desired[(cve_id, asset_id, matched_product)] = {
                "cve": cves[cve_id],
                "asset": assets[asset_id],
                "matched_product": matched_product,
                "matched_service": {
                    "asset_vendor": match.get("asset_vendor", ""),
                    "asset_product": match.get("asset_product", ""),
                    "asset_version": match.get("asset_version", ""),
                    "asset_exposure": match.get("asset_exposure", ""),
                    "asset_criticality": match.get("asset_criticality", ""),
                    "version_detail": match.get("version_detail", ""),
                },
                "confidence_score": int(match.get("confidence", 0) or 0),
                "is_exploitable": bool(node.get("exploit_available")),
                "match_type": str(match.get("match_type", "product_match") or "product_match"),
            }

    existing = list(
        CVEAssetMapping.objects.filter(cve__cve_id__in=cve_ids)
        .select_related("cve", "asset")
    )
    existing_keys = {
        (mapping.cve.cve_id, str(mapping.asset_id), mapping.matched_product): mapping
        for mapping in existing
    }

    created = 0
    updated = 0
    stale_ids = []

    with transaction.atomic():
        for key, payload in desired.items():
            mapping = existing_keys.get(key)
            if mapping is None:
                CVEAssetMapping.objects.create(**payload)
                created += 1
                continue

            changed = False
            for field in ("matched_service", "confidence_score", "is_exploitable", "match_type"):
                if getattr(mapping, field) != payload[field]:
                    setattr(mapping, field, payload[field])
                    changed = True
            if changed:
                mapping.save(update_fields=["matched_service", "confidence_score", "is_exploitable", "match_type"])
                updated += 1

        for key, mapping in existing_keys.items():
            if key not in desired:
                stale_ids.append(mapping.id)

        deleted = 0
        if stale_ids:
            deleted = CVEAssetMapping.objects.filter(id__in=stale_ids).delete()[0]

    return {"created": created, "updated": updated, "deleted": deleted}


def build_report(
    vulnerabilities: Optional[List[Dict]] = None,
    assets: Optional[List[Dict]] = None,
    include_compliance: bool = False,
    include_trending: bool = False,
    trend_days: int = 30,
    sync_mappings: bool = True,
) -> Dict:
    assets = load_asset_inventory() if assets is None else assets
    vulnerabilities = (
        load_current_vulnerability_payload()
        if vulnerabilities is None
        else vulnerabilities
    )

    intelligence = IntelligenceEngine(assets=assets).build_full_intelligence(vulnerabilities)
    nodes = intelligence.get("nodes", []) or []
    attack_chains = intelligence.get("attack_chains", []) or []

    for node in nodes:
        normalized_connections = []
        for conn in node.get("connections", []) or []:
            score = int(conn.get("score", conn.get("strength", 0)) or 0)
            normalized_connections.append({
                "target": conn.get("target", ""),
                "score": score,
                "strength": conn.get("strength") if isinstance(conn.get("strength"), str) else _strength_label(score),
                "reasons": conn.get("reasons", []) or [],
                "type": conn.get("type", "potential"),
                "chain_viable": bool(conn.get("chain_viable", score >= 80)),
            })
        node["connections"] = normalized_connections
        node["connection_count"] = len(normalized_connections)
        node["connected_ids"] = [conn["target"] for conn in normalized_connections]
        node["asset_relevant"] = bool(node.get("has_asset_match"))
        node["id"] = node.get("cve_id")
        node["name"] = node.get("cve_id")
        node["stability"] = max(0, 100 - int(node.get("risk", 0)))

    if sync_mappings:
        sync_asset_mappings(nodes)

    system_status = _augment_system_status(
        intelligence.get("system_status", {}) or {},
        attack_chains,
        nodes,
    )
    analytics = _augment_analytics(
        intelligence.get("analytics", {}) or {},
        nodes,
        attack_chains,
        assets,
    )

    compliance = None
    if include_compliance:
        compliance = build_compliance_assessment_from_nodes(nodes)

    trending = None
    if include_trending:
        from simulation.services.trending import RiskTrending

        trending_service = RiskTrending()
        trending = {
            "latest": trending_service.get_latest_snapshot(),
            "trend": trending_service.get_trend(days=trend_days),
        }

    return {
        "exportDate": timezone.now().isoformat(),
        "version": "4.1.0",
        "source": "canonical_backend_report",
        "system_status": system_status,
        "compliance": compliance,
        "trending": trending,
        "vulnerabilities": nodes,
        "attack_chains": attack_chains,
        "assets": assets,
        "analytics": analytics,
        "timeline": intelligence.get("timeline", {}) or {},
        "risk_propagation": intelligence.get("risk_propagation", []) or [],
        "prioritized_actions": intelligence.get("prioritized_actions", []) or [],
    }
