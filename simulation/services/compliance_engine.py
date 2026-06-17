"""
Compliance Mapping Engine
═══════════════════════════════════════════════════════════════
Production-grade compliance assessment engine for CascadeX.

Features
--------
- weighted control degradation instead of binary affected/unaffected
- asset-aware compliance impact
- exploitability-aware risk
- differentiation between generic and asset-confirmed impact
- truthful compliance risk classification
- frontend-friendly summaries and detailed controls
"""

import logging
from collections import defaultdict
from statistics import mean
from typing import Dict, List, Optional, Tuple

from django.utils import timezone

logger = logging.getLogger(__name__)
# ═══════════════════════════════════════════════════════════════
# FRAMEWORK DEFINITIONS
# ═══════════════════════════════════════════════════════════════

FRAMEWORKS = {
    'SOC2': {
        'name': 'SOC 2 Type II',
        'controls': {
            'CC6.1': {
                'name': 'Logical and Physical Access Controls',
                'description': 'Protect against unauthorized access.',
                'cwes': ['CWE-287', 'CWE-798', 'CWE-255', 'CWE-269', 'CWE-250'],
                'stages': ['credential_access', 'privilege_escalation'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 1.0,
            },
            'CC6.6': {
                'name': 'Security Event Monitoring',
                'description': 'Detect unauthorized software or execution.',
                'cwes': ['CWE-94', 'CWE-78', 'CWE-434'],
                'stages': ['execution', 'initial_access'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 0.9,
            },
            'CC6.7': {
                'name': 'Restriction of Data Transmission',
                'description': 'Restrict transmission of sensitive data.',
                'cwes': ['CWE-311', 'CWE-319'],
                'stages': ['exfiltration'],
                'severity_trigger': ['CRITICAL', 'HIGH', 'MEDIUM'],
                'weight': 1.0,
            },
            'CC7.1': {
                'name': 'Vulnerability Management',
                'description': 'Monitor and manage vulnerabilities.',
                'cwes': [],
                'stages': [],
                'severity_trigger': ['CRITICAL', 'HIGH', 'MEDIUM'],
                'always_relevant': True,
                'weight': 1.1,
            },
            'CC7.2': {
                'name': 'Incident Response',
                'description': 'Monitor for malicious indicators.',
                'cwes': [],
                'stages': ['impact', 'lateral_movement'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 0.9,
            },
        },
    },
    'PCI_DSS': {
        'name': 'PCI DSS v4.0',
        'controls': {
            '6.2': {
                'name': 'Secure Development',
                'description': 'Develop software securely.',
                'cwes': ['CWE-89', 'CWE-78', 'CWE-79', 'CWE-94', 'CWE-434'],
                'stages': ['initial_access', 'execution'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 1.1,
            },
            '6.3': {
                'name': 'Vulnerability Management',
                'description': 'Identify and address vulnerabilities.',
                'cwes': [],
                'stages': [],
                'severity_trigger': ['CRITICAL', 'HIGH', 'MEDIUM'],
                'always_relevant': True,
                'weight': 1.1,
            },
            '11.3': {
                'name': 'Penetration Testing',
                'description': 'Perform internal and external testing.',
                'cwes': [],
                'stages': ['initial_access', 'privilege_escalation'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 1.0,
            },
            '10.2': {
                'name': 'Audit Logging',
                'description': 'Implement audit logging for anomaly detection.',
                'cwes': ['CWE-778'],
                'stages': ['defense_evasion'],
                'severity_trigger': ['CRITICAL', 'HIGH', 'MEDIUM'],
                'weight': 0.8,
            },
        },
    },
    'HIPAA': {
        'name': 'HIPAA Security Rule',
        'controls': {
            '164.312(a)': {
                'name': 'Access Control',
                'description': 'Allow access only to authorized persons.',
                'cwes': ['CWE-287', 'CWE-269', 'CWE-798'],
                'stages': ['credential_access', 'privilege_escalation'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 1.0,
            },
            '164.312(c)': {
                'name': 'Integrity Controls',
                'description': 'Protect data from improper alteration.',
                'cwes': ['CWE-94', 'CWE-434'],
                'stages': ['execution', 'impact'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 1.0,
            },
            '164.312(e)': {
                'name': 'Transmission Security',
                'description': 'Protect transmitted ePHI.',
                'cwes': ['CWE-311', 'CWE-319'],
                'stages': ['exfiltration'],
                'severity_trigger': ['CRITICAL', 'HIGH', 'MEDIUM'],
                'weight': 1.1,
            },
            '164.308(a)(5)': {
                'name': 'Security Awareness Training',
                'description': 'Maintain security awareness training.',
                'cwes': [],
                'stages': ['reconnaissance'],
                'severity_trigger': ['CRITICAL', 'HIGH', 'MEDIUM'],
                'weight': 0.7,
            },
        },
    },
    'NIST_800_53': {
        'name': 'NIST 800-53 Rev 5',
        'controls': {
            'RA-5': {
                'name': 'Vulnerability Monitoring and Scanning',
                'description': 'Monitor and scan for vulnerabilities.',
                'cwes': [],
                'stages': [],
                'severity_trigger': ['CRITICAL', 'HIGH', 'MEDIUM'],
                'always_relevant': True,
                'weight': 1.1,
            },
            'SI-2': {
                'name': 'Flaw Remediation',
                'description': 'Identify and correct system flaws.',
                'cwes': [],
                'stages': [],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'always_relevant': True,
                'weight': 1.0,
            },
            'AC-6': {
                'name': 'Least Privilege',
                'description': 'Apply least privilege.',
                'cwes': ['CWE-269', 'CWE-250'],
                'stages': ['privilege_escalation'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 1.0,
            },
            'SC-7': {
                'name': 'Boundary Protection',
                'description': 'Control communications at boundaries.',
                'cwes': [],
                'stages': ['initial_access', 'lateral_movement'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 1.0,
            },
            'IR-4': {
                'name': 'Incident Handling',
                'description': 'Implement incident handling capability.',
                'cwes': [],
                'stages': ['impact'],
                'severity_trigger': ['CRITICAL', 'HIGH'],
                'weight': 0.9,
            },
        },
    },
}
SEVERITY_WEIGHTS = {
    'CRITICAL': 1.00,
    'HIGH': 0.75,
    'MEDIUM': 0.45,
    'LOW': 0.20,
    'INFO': 0.05,
}

ASSET_CRITICALITY_WEIGHTS = {
    'critical': 1.00,
    'high': 0.80,
    'medium': 0.55,
    'low': 0.30,
    '': 0.25,
}

FRAMEWORK_THRESHOLDS = {
    'compliant': 85,
    'partially_compliant': 70,
    'at_risk': 50,
    'non_compliant': 0,
}
class ComplianceEngine:
    """
    Compliance assessment engine with honest context handling.
    """

    def __init__(self, frameworks: Optional[List[str]] = None):
        self.active_frameworks = frameworks or list(FRAMEWORKS.keys())

    # ───────────────────────────────────────────────────────────
    # PUBLIC METHODS
    # ───────────────────────────────────────────────────────────

    def assess_vulnerability(self, vulnerability: Dict) -> Dict:
        normalized = self._normalize_vulnerability(vulnerability)
        impacts = self._map_vulnerability_to_controls(normalized)

        affected_frameworks = sorted(
            {impact['framework_key'] for impact in impacts}
        )

        compliance_risk = self._derive_compliance_risk(
            impacts=impacts,
            vulnerability=normalized,
        )

        return {
            'cve_id': normalized['cve_id'],
            'severity': normalized['severity'],
            'base_score': normalized['base_score'],
            'compliance_impacts': impacts,
            'frameworks_affected': affected_frameworks,
            'total_controls_affected': len(impacts),
            'compliance_risk': compliance_risk,
            'explainability': {
                'severity': normalized['severity'],
                'exploit_available': normalized['exploit_available'],
                'attack_stage': normalized['attack_stage'],
                'internet_facing': normalized['internet_facing'],
                'asset_criticality': normalized['asset_criticality'],
                'has_asset_match': normalized['has_asset_match'],
                'generic_only': self._is_generic_only(impacts),
            },
        }

    def assess_batch(self, vulnerabilities: List[Dict]) -> Dict:
        results: List[Dict] = []
        framework_control_state: Dict[str, Dict[str, Dict]] = {}
        framework_totals: Dict[str, Dict] = {}

        for fw_key in self.active_frameworks:
            framework_control_state[fw_key] = {}
            framework_totals[fw_key] = {
                'weighted_control_capacity': 0.0,
                'affected_cves': set(),
                'affected_assets': set(),
            }

            fw = FRAMEWORKS.get(fw_key, {})
            for ctrl_id, ctrl in fw.get('controls', {}).items():
                weight = float(ctrl.get('weight', 1.0))
                framework_control_state[fw_key][ctrl_id] = {
                    'control_id': ctrl_id,
                    'control_name': ctrl['name'],
                    'description': ctrl['description'],
                    'weight': weight,
                    'impact_score': 0.0,
                    'max_possible_score': weight,
                    'matched_cves': set(),
                    'matched_assets': set(),
                    'match_reasons': [],
                    'severity_breakdown': defaultdict(int),
                    'generic_matches': 0,
                    'contextual_matches': 0,
                }
                framework_totals[fw_key]['weighted_control_capacity'] += weight

        for vuln in vulnerabilities:
            assessment = self.assess_vulnerability(vuln)
            results.append(assessment)

            asset_label = (
                vuln.get('asset_name')
                or vuln.get('asset')
                or vuln.get('ip')
                or vuln.get('hostname')
                or ''
            )

            for impact in assessment['compliance_impacts']:
                fw_key = impact['framework_key']
                ctrl_id = impact['control_id']
                ctrl_state = framework_control_state[fw_key][ctrl_id]

                ctrl_state['impact_score'] = min(
                    ctrl_state['max_possible_score'],
                    ctrl_state['impact_score'] + impact['impact_score'],
                )
                ctrl_state['matched_cves'].add(assessment['cve_id'])
                if asset_label:
                    ctrl_state['matched_assets'].add(asset_label)
                ctrl_state['match_reasons'].append(impact['match_reason'])
                ctrl_state['severity_breakdown'][impact['impact']] += 1

                if impact.get('generic_match'):
                    ctrl_state['generic_matches'] += 1
                else:
                    ctrl_state['contextual_matches'] += 1

                framework_totals[fw_key]['affected_cves'].add(assessment['cve_id'])
                if asset_label:
                    framework_totals[fw_key]['affected_assets'].add(asset_label)

        framework_summary = self._build_framework_summary(
            framework_control_state=framework_control_state,
            framework_totals=framework_totals,
        )

        overall_compliance = self._compute_overall_compliance(framework_summary)
        top_findings = self._extract_top_findings(results, limit=15)

        return {
            'success': True,
            'generated_at': timezone.now().isoformat(),
            'results': results,
            'framework_summary': framework_summary,
            'overall_compliance': overall_compliance,
            'top_findings': top_findings,
            'total_vulnerabilities': len(vulnerabilities),
        }

    def assess_current_state(self, frameworks: Optional[List[str]] = None) -> Dict:
        vulnerabilities = self._load_current_vulnerabilities()
        engine = ComplianceEngine(frameworks=frameworks or self.active_frameworks)
        assessment = engine.assess_batch(vulnerabilities)

        assessment['data_sources'] = {
            'vulnerability_count': len(vulnerabilities),
            'frameworks': engine.active_frameworks,
            'realtime': True,
            'refreshed_at': timezone.now().isoformat(),
            'asset_matched_vulnerabilities': sum(
                1 for v in vulnerabilities if v.get('has_asset_match')
            ),
        }
        return assessment

    def generate_report(self, assessment: Dict, framework: Optional[str] = None) -> Dict:
        summary = assessment.get('framework_summary', {})
        results = assessment.get('results', [])

        if framework:
            summary = {k: v for k, v in summary.items() if k == framework}

        findings = []
        for result in results:
            for impact in result.get('compliance_impacts', []):
                if framework and impact['framework_key'] != framework:
                    continue
                findings.append({
                    'cve_id': result['cve_id'],
                    'framework': impact['framework'],
                    'framework_key': impact['framework_key'],
                    'control_id': impact['control_id'],
                    'control_name': impact['control_name'],
                    'severity': impact['impact'],
                    'impact_score': round(impact['impact_score'], 4),
                    'match_reason': impact['match_reason'],
                    'remediation': (
                        f"Remediate {result['cve_id']} and validate compensating "
                        f"controls for {impact['control_id']}."
                    ),
                })

        return {
            'title': 'CascadeX Compliance Report',
            'generated_at': timezone.now().isoformat(),
            'frameworks': summary,
            'overall_compliance': assessment.get('overall_compliance', 100),
            'total_vulnerabilities': len(results),
            'findings_count': len(findings),
            'findings': findings,
        }

    # ───────────────────────────────────────────────────────────
    # LOADING
    # ───────────────────────────────────────────────────────────

    def _load_current_vulnerabilities(self) -> List[Dict]:
        from simulation.models import CVERecord

        vulnerabilities: List[Dict] = []
        queryset = CVERecord.objects.exclude(status='mitigated').order_by('-id')[:1000]

        for cve in queryset:
            base_vuln = {
                'cve_id': cve.cve_id,
                'description': cve.description or '',
                'severity': (cve.severity or 'MEDIUM').upper(),
                'cvss_score': self._safe_float(cve.cvss_score, 5.0),
                'attack_vector': cve.attack_vector or '',
                'attack_complexity': cve.attack_complexity or '',
                'privileges_required': cve.privileges_required or '',
                'exploit_available': bool(getattr(cve, 'exploit_available', False)),
                'patch_available': bool(getattr(cve, 'patch_available', False)),
                'affected_products': cve.affected_products or [],
                'cwe_ids': cve.cwe_ids or [],
                'references': cve.references or [],
                'status': cve.status or '',
                'attack_stage': self._infer_attack_stage(cve),
                'has_asset_match': False,
                'internet_facing': False,
                'asset_criticality': 'medium',
                'confidence_score': 35,
            }

            mapped = self._expand_with_asset_mappings(cve, base_vuln)
            if mapped:
                vulnerabilities.extend(mapped)
            else:
                vulnerabilities.append(base_vuln)

        return vulnerabilities

    def _expand_with_asset_mappings(self, cve, base_vuln: Dict) -> List[Dict]:
        try:
            from simulation.models import CVEAssetMapping
        except Exception:
            return []

        expanded = []
        try:
            mappings = CVEAssetMapping.objects.filter(cve=cve).select_related('asset')[:200]
        except Exception as exc:
            logger.warning(f"Could not load CVEAssetMapping for {cve.cve_id}: {exc}")
            return []

        for mapping in mappings:
            asset = getattr(mapping, 'asset', None)
            if asset is None:
                continue

            vuln = dict(base_vuln)
            vuln['asset_id'] = str(asset.id)
            vuln['asset_name'] = getattr(asset, 'hostname', '') or getattr(asset, 'ip_address', 'unknown')
            vuln['ip'] = getattr(asset, 'ip_address', '')
            vuln['hostname'] = getattr(asset, 'hostname', '')
            vuln['internet_facing'] = bool(getattr(asset, 'internet_facing', False))
            vuln['behind_firewall'] = bool(getattr(asset, 'behind_firewall', False))
            vuln['asset_criticality'] = getattr(asset, 'criticality', 'medium') or 'medium'
            vuln['is_exploitable'] = bool(getattr(mapping, 'is_exploitable', False))
            vuln['confidence_score'] = int(getattr(mapping, 'confidence_score', 50) or 50)
            vuln['matched_product'] = getattr(mapping, 'matched_product', '')
            vuln['service'] = getattr(mapping, 'matched_service', {}) or {}
            vuln['has_asset_match'] = True
            expanded.append(vuln)

        return expanded

    # ───────────────────────────────────────────────────────────
    # NORMALIZATION / SCORING
    # ───────────────────────────────────────────────────────────

    def _normalize_vulnerability(self, vulnerability: Dict) -> Dict:
        severity = str(vulnerability.get('severity', 'MEDIUM')).upper()
        cwe_ids = self._normalize_cwe_ids(vulnerability.get('cwe_ids', []))
        attack_stage = str(vulnerability.get('attack_stage', '')).strip().lower()
        exploit_available = bool(
            vulnerability.get('exploit_available') or vulnerability.get('is_exploitable')
        )
        internet_facing = bool(vulnerability.get('internet_facing', False))
        asset_criticality = str(vulnerability.get('asset_criticality', 'medium')).lower()
        confidence_score = self._safe_int(vulnerability.get('confidence_score', 35), 35)
        has_asset_match = bool(vulnerability.get('has_asset_match', False))

        base_score = self._calculate_vulnerability_score(
            severity=severity,
            cvss=vulnerability.get('cvss_score'),
            exploit_available=exploit_available,
            internet_facing=internet_facing,
            asset_criticality=asset_criticality,
            confidence_score=confidence_score,
            has_asset_match=has_asset_match,
        )

        return {
            **vulnerability,
            'cve_id': vulnerability.get('cve_id', ''),
            'severity': severity,
            'cwe_ids': cwe_ids,
            'attack_stage': attack_stage,
            'exploit_available': exploit_available,
            'internet_facing': internet_facing,
            'asset_criticality': asset_criticality,
            'confidence_score': confidence_score,
            'has_asset_match': has_asset_match,
            'base_score': base_score,
        }

    def _calculate_vulnerability_score(
        self,
        severity: str,
        cvss,
        exploit_available: bool,
        internet_facing: bool,
        asset_criticality: str,
        confidence_score: int,
        has_asset_match: bool,
    ) -> float:
        severity_weight = SEVERITY_WEIGHTS.get(severity, 0.30)
        cvss_weight = min(max(self._safe_float(cvss, 5.0) / 10.0, 0.0), 1.0)
        exploit_weight = 1.0 if exploit_available else 0.60
        exposure_weight = 1.0 if internet_facing else 0.55
        asset_weight = ASSET_CRITICALITY_WEIGHTS.get(asset_criticality, 0.25)

        # confidence is much lower when there is no confirmed asset match
        if has_asset_match:
            confidence_weight = min(max(confidence_score / 100.0, 0.35), 1.0)
        else:
            confidence_weight = min(max(confidence_score / 100.0, 0.10), 0.45)

        score = (
            severity_weight * 0.32 +
            cvss_weight * 0.20 +
            exploit_weight * 0.16 +
            exposure_weight * 0.10 +
            asset_weight * 0.12 +
            confidence_weight * 0.10
        )

        if not has_asset_match:
            score *= 0.75

        return round(min(score, 1.0), 4)

    def _normalize_cwe_ids(self, cwes) -> List[str]:
        if not cwes:
            return []
        normalized = []
        for cwe in cwes:
            value = str(cwe).strip().upper()
            if value.startswith('CWE-'):
                normalized.append(value)
            elif value.isdigit():
                normalized.append(f'CWE-{value}')
        return list(sorted(set(normalized)))

    # ───────────────────────────────────────────────────────────
    # CONTROL MAPPING
    # ───────────────────────────────────────────────────────────

    def _map_vulnerability_to_controls(self, vuln: Dict) -> List[Dict]:
        impacts = []

        for fw_key in self.active_frameworks:
            fw = FRAMEWORKS.get(fw_key)
            if not fw:
                continue

            for ctrl_id, ctrl in fw['controls'].items():
                matched, reason, match_strength, generic_match = self._match_control(vuln, ctrl)
                if not matched:
                    continue

                weight = float(ctrl.get('weight', 1.0))
                impact_score = round(
                    min(vuln['base_score'] * weight * match_strength, weight),
                    4,
                )

                impacts.append({
                    'framework': fw['name'],
                    'framework_key': fw_key,
                    'control_id': ctrl_id,
                    'control_name': ctrl['name'],
                    'control_description': ctrl['description'],
                    'impact': vuln['severity'],
                    'impact_score': impact_score,
                    'match_reason': reason,
                    'generic_match': generic_match,
                })

        return impacts

    def _match_control(self, vuln: Dict, ctrl: Dict) -> Tuple[bool, str, float, bool]:
        severity = vuln['severity']
        cwe_ids = set(vuln['cwe_ids'])
        stage = vuln['attack_stage']
        internet_facing = vuln.get('internet_facing', False)
        exploit_available = vuln.get('exploit_available', False)
        has_asset_match = vuln.get('has_asset_match', False)

        if severity not in ctrl.get('severity_trigger', []):
            return False, '', 0.0, False

        ctrl_cwes = set(ctrl.get('cwes', []))
        shared_cwes = cwe_ids & ctrl_cwes
        if shared_cwes:
            return True, f"CWE match: {', '.join(sorted(shared_cwes))}", 1.00, False

        if stage and stage in ctrl.get('stages', []):
            strength = 0.80
            if internet_facing and stage == 'initial_access':
                strength += 0.10
            if exploit_available and stage in ('impact', 'execution', 'initial_access'):
                strength += 0.05
            return True, f"Attack stage '{stage}' maps to this control", min(strength, 1.0), False

        if internet_facing and 'initial_access' in ctrl.get('stages', []):
            return True, "Internet-facing exposure increases control relevance", 0.60, False

        if exploit_available and 'impact' in ctrl.get('stages', []):
            return True, "Exploit availability increases incident relevance", 0.60, False

        if ctrl.get('always_relevant'):
            # always-relevant controls are generic posture controls and should be weaker
            strength = 0.55 if has_asset_match else 0.35
            return True, f"{severity} vulnerability impacts always-relevant control", strength, True

        return False, '', 0.0, False

    # ───────────────────────────────────────────────────────────
    # SUMMARY
    # ───────────────────────────────────────────────────────────

    def _build_framework_summary(
        self,
        framework_control_state: Dict[str, Dict[str, Dict]],
        framework_totals: Dict[str, Dict],
    ) -> Dict:
        summary = {}

        for fw_key in self.active_frameworks:
            fw = FRAMEWORKS[fw_key]
            controls = framework_control_state[fw_key]
            totals = framework_totals[fw_key]

            total_controls = len(controls)
            controls_affected = sum(1 for c in controls.values() if c['impact_score'] > 0)

            control_capacity = totals['weighted_control_capacity'] or 1.0
            actual_impact = sum(
                min(c['impact_score'], c['max_possible_score'])
                for c in controls.values()
            )
            has_any_asset = len(totals["affected_assets"]) > 0
            if not has_any_asset and actual_impact > 0:
                degradation_ratio = min(actual_impact / control_capacity, 0.15)
            else:
                degradation_ratio = min(actual_impact / control_capacity, 1.0)

            compliance_percentage = int(round((1.0 - degradation_ratio) * 100))
            status = self._derive_framework_status(compliance_percentage)

            control_list = []
            for control in controls.values():
                control_list.append({
                    'control_id': control['control_id'],
                    'control_name': control['control_name'],
                    'description': control['description'],
                    'weight': control['weight'],
                    'impact_score': round(control['impact_score'], 4),
                    'max_possible_score': round(control['max_possible_score'], 4),
                    'degradation_percent': int(round(
                        min(
                            control['impact_score'] / max(control['max_possible_score'], 0.0001),
                            1.0
                        ) * 100
                    )),
                    'matched_cve_count': len(control['matched_cves']),
                    'matched_asset_count': len(control['matched_assets']),
                    'matched_cves': sorted(control['matched_cves'])[:20],
                    'matched_assets': sorted(control['matched_assets'])[:20],
                    'severity_breakdown': dict(control['severity_breakdown']),
                    'match_reasons': control['match_reasons'][:10],
                    'generic_matches': control['generic_matches'],
                    'contextual_matches': control['contextual_matches'],
                    'status': 'affected' if control['impact_score'] > 0 else 'healthy',
                })

            control_list.sort(
                key=lambda x: (
                    x['impact_score'],
                    x['contextual_matches'],
                    x['matched_cve_count'],
                ),
                reverse=True,
            )

            summary[fw_key] = {
                'name': fw['name'],
                'total_controls': total_controls,
                'controls_affected': controls_affected,
                'controls_healthy': total_controls - controls_affected,
                'compliance_percentage': compliance_percentage,
                'status': status,
                'affected_cve_count': len(totals['affected_cves']),
                'affected_asset_count': len(totals['affected_assets']),
                'weighted_control_capacity': round(control_capacity, 4),
                'weighted_impact_score': round(actual_impact, 4),
                'degradation_ratio': round(degradation_ratio, 4),
                'top_controls': control_list[:5],
                'controls': control_list,
                'summary_text': self._build_framework_summary_text(
                    fw_name=fw['name'],
                    compliance_percentage=compliance_percentage,
                    controls_affected=controls_affected,
                    total_controls=total_controls,
                    affected_cve_count=len(totals['affected_cves']),
                    affected_asset_count=len(totals['affected_assets']),
                ),
            }

        return summary

    def _build_framework_summary_text(
        self,
        fw_name: str,
        compliance_percentage: int,
        controls_affected: int,
        total_controls: int,
        affected_cve_count: int,
        affected_asset_count: int,
    ) -> str:
        if affected_cve_count == 0:
            return (
                f"{fw_name} currently shows no active mapped findings and appears healthy "
                f"from the available vulnerability data."
            )

        if affected_asset_count > 0:
            return (
                f"{fw_name} is at {compliance_percentage}% posture with "
                f"{controls_affected} of {total_controls} controls impacted by "
                f"{affected_cve_count} mapped vulnerabilities across {affected_asset_count} asset(s)."
            )

        return (
            f"{fw_name} is at {compliance_percentage}% posture with "
            f"{controls_affected} of {total_controls} controls impacted by "
            f"{affected_cve_count} generic vulnerability finding(s) without confirmed asset mapping."
        )

    def _compute_overall_compliance(self, framework_summary: Dict[str, Dict]) -> int:
        if not framework_summary:
            return 100
        values = [fw['compliance_percentage'] for fw in framework_summary.values()]
        return int(round(mean(values))) if values else 100

    def _derive_framework_status(self, compliance_percentage: int) -> str:
        if compliance_percentage >= FRAMEWORK_THRESHOLDS['compliant']:
            return 'compliant'
        if compliance_percentage >= FRAMEWORK_THRESHOLDS['partially_compliant']:
            return 'partially_compliant'
        if compliance_percentage >= FRAMEWORK_THRESHOLDS['at_risk']:
            return 'at_risk'
        return 'non_compliant'

    def _derive_compliance_risk(self, impacts: List[Dict], vulnerability: Dict) -> str:
        if not impacts:
            return 'low'

        max_score = max((i['impact_score'] for i in impacts), default=0)
        frameworks_hit = len({i['framework_key'] for i in impacts})
        generic_only = self._is_generic_only(impacts)
        severity = vulnerability.get('severity')
        exploit_available = vulnerability.get('exploit_available', False)
        internet_facing = vulnerability.get('internet_facing', False)
        has_asset_match = vulnerability.get('has_asset_match', False)

        # Generic-only findings should not inflate to high automatically
        if generic_only:
            if severity == 'CRITICAL' and exploit_available and has_asset_match:
                return 'medium'
            if severity == 'HIGH' and (internet_facing or has_asset_match):
                return 'medium'
            return 'low'

        if severity == 'CRITICAL' and exploit_available and (internet_facing or has_asset_match):
            return 'critical'

        if max_score >= 0.75:
            return 'high'

        if frameworks_hit >= 2 and (internet_facing or exploit_available or has_asset_match):
            return 'high'

        if max_score >= 0.35 or frameworks_hit >= 1:
            return 'medium'

        return 'low'

    def _is_generic_only(self, impacts: List[Dict]) -> bool:
        if not impacts:
            return False
        return all(impact.get('generic_match', False) for impact in impacts)

    def _extract_top_findings(self, results: List[Dict], limit: int = 15) -> List[Dict]:
        findings = []

        for result in results:
            highest_impact = max(
                (impact['impact_score'] for impact in result.get('compliance_impacts', [])),
                default=0,
            )
            findings.append({
                'cve_id': result.get('cve_id'),
                'severity': result.get('severity'),
                'compliance_risk': result.get('compliance_risk'),
                'frameworks_affected': result.get('frameworks_affected', []),
                'total_controls_affected': result.get('total_controls_affected', 0),
                'highest_impact_score': round(highest_impact, 4),
            })

        severity_rank = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}

        findings.sort(
            key=lambda x: (
                x['highest_impact_score'],
                severity_rank.get(x['severity'], 0),
                x['total_controls_affected'],
            ),
            reverse=True,
        )

        return findings[:limit]

    # ───────────────────────────────────────────────────────────
    # HELPERS
    # ───────────────────────────────────────────────────────────

    def _infer_attack_stage(self, cve) -> str:
        cwe_ids = {str(c).upper() for c in (cve.cwe_ids or [])}
        severity = (cve.severity or '').upper()

        if {'CWE-287', 'CWE-798', 'CWE-255'} & cwe_ids:
            return 'credential_access'
        if {'CWE-269', 'CWE-250'} & cwe_ids:
            return 'privilege_escalation'
        if {'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94', 'CWE-434'} & cwe_ids:
            return 'execution'
        if {'CWE-311', 'CWE-319'} & cwe_ids:
            return 'exfiltration'
        if severity == 'CRITICAL':
            return 'impact'
        if severity == 'HIGH':
            return 'initial_access'
        return ''

    def _safe_float(self, value, default: float = 0.0) -> float:
        try:
            if value in (None, ''):
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def _safe_int(self, value, default: int = 0) -> int:
        try:
            if value in (None, ''):
                return default
            return int(value)
        except (TypeError, ValueError):
            return default