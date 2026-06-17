from django.test import TestCase
from django.urls import reverse

from simulation.models import AlertRecord, AssetInventory, CVEAssetMapping, CVERecord
from simulation.services.integrations import get_integration_manager
from simulation.services.reporting import build_report, persist_vulnerabilities


class SimulationApiTests(TestCase):
    def setUp(self):
        manager = get_integration_manager()
        manager.integrations.clear()
        manager.stop()

    def tearDown(self):
        manager = get_integration_manager()
        manager.integrations.clear()
        manager.stop()

    def test_health_endpoint_returns_platform_status(self):
        response = self.client.get(reverse("simulation:health"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(payload["status"], "healthy")
        self.assertIn("database", payload)
        self.assertIn("services", payload)

    def test_alert_acknowledge_persists_state(self):
        alert = AlertRecord.objects.create(
            alert_type="critical_vulnerability",
            message="Critical exposure detected",
            severity="critical",
        )

        response = self.client.post(
            reverse("simulation:alert-acknowledge", args=[alert.id]),
            data={"acknowledged_by": "test-suite"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        alert.refresh_from_db()
        self.assertTrue(alert.acknowledged)
        self.assertEqual(alert.acknowledged_by, "test-suite")

    def test_integration_configure_rejects_unsupported_type(self):
        response = self.client.post(
            reverse("simulation:integrations-configure"),
            data={"type": "email", "config": {}},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])

    def test_integration_configure_persists_webhook_in_status(self):
        configure_response = self.client.post(
            reverse("simulation:integrations-configure"),
            data={
                "type": "webhook",
                "config": {
                    "url": "https://example.com/hooks/cascadex",
                    "secret": "super-secret",
                },
            },
            content_type="application/json",
        )

        self.assertEqual(configure_response.status_code, 200)
        self.assertTrue(configure_response.json()["success"])

        status_response = self.client.get(reverse("simulation:integrations-status"))
        self.assertEqual(status_response.status_code, 200)

        integrations = status_response.json()["status"]["integrations"]
        self.assertEqual(len(integrations), 1)
        self.assertEqual(integrations[0]["type"], "webhook")

    def test_persist_vulnerabilities_keeps_enrichment_and_preserves_mitigation(self):
        CVERecord.objects.create(
            cve_id="CVE-2023-9999",
            status="mitigated",
            severity="HIGH",
        )

        result = persist_vulnerabilities([
            {
                "cve_id": "CVE-2023-9999",
                "description": "Example vulnerability with full enrichment data.",
                "nvd_status": "Analyzed",
                "cvss_score": 9.8,
                "cvss_version": "3.1",
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "exploit_available": True,
                "exploit_maturity": "weaponized",
                "exploit_confidence": 100,
                "exploit_sources": ["cisa_kev"],
                "patch_available": True,
                "patch_confidence": 95,
                "patch_sources": ["vendor"],
                "cisa_kev": True,
                "affected_products": ["acme:demo:1.0"],
                "affected_vendors": ["acme"],
                "affected_entries": [{"vendor": "acme", "product": "demo", "version": "1.0"}],
                "cwe_ids": ["CWE-434"],
                "references": [{"url": "https://example.com/advisory", "tags": ["Patch"]}],
                "status": "warning",
            }
        ])

        self.assertEqual(result["saved"], 1)

        record = CVERecord.objects.get(cve_id="CVE-2023-9999")
        self.assertEqual(record.status, "mitigated")
        self.assertEqual(record.exploit_maturity, "weaponized")
        self.assertEqual(record.exploit_confidence, 100)
        self.assertTrue(record.cisa_kev)
        self.assertEqual(record.affected_entries[0]["product"], "demo")

    def test_canonical_report_keeps_counts_consistent_and_syncs_asset_mappings(self):
        persist_vulnerabilities([
            {
                "cve_id": "CVE-2023-1111",
                "description": "Remote code execution in Demo CMS plugin.",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "attack_vector": "NETWORK",
                "privileges_required": "NONE",
                "affected_products": ["demo:cms_plugin"],
                "affected_vendors": ["demo"],
                "affected_entries": [
                    {
                        "vendor": "demo",
                        "product": "cms_plugin",
                        "version": "*",
                        "raw_cpe": "cpe:2.3:a:demo:cms_plugin:*:*:*:*:*:*:*:*",
                    }
                ],
                "cwe_ids": ["CWE-434"],
                "references": [],
                "exploit_available": True,
                "exploit_maturity": "weaponized",
                "exploit_confidence": 100,
                "exploit_sources": ["cisa_kev"],
                "patch_available": False,
                "patch_confidence": 0,
                "patch_sources": [],
                "cisa_kev": True,
            }
        ])

        AssetInventory.objects.create(
            hostname="demo-web-1",
            ip_address="10.10.10.10",
            services=[
                {
                    "product": "cms_plugin",
                    "vendor": "demo",
                    "version": "1.0",
                    "cpe": "cpe:2.3:a:demo:cms_plugin:1.0:*:*:*:*:*:*:*",
                }
            ],
            criticality="critical",
            internet_facing=True,
            behind_firewall=False,
        )

        report = build_report(include_compliance=True, include_trending=False, sync_mappings=True)

        self.assertEqual(report["system_status"]["critical_count"], report["analytics"]["critical_count"])
        self.assertEqual(report["analytics"]["criticalCount"], report["analytics"]["critical_count"])
        self.assertEqual(report["system_status"]["top_risks"][0]["risk_score"], report["vulnerabilities"][0]["risk"])
        self.assertEqual(report["system_status"]["top_risks"][0]["exploit_status"], report["vulnerabilities"][0]["exploit_maturity"])
        self.assertTrue(report["vulnerabilities"][0]["has_asset_match"])
        self.assertEqual(CVEAssetMapping.objects.count(), 1)
        self.assertEqual(report["compliance"]["total_vulnerabilities"], len(report["vulnerabilities"]))
