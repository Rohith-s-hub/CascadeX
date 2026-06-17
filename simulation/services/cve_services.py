# backend/apps/simulations/services/cve_service.py

import requests
from datetime import datetime, timedelta

class CVEService:
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def get_recent_critical_cves(self, days=30):
        """Fetch critical CVEs from last N days"""
        start_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        response = requests.get(
            self.NVD_API_BASE,
            params={
                "pubStartDate": start_date,
                "cvssV3Severity": "CRITICAL",
                "resultsPerPage": 50
            },
            headers={"apiKey": "YOUR_NVD_API_KEY"}  # Free API key
        )
        
        return self._parse_cves(response.json())
    
    def get_exploited_vulnerabilities(self):
        """Get CISA Known Exploited Vulnerabilities"""
        response = requests.get(self.CISA_KEV_URL)
        data = response.json()
        
        return [
            {
                "cve_id": vuln["cveID"],
                "name": vuln["vulnerabilityName"],
                "vendor": vuln["vendorProject"],
                "product": vuln["product"],
                "date_added": vuln["dateAdded"],
                "due_date": vuln["dueDate"],
                "description": vuln["shortDescription"],
                "risk": 95,  # Actively exploited = high risk
                "status": "critical"
            }
            for vuln in data["vulnerabilities"][:20]
        ]
    
    def calculate_cascade_risk(self, cve_id, infrastructure):
        """Calculate how a CVE cascades through infrastructure"""
        # Find affected nodes
        affected = self._find_affected_nodes(cve_id, infrastructure)
        
        # Calculate propagation paths
        propagation = []
        for node in affected:
            connected = self._get_connected_nodes(node, infrastructure)
            for conn in connected:
                propagation.append({
                    "from": node["name"],
                    "to": conn["name"],
                    "intensity": self._calculate_intensity(node, conn),
                    "attack_vector": self._get_attack_vector(cve_id)
                })
        
        return {
            "affected_nodes": affected,
            "propagation_paths": propagation,
            "total_risk_score": self._calculate_total_risk(affected)
        }
    
    def _parse_cves(self, nvd_response):
        """Parse NVD API response into our format"""
        nodes = []
        
        for item in nvd_response.get("vulnerabilities", []):
            cve = item["cve"]
            metrics = cve.get("metrics", {})
            
            # Get CVSS score
            cvss_data = metrics.get("cvssMetricV31", [{}])[0]
            cvss_score = cvss_data.get("cvssData", {}).get("baseScore", 0)
            
            nodes.append({
                "id": cve["id"],
                "name": cve["id"],
                "type": "vulnerability",
                "description": cve["descriptions"][0]["value"][:200],
                "cvss_score": cvss_score,
                "severity": self._get_severity(cvss_score),
                "stability": max(0, 100 - (cvss_score * 10)),
                "risk": min(100, cvss_score * 10),
                "status": "critical" if cvss_score >= 9 else "warning" if cvss_score >= 7 else "operational",
                "connections": self._get_affected_products(cve),
                "published": cve.get("published"),
                "exploitability": cvss_data.get("exploitabilityScore", 0),
                "impact": cvss_data.get("impactScore", 0)
            })
        
        return nodes
    
    def _get_severity(self, score):
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_affected_products(self, cve):
        """Extract affected products from CVE"""
        products = []
        configurations = cve.get("configurations", [])
        
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    # Parse CPE string: cpe:2.3:a:vendor:product:version
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        products.append(f"{parts[3]}:{parts[4]}")
        
        return products[:5]  # Limit connections