import requests
import random

CISA_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_threat_score():
    try:
        response = requests.get(CISA_FEED, timeout=5)
        data = response.json()

        vulns = data.get("vulnerabilities", [])

        if not vulns:
            return random.randint(10, 40)

        recent_vulns = vulns[-10:]

        score = len(recent_vulns) * 3

        threat_level = min(score, 100)

        return threat_level

    except Exception:
        return random.randint(10, 40)