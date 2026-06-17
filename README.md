# CascadeX — Vulnerability Cascade Intelligence Platform

The security tool that tells you which vulnerabilities will actually be used against you — not just which ones exist.

## What Makes CascadeX Different

Most vulnerability tools give you a list of 180,000+ CVEs marked "Critical."

CascadeX gives you the 3 CVEs that will actually be exploited next week.

## Core Capabilities

- Cascade Intelligence Engine — Maps CVEs into real attack kill chains
- EPSS Integration — Real exploitation probability from FIRST.org
- Asset-Confirmed Chains — CVEs matched to YOUR infrastructure
- Honest Graph Edges — Confidence levels, not fake certainty
- MITRE ATT&CK Mapping — Tactics & techniques classification
- Compliance Engine — SOC2, PCI DSS, HIPAA, NIST 800-53
- Real-time Trending — Track security posture over time
- Live Monitoring — Webhook integrations (Slack, Jira, PagerDuty)

## Tech Stack

- Backend: Django 6.0 + PostgreSQL + Redis
- Frontend: React 18 + TypeScript + Vite + Tailwind
- Auth: JWT + OAuth2 (Google + GitHub)
- Deploy: Docker + Nginx + Gunicorn
- Intel: NVD + EPSS + CISA KEV + MITRE ATT&CK

## Quick Start

Clone the repo:
git clone https://github.com/Rohith-s-hub/cascadex.git
cd cascadex

Configure environment:
cp .env.example .env

Start with Docker:
docker compose up -d

Open http://localhost in your browser.

## License

MIT License - Copyright 2026 Rohith

## Contributing

Pull requests welcome.
