```
╔══════════════════════════════════════════════════════════════════╗
║   ██████  ██████  ████████ ██  ██  ███████ ███████  ██████     ║
║  ██    ██ ██   ██    ██    ██ ██  ██      ██      ██           ║
║  ██    ██ ██████     ██    ████   ███████ █████   ██           ║
║  ██    ██ ██         ██    ██ ██       ██ ██      ██           ║
║   ██████  ██         ██    ██  ██ ███████ ███████  ██████      ║
╠══════════════════════════════════════════════════════════════════╣
║          R E C O N   P R O  ·  v4.0  S I N G U L A R I T Y   ║
║          Enterprise Cybersecurity Intelligence Platform         ║
╚══════════════════════════════════════════════════════════════════╝
```

<p align="center">
  <img src="https://img.shields.io/badge/Version-v4.0%20SINGULARITY-ff0055?style=for-the-badge&logo=rocket&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.104%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/github/stars/OptisecDev/optisec-recon-pro?style=for-the-badge&color=yellow&logo=github" />
  <img src="https://img.shields.io/badge/AI%20Powered-Groq%20LLaMA-ff6b35?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Active-00ff88?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Screenshots-23%20Pages-blueviolet?style=for-the-badge&logo=camera&logoColor=white" />
</p>

---

## Overview

**OPTISEC Recon Pro** is a full-stack, enterprise-grade cybersecurity intelligence platform built for professional penetration testers, bug bounty hunters, and security operations teams. It combines automated reconnaissance, AI-driven vulnerability analysis, dark web monitoring, post-quantum cryptography, and real-time threat intelligence into a single unified dashboard — all deployable with a single command.

Powered by **FastAPI** (async), **SQLAlchemy 2.0**, **Groq LLaMA AI**, and a modular architecture that scales from solo analysts to distributed red teams, OPTISEC Recon Pro is engineered for **speed**, **accuracy**, and **operational depth**.

---

## Features

| # | Module | Description |
|---|--------|-------------|
| 🔍 **1** | **Recon Engine** | Subdomain enumeration, DNS record analysis, WHOIS lookup, and Nmap port scanning in a single async pipeline |
| 🐛 **2** | **Vulnerability Scanner** | Automated detection of XSS, SQL injection, SSRF, LFI, and open-redirect vulnerabilities with severity scoring |
| 🕵️ **3** | **OSINT Intelligence** | Multi-source open-source intelligence: email profiling, social media footprinting, IP geolocation, phone/carrier lookup, and national ID analysis |
| 💰 **4** | **Bug Bounty Integration** | Native API clients for HackerOne, Bugcrowd, and Intigriti — browse programs, check scope, and submit reports without leaving the platform |
| 📋 **5** | **CVE Pipeline** | Draft, queue, and submit CVEs directly to MITRE NVD; full NVD search integration with CISA KEV cross-reference |
| ✅ **6** | **Compliance Checker** | Automated compliance gap analysis against ISO 27001, NIST CSF 2.0, GDPR, and PCI-DSS with actionable control mapping |
| 🛡️ **7** | **AI Firewall (DPI)** | 12-rule deep-packet inspection engine with ML anomaly scoring, rate limiting, and real-time traffic analysis |
| 🌐 **8** | **WireGuard VPN Manager** | Generate server/peer configs, manage WireGuard peers, and export QR codes — all from the web UI |
| 🧠 **9** | **UEBA Behavioral Analytics** | Entity profiling and anomaly detection — continuously models user/device behavior and flags deviations in real time |
| ☢️ **10** | **Zero-Day Prediction** | Groq AI + NVD + CISA KEV fusion engine that predicts zero-day exploitation likelihood before public PoC release |
| 🔗 **11** | **Kill-Chain Correlation** | Maps observed IOCs and TTPs to MITRE ATT&CK kill-chain stages; detects multi-stage campaigns automatically |
| 🤖 **12** | **AI Red Team Planner** | Groq-powered red team engagement planner — generates phased attack plans, tailored payloads, and debrief reports |
| ⚛️ **13** | **Post-Quantum Cryptography** | Generate Kyber-768 / Dilithium / SPHINCS+ keypairs; hybrid AES-256-GCM encryption future-proofed against quantum attacks |
| 🌍 **14** | **Federated Scanning** | Distribute scans across multiple OPTISEC nodes; aggregate findings centrally with signed task delegation |
| 🗺️ **15** | **ATT&CK Navigator** | Interactive MITRE ATT&CK matrix covering all 14 tactics and 278 techniques; 8 APT profiles and IOC→technique mapping |
| 🕸️ **16** | **Dark Web Intelligence** | Breach detection (4B+ records), paste scanner (15 pattern templates), Tor exit-node monitoring, and ransomware gang tracking |

### Additional Elite Capabilities

- **Autonomous Red Team** — 7-phase kill-chain simulation engine with an 8-category payload library and AI-generated pentest report output
- **NGFW v2** — ML-enhanced DPI with Shannon entropy scoring, geo-blocking, and live traffic charts
- **Global Threat Feed** — 20-point geo threat map, TLP-aware IOC federation, and multi-source campaign correlation
- **IOC Correlation Engine** — AlienVault OTX integration with automatic cluster detection across indicators
- **WebSocket Live Progress** — Real-time scan progress streamed to the browser via `/ws/scan/{scan_id}`
- **Role-Based Access Control** — Admin / Analyst / Viewer roles with JWT cookies, API key auth, and audit logging

---

## Screenshots

### Login & Dashboard

| Login | Dashboard |
|-------|-----------|
| ![Login](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/login.png) | ![Dashboard](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/dashboard.png) |

### Reconnaissance & Scanning

| Scan | Scan History |
|------|-------------|
| ![Scan](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/scan.png) | ![Scans](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/scans.png) |

### Threat Intelligence

| ATT&CK Navigator | Global Threat Feed |
|-----------------|-------------------|
| ![ATT&CK Navigator](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/attack_navigator.png) | ![Threat Feed](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/threat_feed.png) |

| IOC Correlations | Dark Web Intel |
|-----------------|----------------|
| ![Correlations](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/correlations.png) | ![Dark Web](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/darkweb.png) |

### AI Security

| Zero-Day Prediction | Kill-Chain Correlation |
|---------------------|----------------------|
| ![Zero-Day](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/zero_day.png) | ![Attack Patterns](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/attack_patterns.png) |

| Behavioral Analytics | AI Red Team |
|---------------------|-------------|
| ![Behavioral](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/behavioral.png) | ![Red Team](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/red_team.png) |

### Autonomous Red Team

| Autonomous Red Team |
|--------------------|
| ![Autonomous Red Team](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/autonomous_redteam.png) |

### Compliance & Security

| Compliance Checker | AI Firewall |
|-------------------|-------------|
| ![Compliance](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/compliance.png) | ![Firewall](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/firewall.png) |

| NGFW v2 | Bug Bounty |
|---------|-----------|
| ![NGFW](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/ngfw.png) | ![Bug Bounty](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/bug_bounty.png) |

### Infrastructure

| Post-Quantum Cryptography | WireGuard VPN |
|--------------------------|---------------|
| ![Quantum](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/quantum.png) | ![VPN](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/vpn.png) |

### OSINT & Reports

| OSINT Intelligence | Reports |
|-------------------|---------|
| ![OSINT](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/osint.png) | ![Reports](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/reports.png) |

### Administration

| Targets | Admin Panel |
|---------|------------|
| ![Targets](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/targets.png) | ![Admin](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/admin.png) |

---

## Quick Install

### Requirements

- Python 3.11+
- Git
- (Optional) PostgreSQL for production deployments

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/OptisecDev/optisec-recon-pro.git
cd optisec-recon-pro

# 2. Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Configure environment (copy and edit)
cp .env.example .env
# Edit .env — set GROQ_API_KEY, JWT_SECRET, and optionally DATABASE_URL

# 4. Launch the platform
./optisec.sh
```

The launcher automatically activates the venv, loads `.env`, starts Uvicorn with hot-reload, and opens your browser at `http://localhost:8000`.

### First Login

On first startup, an admin account is seeded from `.env` defaults:

| Field | Default |
|-------|---------|
| Username | `admin` |
| Email | `admin@optisec.local` |
| Password | `admin123` |

> **Change the default password immediately in production.**

### Docker (optional)

```bash
docker build -t optisec-recon-pro .
docker run -p 8000:8000 --env-file .env optisec-recon-pro
```

---

## API Endpoints

Interactive documentation is available at `http://localhost:8000/docs` (Swagger UI) and `http://localhost:8000/redoc` (ReDoc).

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Authenticate and receive JWT token |
| `POST` | `/api/auth/register` | Register a new user account |
| `POST` | `/api/auth/api-key/regenerate` | Rotate your API key |

### Reconnaissance & Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Launch a full recon + vuln scan |
| `GET` | `/api/scan/{scan_id}` | Fetch scan status and results |
| `GET` | `/api/scans` | List all scans with pagination |
| `GET` | `/api/findings` | Query findings with severity/type filters |
| `POST` | `/api/scan/ssl` | SSL/TLS certificate deep analysis |
| `POST` | `/api/scan/headers` | HTTP security headers audit |
| `POST` | `/api/scan/ports` | TCP port scan via Nmap |

### AI & Threat Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ai/analyze` | Groq LLaMA AI threat analysis on findings |
| `POST` | `/api/nlp` | Natural language query → structured scan params |
| `POST` | `/ai-security/api/zero-day/predict` | Zero-day exploitation risk prediction |
| `POST` | `/ai-security/api/attack-patterns/analyze` | Kill-chain stage correlation |
| `POST` | `/ai-security/api/red-team/engagements` | Create AI-planned red team engagement |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/report` | Generate PDF security report (ReportLab) |
| `GET` | `/reports/download/{filename}` | Download generated report |

### OSINT

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/osint` | Multi-source OSINT lookup (email, social) |
| `GET` | `/api/osint/username` | Username search across platforms |

### Threat Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/threat-feed/api/feed` | Live global threat intelligence feed |
| `GET` | `/threat-feed/api/threat-map` | Geo-distributed threat map data |
| `POST` | `/threat-feed/api/submit-ioc` | Submit a new IOC to the federation |
| `GET` | `/api/correlations` | IOC correlation clusters (AlienVault OTX) |

### Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/compliance/api/frameworks` | List available compliance frameworks |
| `POST` | `/compliance/api/assess` | Run automated compliance gap assessment |

### Bug Bounty

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/bug-bounty/api/hackerone/programs` | Browse HackerOne public programs |
| `POST` | `/bug-bounty/api/hackerone/submit` | Submit a bug report to HackerOne |
| `GET` | `/bug-bounty/api/cve/search` | Search NVD CVE database |

### Quantum & VPN

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/quantum/api/keypair` | Generate post-quantum (Kyber-768) keypair |
| `GET` | `/vpn/api/peers` | List WireGuard peers and their status |
| `POST` | `/darkweb/api/check-domain` | Check domain exposure on dark web |

---

## Configuration Reference

Key environment variables (see `.env.example` for the full list):

```env
# AI
GROQ_API_KEY=your_groq_api_key_here

# Threat Intelligence
OTX_API_KEY=your_alienvault_otx_key_here

# Database (SQLite default — no setup required)
DATABASE_URL=sqlite+aiosqlite:///./data/optisec.db
# PostgreSQL (recommended for production):
# DATABASE_URL=postgresql+asyncpg://optisec:password@localhost/optisec

# Auth
JWT_SECRET=change-this-to-a-strong-random-secret
JWT_EXPIRE_HOURS=24

# Bug Bounty
HACKERONE_USERNAME=your_h1_username
HACKERONE_API_TOKEN=your_h1_token
BUGCROWD_API_TOKEN=your_bugcrowd_token
INTIGRITI_API_TOKEN=your_intigriti_token

# CVE Submission
CVE_CNA_ORG=your_cna_org
CVE_CNA_USERNAME=your_cna_user
CVE_CNA_API_KEY=your_cna_key
```

---

## Architecture

```
optisec-recon-pro/
├── web/
│   ├── app.py              # FastAPI application, routes, middleware
│   ├── auth.py             # JWT + bcrypt + API key authentication
│   ├── database.py         # SQLAlchemy 2.0 async engine
│   ├── models.py           # User, Target, Scan, Finding, Report tables
│   ├── websocket_manager.py# Real-time scan progress via WebSocket
│   ├── routers/            # Feature routers (15 modules)
│   └── templates/          # Jinja2 dark-theme HTML templates
├── modules/
│   ├── ai_advanced/        # Zero-day, UEBA, kill-chain, red team
│   ├── bug_bounty/         # HackerOne, Bugcrowd, Intigriti, CVE
│   ├── compliance/         # ISO 27001, NIST, GDPR, PCI-DSS
│   ├── darkweb/            # Breach intel, paste scanner, Tor monitor
│   ├── federation/         # Multi-node distributed scanning
│   ├── firewall/           # AI DPI firewall + NGFW v2
│   ├── quantum/            # Post-quantum cryptography (PQC)
│   ├── threat_intel/       # MITRE ATT&CK, IOC, global feed
│   └── vpn/                # WireGuard management
├── cli/                    # Command-line interface with NLP parser
├── data/                   # Runtime data, keys, profiles, configs
├── optisec.sh              # One-command launcher with health checks
└── requirements.txt
```

---

## About OPTISEC

**OPTISEC** is an independent cybersecurity engineering project founded by **Engineer Ihsan Ali**, dedicated to building open-source, production-ready security tooling for the modern threat landscape.

OPTISEC Recon Pro is the flagship platform — designed from the ground up to give security professionals the same intelligence capabilities typically reserved for enterprise SOC teams, but in a self-hosted, open-source package that anyone can deploy, extend, and contribute to.

> *"Security is not a product, it's a process — and that process deserves professional tooling."*

### Links

- **GitHub:** [github.com/OptisecDev/optisec-recon-pro](https://github.com/OptisecDev/optisec-recon-pro)
- **Issues / Feature Requests:** [github.com/OptisecDev/optisec-recon-pro/issues](https://github.com/OptisecDev/optisec-recon-pro/issues)
- **Email:** ahssanali84.syber@gmail.com

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push to the branch: `git push origin feat/your-feature`
5. Open a Pull Request

Please follow the existing code style and include tests for new modules.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with ♦ by <strong>Engineer Ihsan Ali</strong> · OPTISEC © 2025
</p>
