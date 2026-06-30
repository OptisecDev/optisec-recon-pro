<div align="center">

<img src="docs/screenshots/landing.png" alt="OPTISEC v4.0 SINGULARITY" width="100%">

# OPTISEC v4.0 SINGULARITY

### Enterprise Security Intelligence Platform

[![License](https://img.shields.io/badge/License-Proprietary-red.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Status](https://img.shields.io/badge/Status-Production-00ff88.svg?style=for-the-badge)](https://github.com/OptisecDev/optisec-recon-pro)
[![Version](https://img.shields.io/badge/Version-4.0.0--SINGULARITY-bc8cff.svg?style=for-the-badge)](https://github.com/OptisecDev/optisec-recon-pro/releases)
[![Stars](https://img.shields.io/github/stars/OptisecDev/optisec-recon-pro?style=for-the-badge&color=00ff88)](https://github.com/OptisecDev/optisec-recon-pro/stargazers)

**A full-stack, AI-powered security intelligence platform built for bug bounty hunters,  
red teamers, and enterprise SOC teams — featuring 13 integrated scanning modules,  
Arabic/English NLP, post-quantum cryptography, and autonomous red team simulation.**

[Live Demo](https://optisec-recon-pro.onrender.com/demo) · [API Docs](https://optisec-recon-pro.onrender.com/docs) · [Report Bug](https://github.com/OptisecDev/optisec-recon-pro/issues) · [Request Feature](https://github.com/OptisecDev/optisec-recon-pro/issues)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features Matrix — 13 Modules](#features-matrix--13-modules)
- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
  - [Quick Start (Local)](#quick-start-local)
  - [Docker Compose](#docker-compose)
  - [Deploy to Render](#deploy-to-render)
- [API Documentation](#api-documentation)
- [Licensing Tiers](#licensing-tiers)
- [Security & Responsible Disclosure](#security--responsible-disclosure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License & Contact](#license--contact)

---

## Overview

**OPTISEC v4.0 SINGULARITY** is a comprehensive bug bounty and penetration testing platform that consolidates the entire security research workflow into a single, unified web dashboard. From subdomain enumeration to autonomous AI-driven red team simulations, OPTISEC gives security professionals an enterprise-grade toolkit accessible from any browser.

### Why OPTISEC?

| Problem | OPTISEC Solution |
|---------|-----------------|
| Fragmented tooling (Nmap, Burp, nuclei, theHarvester…) | Single unified dashboard with 13 integrated modules |
| Manual report writing takes hours | One-click professional PDF reports |
| No Arabic-language security tooling | Native Arabic + English NLP command interface |
| Bug bounty context switching between H1/Bugcrowd/Intigriti | Unified bug bounty management with direct submission APIs |
| Quantum threats to modern encryption | Built-in Kyber-768 post-quantum key encapsulation |
| SOC teams need correlation across threat feeds | IOC correlation engine with AlienVault OTX integration |

---

## Features Matrix — 13 Modules

### Core Scanning Engine

| Module | Capabilities | Tier |
|--------|-------------|------|
| **Reconnaissance** | Subdomain enumeration (wordlist + DNS brute), DNS lookup (A/MX/TXT/NS/CNAME), WHOIS, Nmap service detection, SSL/TLS analysis, Security headers grading, Port scanning | FREE+ |
| **Vulnerability Scanner** | XSS (reflected/stored), SQL Injection, SSRF (cloud metadata bypass), LFI (path traversal), Open Redirect | FREE+ |
| **OSINT Engine** | Email discovery, Social media footprint, Phone number intelligence, IP geolocation, Username search (200+ platforms), Device fingerprinting, National ID lookup (Iraq), Vehicle plate recon, Cell tower triangulation | FREE/PRO |

### AI & Intelligence

| Module | Capabilities | Tier |
|--------|-------------|------|
| **AI Security Analysis** | Groq LLaMA-3.3-70B powered threat analysis, CVE mapping, attack chain reconstruction, remediation prioritization | PRO+ |
| **Behavioral UEBA** | User and Entity Behavior Analytics, anomaly detection, insider threat profiling | PRO+ |
| **Zero-Day Prediction** | ML-based vulnerability pattern matching, exploit probability scoring | PRO+ |
| **Attack Pattern Engine** | Known malicious pattern library, payload classification, kill chain analysis | PRO+ |
| **Autonomous Red Team** | AI-driven multi-phase attack simulation (SINGULARITY engine), stealth-tunable, automated reporting | ENTERPRISE |

### Platform & Integration

| Module | Capabilities | Tier |
|--------|-------------|------|
| **Bug Bounty Platform** | HackerOne program browser + report submission, Bugcrowd program discovery + submission, Intigriti integration, CVE pipeline (NVD/MITRE) | PRO+ |
| **Compliance Checker** | Automated audits against ISO 27001, NIST CSF, PCI-DSS, GDPR, HIPAA with gap analysis | PRO+ |
| **Threat Intelligence** | AlienVault OTX live feed, MITRE ATT&CK Navigator, Global threat campaigns, HIBP breach detection, Honeypot detection, IOC correlation clustering | ENTERPRISE |
| **Dark Web Intelligence** | Leaked credential monitoring, threat actor mentions, IOC extraction from dark web sources | ENTERPRISE |
| **Federated Scanning** | Multi-node OPTISEC cluster coordination, distributed scan tasks, node health monitoring | ENTERPRISE |

### Infrastructure Security

| Module | Capabilities | Tier |
|--------|-------------|------|
| **AI Firewall (WAF)** | Rule-based + ML traffic analysis, IP whitelist/blacklist, custom rule engine | PRO+ |
| **NGFW v2** | Next-gen firewall with ML-based Deep Packet Inspection, anomaly detection, L7 policy engine | PRO+ |
| **WireGuard VPN** | Peer management, key generation + QR codes, config export | PRO+ |
| **Quantum-Safe Crypto** | Kyber-768 post-quantum key encapsulation, hybrid AES-GCM schemes, key vault | PRO+ |

### Platform Features

- **Real-time WebSocket** — Live scan progress streaming (`ws://host/ws/scan/{scan_id}`)
- **Arabic/English NLP** — Natural language command interface (`افحص tesla.com عن ثغرات XSS`)
- **Role-Based Access** — Admin / Analyst / Viewer permission model
- **PDF Reports** — Professional executive-grade security reports with ReportLab
- **REST API** — Full OpenAPI 3.0 spec at `/docs` and `/redoc`
- **Demo Mode** — One-click `/demo` login with pre-populated findings and targets

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     OPTISEC v4.0 SINGULARITY                        │
│                                                                       │
│  ┌─────────────┐   ┌──────────────────────────────────────────────┐ │
│  │   Browser   │◄──│        FastAPI Web Application               │ │
│  │  Dashboard  │   │   (Jinja2 Templates + Static Assets)         │ │
│  └──────┬──────┘   └────────────────────┬─────────────────────────┘ │
│         │ WebSocket                      │ HTTP/REST                 │
│  ┌──────▼──────┐   ┌────────────────────▼─────────────────────────┐ │
│  │  WS Manager │   │              API Routers (14)                 │ │
│  │  Real-time  │   │  auth · scans · targets · findings · nlp     │ │
│  │  Progress   │   │  bug_bounty · compliance · osint · firewall   │ │
│  └─────────────┘   │  vpn · quantum · federation · ai_security    │ │
│                    │  attack_navigator · darkweb · autonomous_rt   │ │
│                    │  ngfw · threat_feed · correlations · reports  │ │
│                    └────────────────────┬─────────────────────────┘ │
│                                         │                            │
│  ┌──────────────────────────────────────▼─────────────────────────┐ │
│  │                    Module Engine (13 Core)                      │ │
│  │                                                                 │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │ │
│  │  │  recon/  │ │  vuln/   │ │  osint/  │ │  ai / ai_advanced│  │ │
│  │  │ subdom   │ │  xss     │ │  phone   │ │  groq_analyzer   │  │ │
│  │  │ dns      │ │  sqli    │ │  username│ │  behavioral      │  │ │
│  │  │ whois    │ │  ssrf    │ │  geo_ip  │ │  zero_day        │  │ │
│  │  │ nmap     │ │  lfi     │ │  nat_id  │ │  attack_patterns │  │ │
│  │  │ ssl      │ │  redirect│ │  device  │ │  autonomous_rt   │  │ │
│  │  │ headers  │ └──────────┘ └──────────┘ └──────────────────┘  │ │
│  │  │ ports    │                                                   │ │
│  │  └──────────┘ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │ │
│  │               │bug_bounty│ │compliance│ │  threat_intel/   │  │ │
│  │               │hackerone │ │iso_27001 │ │  otx_feed        │  │ │
│  │               │bugcrowd  │ │nist_csf  │ │  mitre_attack    │  │ │
│  │               │intigriti │ │pci_dss   │ │  ioc_correlations│  │ │
│  │               │cve_pipe  │ │gdpr/hipaa│ │  global_feed     │  │ │
│  │               └──────────┘ └──────────┘ └──────────────────┘  │ │
│  │                                                                 │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │ │
│  │  │ firewall │ │   vpn/   │ │ quantum/ │ │  federation/     │  │ │
│  │  │ ai_waf   │ │wireguard │ │ kyber768 │ │  multi_node_scan │  │ │
│  │  │ ngfw_v2  │ │ peer_mgmt│ │ aes_gcm  │ │  distributed_rt  │  │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘  │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                         │                            │
│  ┌──────────────────────────────────────▼─────────────────────────┐ │
│  │              Data Layer                                         │ │
│  │   SQLite (dev) / PostgreSQL (prod)  ·  JSON data stores        │ │
│  │   SQLAlchemy Async ORM  ·  Alembic migrations                  │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  External Integrations:                                              │
│  AlienVault OTX  ·  HackerOne API  ·  Bugcrowd API  ·  Intigriti  │
│  Groq LLaMA-3.3-70B  ·  NVD/CVE  ·  MITRE ATT&CK  ·  HIBP        │
└─────────────────────────────────────────────────────────────────────┘
```

```mermaid
graph TB
    Browser["🌐 Browser / CLI"] --> FastAPI["FastAPI Application"]
    FastAPI --> Auth["🔑 JWT Auth<br/>3 Roles: Admin/Analyst/Viewer"]
    FastAPI --> WS["⚡ WebSocket<br/>Real-time Scan Progress"]
    FastAPI --> Modules

    subgraph Modules["Module Engine"]
        Recon["🔍 Recon<br/>subdomain·dns·nmap·ssl"]
        Vuln["🎯 Vuln Scanner<br/>xss·sqli·ssrf·lfi"]
        OSINT["🕵️ OSINT<br/>phone·username·geo·device"]
        AI["🤖 AI Engine<br/>Groq LLaMA-3.3-70B"]
        BugBounty["💰 Bug Bounty<br/>H1·Bugcrowd·Intigriti"]
        Compliance["✅ Compliance<br/>ISO27001·NIST·GDPR"]
        ThreatIntel["🌍 Threat Intel<br/>OTX·MITRE·IOC"]
        RedTeam["⚔️ Autonomous RT<br/>SINGULARITY Engine"]
        Quantum["⚛️ Quantum Crypto<br/>Kyber-768 PQC"]
    end

    Modules --> DB["🗄️ SQLite / PostgreSQL"]
    Modules --> OTX["AlienVault OTX"]
    Modules --> Groq["Groq API"]
    Modules --> H1["HackerOne API"]
    Modules --> BC["Bugcrowd API"]
```

---

## Screenshots

> All screenshots are taken live from a running OPTISEC v4.0 SINGULARITY instance.

<details open>
<summary><strong>Dashboard & Overview</strong></summary>

| Landing Page | Main Dashboard |
|:---:|:---:|
| ![Landing](docs/screenshots/landing.png) | ![Dashboard](docs/screenshots/dashboard.png) |

| Login | Admin Panel |
|:---:|:---:|
| ![Login](docs/screenshots/login.png) | ![Admin](docs/screenshots/admin.png) |

| Demo Dashboard | Demo Scans |
|:---:|:---:|
| ![Demo Dashboard](docs/screenshots/demo_dashboard.png) | ![Demo Scans](docs/screenshots/demo_scans.png) |

</details>

<details>
<summary><strong>Scanning & Vulnerabilities</strong></summary>

| Scan Interface | All Scans |
|:---:|:---:|
| ![Scan](docs/screenshots/scan.png) | ![Scans](docs/screenshots/scans.png) |

| Scan Detail | Reports |
|:---:|:---:|
| ![Scan Detail](docs/screenshots/demo_scan_detail.png) | ![Reports](docs/screenshots/reports.png) |

| Targets Manager | |
|:---:|:---:|
| ![Targets](docs/screenshots/targets.png) | |

</details>

<details>
<summary><strong>Intelligence & OSINT</strong></summary>

| OSINT Engine | Dark Web Intel |
|:---:|:---:|
| ![OSINT](docs/screenshots/osint.png) | ![Dark Web](docs/screenshots/darkweb.png) |

| IOC Correlations | Global Threat Feed |
|:---:|:---:|
| ![Correlations](docs/screenshots/correlations.png) | ![Threat Feed](docs/screenshots/threat_feed.png) |

| Attack Patterns | MITRE ATT&CK Navigator |
|:---:|:---:|
| ![Attack Patterns](docs/screenshots/attack_patterns.png) | ![ATT&CK](docs/screenshots/attack_navigator.png) |

</details>

<details>
<summary><strong>AI & Red Team</strong></summary>

| Autonomous Red Team | AI Red Team |
|:---:|:---:|
| ![Autonomous RT](docs/screenshots/autonomous_redteam.png) | ![Red Team](docs/screenshots/red_team.png) |

| Behavioral UEBA | Zero-Day Prediction |
|:---:|:---:|
| ![Behavioral](docs/screenshots/behavioral.png) | ![Zero Day](docs/screenshots/zero_day.png) |

</details>

<details>
<summary><strong>Platform & Integration</strong></summary>

| Bug Bounty Platform | Compliance Checker |
|:---:|:---:|
| ![Bug Bounty](docs/screenshots/bug_bounty.png) | ![Compliance](docs/screenshots/compliance.png) |

| Federated Scanning | WireGuard VPN |
|:---:|:---:|
| ![Federation](docs/screenshots/federation.png) | ![VPN](docs/screenshots/vpn.png) |

| NGFW v2 | Firewall Rules |
|:---:|:---:|
| ![NGFW](docs/screenshots/ngfw.png) | ![Firewall](docs/screenshots/firewall.png) |

| Quantum Crypto (Kyber-768) | License Manager |
|:---:|:---:|
| ![Quantum](docs/screenshots/quantum.png) | ![License](docs/screenshots/license.png) |

</details>

<details>
<summary><strong>API Documentation</strong></summary>

| Built-in API Docs (Dark Theme) | Swagger UI |
|:---:|:---:|
| ![API Docs](docs/screenshots/api_docs.png) | ![Swagger](docs/screenshots/swagger.png) |

</details>

---

## Tech Stack

| Category | Technology | Version |
|----------|-----------|---------|
| **Language** | Python | 3.12 |
| **Web Framework** | FastAPI | ≥ 0.104 |
| **ASGI Server** | Uvicorn | ≥ 0.24 |
| **Templates** | Jinja2 | ≥ 3.1 |
| **ORM** | SQLAlchemy (async) | ≥ 2.0 |
| **Database (dev)** | SQLite via aiosqlite | — |
| **Database (prod)** | PostgreSQL via asyncpg | — |
| **Migrations** | Alembic | ≥ 1.13 |
| **Auth** | python-jose (JWT) + bcrypt | — |
| **AI Engine** | Groq LLaMA-3.3-70B | — |
| **HTTP Client** | httpx + aiohttp | — |
| **DNS/Recon** | dnspython + python-whois | — |
| **Port Scanning** | Nmap (system) | 7.x |
| **PDF Reports** | ReportLab | ≥ 4.0 |
| **OSINT** | phonenumbers + ua-parser | — |
| **Cryptography** | cryptography (AES-GCM) + Kyber-768 | ≥ 41.0 |
| **VPN** | WireGuard Tools + qrcode | — |
| **WebSocket** | websockets | ≥ 12.0 |
| **CLI** | Click + Rich | — |
| **Containerization** | Docker + Docker Compose | — |
| **Proxy** | Nginx | 1.25 |

---

## Installation

### Prerequisites

- Python 3.12+
- Nmap 7.x (`apt install nmap` / `brew install nmap`)
- Git

### Quick Start (Local)

```bash
# 1. Clone the repository
git clone https://github.com/OptisecDev/optisec-recon-pro.git
cd optisec-recon-pro

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — set JWT_SECRET and optionally GROQ_API_KEY

# 5. Launch the dashboard
python main.py web --port 8000

# Dashboard: http://localhost:8000
# API Docs:  http://localhost:8000/docs
# ReDoc:     http://localhost:8000/redoc
# Demo:      http://localhost:8000/demo  (one-click demo account)
```

**First-run admin account** is created automatically. Credentials are printed to stdout:
```
[OPTISEC] Initial admin created → admin / <auto-generated-password>
```

### Docker Compose

The recommended production setup with PostgreSQL + Nginx reverse proxy:

```bash
# 1. Clone and configure
git clone https://github.com/OptisecDev/optisec-recon-pro.git
cd optisec-recon-pro
cp .env.example .env

# 2. Set required secrets in .env
#    JWT_SECRET=<min 32 chars>
#    POSTGRES_PASSWORD=<strong password>
#    GROQ_API_KEY=<your key>          # optional — enables AI features
#    OTX_API_KEY=<your key>           # optional — enables AlienVault feed
#    HACKERONE_API_TOKEN=<your token> # optional — enables H1 integration

# 3. Start all services
docker compose up -d

# Services:
#   optisec  → http://localhost:8000
#   nginx    → http://localhost:80  (reverse proxy)
#   postgres → localhost:5432
```

**Docker Compose services:**

| Service | Port | Description |
|---------|------|-------------|
| `optisec` | 8000 | Main application (2 Uvicorn workers) |
| `nginx` | 80 / 443 | Reverse proxy + SSL termination |
| `postgres` | 5432 | PostgreSQL 16 database |

### Deploy to Render

One-click deployment on [Render.com](https://render.com):

1. Fork this repository
2. Create a new **Web Service** on Render pointing to your fork
3. Set the following environment variables in Render dashboard:

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | ✅ | Random string ≥ 32 characters |
| `DATABASE_URL` | ✅ | Render PostgreSQL URL (`postgresql+asyncpg://...`) |
| `FIRST_ADMIN_PASSWORD` | ✅ | Initial admin password |
| `GROQ_API_KEY` | Optional | Enables AI analysis features |
| `OTX_API_KEY` | Optional | AlienVault OTX threat feed |
| `HACKERONE_API_TOKEN` | Optional | HackerOne integration |
| `BUGCROWD_API_TOKEN` | Optional | Bugcrowd integration |

4. Render auto-detects the `Dockerfile` and deploys

**Start Command:** `sh -c "python -m uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2"`

### CLI Usage

OPTISEC also ships a full command-line interface:

```bash
# Run a full scan
python main.py scan example.com --type full

# Specific scan types
python main.py scan example.com --type xss
python main.py scan example.com --type subdomain
python main.py scan example.com --type nmap --output results.json

# Manage targets
python main.py targets
python main.py add https://example.com --name "Example Corp"

# Generate PDF report
python main.py report example.com
```

---

## API Documentation

Interactive API documentation is available at runtime:

| Interface | URL | Description |
|-----------|-----|-------------|
| **Swagger UI** | `/docs` | Dark-themed interactive API explorer |
| **ReDoc** | `/redoc` | Full reference documentation |
| **OpenAPI JSON** | `/openapi.json` | Raw OpenAPI 3.0 spec |

### Authentication

All API endpoints require a JWT bearer token:

```bash
# 1. Obtain token
curl -X POST https://your-instance/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Response:
# { "access_token": "eyJ...", "token_type": "bearer", "user": {...} }

# 2. Use token in subsequent requests
export TOKEN="eyJ..."
curl -H "Authorization: Bearer $TOKEN" https://your-instance/api/scans
```

### Key Endpoints

#### Launch a Scan

```bash
curl -X POST https://your-instance/api/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_types": ["subdomain", "dns", "xss", "sqli"]
  }'

# Response: { "scan_id": "scan_a3f9b2c1d4e5f6a7" }
```

#### Monitor Scan Progress (WebSocket)

```javascript
const ws = new WebSocket("wss://your-instance/ws/scan/scan_a3f9b2c1d4e5f6a7");
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  // { "type": "progress", "step": "xss", "progress": 58, "status": "running" }
  // { "type": "completed", "progress": 100, "status": "done", "results": {...} }
};
```

#### NLP Command (Arabic/English)

```bash
curl -X POST https://your-instance/api/nlp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text": "افحص tesla.com عن ثغرات XSS"}'

# Response: { "action": "scan_xss", "target": "tesla.com", "confidence": 0.95 }
```

#### AI Security Analysis

```bash
curl -X POST https://your-instance/api/ai/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "findings": [...],
    "lang": "en"
  }'
```

#### IOC Correlations

```bash
# Get correlation clusters
curl -H "Authorization: Bearer $TOKEN" \
  "https://your-instance/api/correlations?refresh=true"

# Get specific cluster
curl -H "Authorization: Bearer $TOKEN" \
  "https://your-instance/api/correlations/cluster_abc123"
```

### API Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `POST /api/auth/login` | 5 failed attempts | 15-minute lockout |
| All other API endpoints | No hard limit | Valid token required |
| WebSocket connections | 1 per scan_id | Persistent until scan completes |

### Role Capabilities

| Role | Capabilities |
|------|-------------|
| `admin` | Full platform access — user management, all scans, license control |
| `analyst` | Launch scans, view all findings, generate reports, use all modules |
| `viewer` | Read-only access to own scans and findings |

---

## Licensing Tiers

OPTISEC operates on a feature-gated licensing model. The license is validated locally via HMAC-signed keys — no internet call-home required.

| Feature | FREE | PRO | ENTERPRISE |
|---------|:----:|:---:|:----------:|
| **Targets** | 3 | 50 | Unlimited |
| **Scans / Day** | 10 | 500 | Unlimited |
| **Users** | 1 | 5 | Unlimited |
| XSS Scanner | ✅ | ✅ | ✅ |
| SQL Injection | ✅ | ✅ | ✅ |
| DNS / WHOIS | ✅ | ✅ | ✅ |
| PDF Reports | ✅ | ✅ | ✅ |
| SSRF / LFI / Redirect | ❌ | ✅ | ✅ |
| Nmap / SSL / Headers | ❌ | ✅ | ✅ |
| Subdomain Enumeration | ❌ | ✅ | ✅ |
| OSINT Basic | ✅ | ✅ | ✅ |
| OSINT Advanced | ❌ | ✅ | ✅ |
| AI Analysis (Groq) | ❌ | ✅ | ✅ |
| Arabic/English NLP | ❌ | ✅ | ✅ |
| Bug Bounty Platform | ❌ | ✅ | ✅ |
| Compliance Checker | ❌ | ✅ | ✅ |
| Behavioral UEBA | ❌ | ✅ | ✅ |
| Zero-Day Prediction | ❌ | ✅ | ✅ |
| Attack Patterns | ❌ | ✅ | ✅ |
| AI Firewall + NGFW | ❌ | ✅ | ✅ |
| WireGuard VPN | ❌ | ✅ | ✅ |
| Quantum Crypto (PQC) | ❌ | ✅ | ✅ |
| REST API Access | ❌ | ✅ | ✅ |
| Autonomous Red Team | ❌ | ❌ | ✅ |
| MITRE ATT&CK Navigator | ❌ | ❌ | ✅ |
| Dark Web Intelligence | ❌ | ❌ | ✅ |
| Global Threat Feed | ❌ | ❌ | ✅ |
| IOC Correlations | ❌ | ❌ | ✅ |
| Federated Scanning | ❌ | ❌ | ✅ |
| User Management | ❌ | ❌ | ✅ |
| Multi-node Deployment | ❌ | ❌ | ✅ |

### Activate a License

```bash
# Via web dashboard: Settings → License → Enter Key
# Via API (admin only):
curl -X POST https://your-instance/api/license/activate \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "OPTISEC-PRO-XXXX-XXXX-XXXX"}'
```

> **Contact:** [ahssanali84.syber@gmail.com](mailto:ahssanali84.syber@gmail.com) for PRO/ENTERPRISE license inquiries.

---

## Security & Responsible Disclosure

### Security Architecture

OPTISEC is designed with security-first principles:

- **Authentication**: JWT tokens (30-minute expiry) with bcrypt password hashing (cost factor 12)
- **Rate Limiting**: IP-based failed login protection — 5 attempts triggers a 15-minute lockout
- **Session Security**: `HttpOnly` + `SameSite=Lax` cookies, sliding 30-minute window refresh
- **Role Isolation**: Database-level role enforcement; viewers cannot trigger scans
- **Non-root Container**: Docker image runs as `optisec` system user
- **Input Validation**: Pydantic v2 schema validation on all API inputs
- **Audit Logging**: Full auth event log (`logs/auth.log`) with IP, timestamp, outcome
- **Secrets Management**: All secrets via environment variables, never hardcoded

### Responsible Disclosure

OPTISEC is a legitimate security research tool. Usage must comply with applicable law and the following principles:

1. **Authorization First** — Only scan targets you own or have explicit written permission to test
2. **Bug Bounty Scope** — When using the bug bounty module, respect each program's defined scope
3. **No Unauthorized Access** — Do not use OPTISEC to access systems without authorization
4. **Data Privacy** — OSINT modules must be used in accordance with local privacy laws (GDPR, etc.)

#### Found a Vulnerability in OPTISEC itself?

We follow coordinated disclosure. Please report security issues **privately** before public disclosure:

- **Email**: [ahssanali84.syber@gmail.com](mailto:ahssanali84.syber@gmail.com)
- **Subject**: `[SECURITY] Brief description`
- **Response Time**: Within 48 hours
- **Disclosure Timeline**: 90-day coordinated disclosure window

We do not operate a formal bug bounty program for OPTISEC itself at this time, but we credit all responsibly reported vulnerabilities in the changelog.

---

## Roadmap

### v4.1 — Horizon *(Q3 2026)*
- [ ] Nuclei template integration — run community templates via OPTISEC UI
- [ ] Shodan / Censys passive recon module
- [ ] Scheduled recurring scans with email/webhook alerts
- [ ] CVSS v4.0 scoring engine

### v4.2 — Phantom *(Q4 2026)*
- [ ] Full SIEM integration (Elastic / Splunk / Wazuh)
- [ ] Playwright-based JavaScript-rendered XSS/DOM scanning
- [ ] Mobile app (React Native) for scan monitoring
- [ ] Multi-tenant organization support

### v5.0 — NEXUS *(2027)*
- [ ] Distributed agent network for global passive monitoring
- [ ] On-device local LLM support (Ollama / LM Studio)
- [ ] Real liboqs PQC library integration (CRYSTALS-Dilithium signatures)
- [ ] Full SOC workflow with ticket creation (Jira / ServiceNow)

---

## Contributing

We welcome contributions from the security community. Please read these guidelines before submitting a pull request.

### Development Setup

```bash
git clone https://github.com/OptisecDev/optisec-recon-pro.git
cd optisec-recon-pro
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py web --reload  # hot-reload for development
```

### Contribution Guidelines

1. **Fork** the repository and create a feature branch from `master`
2. **Test** your changes — ensure existing endpoints still respond correctly
3. **Document** new API endpoints with proper FastAPI docstrings and `tags`
4. **Security** — never commit credentials, API keys, or secrets
5. **Scope** — keep PRs focused; one feature or fix per PR
6. **Style** — follow existing code conventions

### Pull Request Checklist

- [ ] Branch created from latest `master`
- [ ] No hardcoded secrets or credentials
- [ ] New routes include proper `tags`, `summary`, and `responses` metadata
- [ ] `.env.example` updated if new environment variables are introduced
- [ ] `requirements.txt` updated if new packages are added

### Issue Reporting

When reporting bugs, include:
- OPTISEC version (`/api/license/status`)
- Python version and OS
- Steps to reproduce
- Expected vs. actual behavior
- Relevant logs from `logs/auth.log` or stdout

---

## License & Contact

```
Copyright (c) 2026 OptisecDev. All Rights Reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, in whole or in
part, is strictly prohibited without prior written consent from OptisecDev.

The FREE tier may be used for personal and educational purposes.
Commercial use requires a PRO or ENTERPRISE license.
```

### Contact

| Channel | Address |
|---------|---------|
| **GitHub** | [@OptisecDev](https://github.com/OptisecDev) |
| **Email** | [ahssanali84.syber@gmail.com](mailto:ahssanali84.syber@gmail.com) |
| **Security Issues** | [ahssanali84.syber@gmail.com](mailto:ahssanali84.syber@gmail.com) with subject `[SECURITY]` |

---

<div align="center">

**Built with dedication for the security community**

*OPTISEC v4.0 SINGULARITY — Redefining Security Intelligence*

[![GitHub](https://img.shields.io/badge/GitHub-OptisecDev-181717?style=for-the-badge&logo=github)](https://github.com/OptisecDev)

</div>
