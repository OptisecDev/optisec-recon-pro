<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║   ██████  ██████  ████████ ██  ██  ███████ ███████  ██████     ║
║  ██    ██ ██   ██    ██    ██ ██  ██      ██      ██           ║
║  ██    ██ ██████     ██    ████   ███████ █████   ██           ║
║  ██    ██ ██         ██    ██ ██       ██ ██      ██           ║
║   ██████  ██         ██    ██  ██ ███████ ███████  ██████      ║
╠══════════════════════════════════════════════════════════════════╣
║        R E C O N   P R O  ·  v 4 . 0  S I N G U L A R I T Y  ║
║           Enterprise Cybersecurity Intelligence Platform        ║
╚══════════════════════════════════════════════════════════════════╝
```

<p>
  <img src="https://img.shields.io/badge/Version-v4.0%20SINGULARITY-ff0055?style=for-the-badge&logo=rocket&logoColor=white" alt="Version" />
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-Async-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/AI-Groq%20LLaMA-ff6b35?style=for-the-badge&logo=meta&logoColor=white" alt="AI" />
  <img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/Status-Active-00ff88?style=for-the-badge&logo=statuspage&logoColor=white" alt="Status" />
</p>

<p>
  <img src="https://img.shields.io/github/stars/OptisecDev/optisec-recon-pro?style=for-the-badge&color=fbbf24&logo=github" alt="Stars" />
  <img src="https://img.shields.io/github/forks/OptisecDev/optisec-recon-pro?style=for-the-badge&color=60a5fa&logo=github" alt="Forks" />
  <img src="https://img.shields.io/github/issues/OptisecDev/optisec-recon-pro?style=for-the-badge&color=f87171&logo=github" alt="Issues" />
  <img src="https://img.shields.io/badge/Endpoints-149%2B-8b5cf6?style=for-the-badge" alt="Endpoints" />
  <img src="https://img.shields.io/badge/Modules-17-06b6d4?style=for-the-badge" alt="Modules" />
</p>

<h3>The all-in-one, self-hosted cybersecurity intelligence platform for<br/>penetration testers, bug bounty hunters, and security operations teams.</h3>

<p>
  <a href="#-quick-start"><strong>Quick Start</strong></a> ·
  <a href="#-features"><strong>Features</strong></a> ·
  <a href="#-screenshots"><strong>Screenshots</strong></a> ·
  <a href="#-api-reference"><strong>API Docs</strong></a> ·
  <a href="#-try-the-demo"><strong>Live Demo</strong></a> ·
  <a href="#-contributing"><strong>Contributing</strong></a>
</p>

</div>

---

## Table of Contents

- [Overview](#-overview)
- [What's New in v4.0 SINGULARITY](#-whats-new-in-v40-singularity)
- [Features](#-features)
- [Screenshots](#-screenshots)
- [Try the Demo](#-try-the-demo)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [License Tiers](#-license-tiers)
- [Security](#-security)
- [Contributing](#-contributing)
- [About](#-about)

---

## Overview

**OPTISEC Recon Pro** is a full-stack, enterprise-grade cybersecurity intelligence platform that consolidates 17 security modules into a single, self-hosted dashboard. From automated reconnaissance and AI-powered vulnerability analysis to dark web monitoring, post-quantum cryptography, and autonomous red team simulations — OPTISEC gives solo analysts and distributed SOC teams the same intelligence depth previously available only in expensive commercial products.

**Built on** FastAPI (async), SQLAlchemy 2.0, Groq LLaMA AI, and a modular Python architecture that runs on any VPS with a single command.

| Stat | Value |
|------|-------|
| REST API Endpoints | **149+** |
| Security Modules | **17** |
| Feature Gates | **32** |
| Compliance Frameworks | **4** (ISO 27001, NIST CSF 2.0, GDPR, PCI-DSS) |
| Bug Bounty Platforms | **3** (HackerOne, Bugcrowd, Intigriti) |
| ATT&CK Techniques Mapped | **278** across 14 tactics |
| Threat Records (Dark Web) | **4 billion+** |

---

## What's New in v4.0 SINGULARITY

> Released June 2026 — the most significant update to date.

| # | New Module | Capability |
|---|-----------|------------|
| 1 | **ATT&CK Navigator** | Full interactive MITRE ATT&CK matrix — 14 tactics, 278 techniques, 8 APT profiles, IOC→technique mapping |
| 2 | **Dark Web Intelligence** | Breach detection across 4B+ records, paste scanner with 15 pattern templates, Tor exit-node monitoring, ransomware gang tracking |
| 3 | **Autonomous Red Team** | 7-phase kill-chain simulation, 8-category payload library, AI-generated pentest debrief reports |
| 4 | **NGFW v2** | ML-enhanced deep-packet inspection with Shannon entropy scoring, geo-blocking, and live traffic visualization |
| 5 | **Global Threat Feed** | 20-point geo threat map, TLP-aware IOC federation, multi-source campaign correlation |

Also shipped in v4.0:
- Professional dashboard with live Threat Level Gauge, Chart.js analytics, and real-time activity feed
- Full Swagger UI 5 + ReDoc with OPTISEC dark theme at `/docs` and `/redoc`
- Interactive web API docs at `/api-docs` with 149-endpoint searchable table
- HMAC-SHA256 license engine with FREE / PRO / ENTERPRISE tiers
- Public landing page + one-click `/demo` login

---

## Features

### Core Security Modules

| Module | Description |
|--------|-------------|
| **Recon Engine** | Subdomain enumeration, DNS record analysis, WHOIS lookup, and Nmap port scanning in a single async pipeline |
| **Vulnerability Scanner** | Automated detection of XSS, SQL injection, SSRF, LFI, and open-redirect — with CVSS severity scoring |
| **OSINT Intelligence** | Email profiling, social media footprinting, IP geolocation, phone/carrier lookup, and username enumeration across platforms |
| **IOC Correlation** | AlienVault OTX integration — automatically clusters indicators and surfaces campaign patterns |
| **SSL/TLS Auditor** | Deep certificate chain analysis, cipher suite scoring, and protocol downgrade detection |
| **HTTP Headers Audit** | CSP, HSTS, X-Frame-Options, and 15+ security header checks with remediation guidance |

### Threat Intelligence

| Module | Description |
|--------|-------------|
| **ATT&CK Navigator** | Interactive matrix covering all 14 MITRE ATT&CK tactics and 278 techniques; 8 built-in APT profiles; IOC→technique mapping |
| **Global Threat Feed** | Live 20-point geo threat map; TLP-aware IOC federation; campaign correlation across multiple threat feeds |
| **Dark Web Intelligence** | Breach record lookup (4B+ records), paste site scanner (15 pattern templates), Tor exit-node monitor, ransomware tracker |
| **UEBA Behavioral Analytics** | Continuous entity profiling for users and devices; real-time anomaly scoring and alert generation |
| **Zero-Day Prediction** | Groq AI + NVD + CISA KEV fusion — predicts exploitation likelihood before public PoC release |
| **Kill-Chain Correlation** | Maps observed IOCs and TTPs to MITRE ATT&CK stages; detects multi-stage campaigns automatically |

### AI & Red Team

| Module | Description |
|--------|-------------|
| **AI Red Team Planner** | Groq-powered engagement planner — generates phased attack plans, tailored payloads, and debrief reports |
| **Autonomous Red Team** | 7-phase kill-chain simulation engine with 8-category payload library and AI-generated pentest reports |
| **NLP Scan Interface** | Natural language query → structured scan parameters (e.g., *"check example.com for SQL injection"*) |

### Compliance & Infrastructure

| Module | Description |
|--------|-------------|
| **Compliance Checker** | Automated gap analysis for ISO 27001, NIST CSF 2.0, GDPR, and PCI-DSS with actionable control mapping |
| **AI Firewall (DPI)** | 12-rule deep-packet inspection with ML anomaly scoring and rate limiting |
| **NGFW v2** | ML-enhanced DPI with Shannon entropy scoring, geo-blocking, and live traffic charts |
| **Post-Quantum Cryptography** | Generate Kyber-768, Dilithium, and SPHINCS+ keypairs; hybrid AES-256-GCM encryption future-proofed against quantum threats |
| **WireGuard VPN Manager** | Generate server/peer configs, manage peers, and export QR codes — all from the web UI |
| **Federated Scanning** | Distribute scans across multiple OPTISEC nodes; aggregate findings centrally with signed task delegation |

### Bug Bounty

| Module | Description |
|--------|-------------|
| **HackerOne** | Browse programs, check scope, submit reports directly via the HackerOne API |
| **Bugcrowd / Intigriti** | Program browsing and report submission for Bugcrowd and Intigriti |
| **CVE Pipeline** | Draft, queue, and submit CVEs to MITRE NVD; full NVD search with CISA KEV cross-reference |

### Platform

- **Role-Based Access Control** — Admin / Analyst / Viewer roles with JWT cookies, API key auth, and audit logging
- **WebSocket Live Progress** — Real-time scan progress streamed to the browser via `/ws/scan/{scan_id}`
- **PDF Report Generation** — Professional security reports via ReportLab, downloadable from the dashboard
- **Async Architecture** — FastAPI + SQLAlchemy 2.0 async — handles concurrent scans without blocking
- **CLI Interface** — Full-featured command-line client with NLP parser for headless operations

---

## Screenshots

### Landing & Login

| Landing Page | Login |
|-------------|-------|
| ![Landing](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/login.png) | ![Login](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/login.png) |

### Dashboard

| Dashboard Overview |
|-------------------|
| ![Dashboard](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/dashboard.png) |

### Reconnaissance & Scanning

| New Scan | Scan History |
|----------|-------------|
| ![Scan](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/scan.png) | ![Scans](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/scans.png) |

### Threat Intelligence

| ATT&CK Navigator | Global Threat Feed |
|-----------------|-------------------|
| ![ATT&CK Navigator](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/attack_navigator.png) | ![Threat Feed](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/threat_feed.png) |

| IOC Correlations | Dark Web Intelligence |
|-----------------|----------------------|
| ![Correlations](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/correlations.png) | ![Dark Web](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/darkweb.png) |

### AI Security

| Zero-Day Prediction | Kill-Chain Correlation |
|---------------------|----------------------|
| ![Zero-Day](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/zero_day.png) | ![Attack Patterns](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/attack_patterns.png) |

| Behavioral Analytics | AI Red Team Planner |
|---------------------|---------------------|
| ![Behavioral](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/behavioral.png) | ![Red Team](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/red_team.png) |

| Autonomous Red Team |
|--------------------|
| ![Autonomous Red Team](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/autonomous_redteam.png) |

### Compliance & Firewall

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

| Target Management | Admin Panel |
|------------------|------------|
| ![Targets](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/targets.png) | ![Admin](https://raw.githubusercontent.com/OptisecDev/optisec-recon-pro/master/docs/screenshots/admin.png) |

---

## Try the Demo

Explore a fully seeded instance — no signup required.

```
URL:      http://localhost:8000/demo
Username: demo
Password: Demo@optisec1
```

The demo account comes pre-loaded with:
- 5 targets (tesla, google, microsoft, apple, amazon)
- 5 completed scans with realistic timings
- 8 findings (2 Critical, 3 High, 2 Medium, 1 Low)
- Pre-generated PDF reports

Or hit `/demo` to be logged in automatically with one click.

---

## Quick Start

### Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.11+ |
| Git | Any |
| PostgreSQL | Optional (SQLite default) |

### Installation

```bash
# 1. Clone
git clone https://github.com/OptisecDev/optisec-recon-pro.git
cd optisec-recon-pro

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — at minimum set GROQ_API_KEY and JWT_SECRET

# 5. Launch
./optisec.sh
```

The launcher activates the virtual environment, loads `.env`, starts Uvicorn with hot-reload, and opens the dashboard at `http://localhost:8000`.

### First Login

On first startup, an admin account is seeded automatically:

| Field | Default |
|-------|---------|
| Username | `admin` |
| Email | `admin@optisec.local` |
| Password | `admin123` |

> **Change the admin password immediately in production.**

### Docker

```bash
docker build -t optisec-recon-pro .
docker run -p 8000:8000 --env-file .env optisec-recon-pro
```

---

## Configuration

All settings are controlled via environment variables. Copy `.env.example` to `.env` and fill in your values.

```env
# ── Core ──────────────────────────────────────────────────────────
JWT_SECRET=change-this-to-a-long-random-secret
JWT_EXPIRE_HOURS=24

# ── AI ────────────────────────────────────────────────────────────
GROQ_API_KEY=your_groq_api_key

# ── Database ──────────────────────────────────────────────────────
# SQLite (default — zero setup)
DATABASE_URL=sqlite+aiosqlite:///./data/optisec.db

# PostgreSQL (recommended for production)
# DATABASE_URL=postgresql+asyncpg://optisec:password@localhost/optisec

# ── Threat Intelligence ───────────────────────────────────────────
OTX_API_KEY=your_alienvault_otx_key

# ── Bug Bounty ────────────────────────────────────────────────────
HACKERONE_USERNAME=your_h1_username
HACKERONE_API_TOKEN=your_h1_token
BUGCROWD_API_TOKEN=your_bugcrowd_token
INTIGRITI_API_TOKEN=your_intigriti_token

# ── CVE Submission ────────────────────────────────────────────────
CVE_CNA_ORG=your_cna_org
CVE_CNA_USERNAME=your_cna_user
CVE_CNA_API_KEY=your_cna_key
NVD_API_KEY=your_nvd_key

# ── License ───────────────────────────────────────────────────────
OPTISEC_LICENSE_SECRET=your_license_secret

# ── Admin Seed ────────────────────────────────────────────────────
FIRST_ADMIN_USER=admin
FIRST_ADMIN_EMAIL=admin@optisec.local
FIRST_ADMIN_PASSWORD=admin123
```

---

## API Reference

Interactive docs are available at:

| URL | Interface |
|-----|-----------|
| `/docs` | Swagger UI 5 (dark OPTISEC theme) |
| `/redoc` | ReDoc with OPTISEC theme |
| `/api-docs` | Web UI with 149-endpoint searchable table, curl examples, WebSocket guide |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Authenticate and receive JWT token |
| `POST` | `/api/auth/register` | Register a new user account |
| `POST` | `/api/auth/api-key/regenerate` | Rotate your API key |

All authenticated endpoints accept either a `Bearer` token in the `Authorization` header or an `access_token` httponly cookie. API keys are accepted via the `X-API-Key` header.

### Reconnaissance & Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Launch a full recon + vuln scan |
| `GET` | `/api/scan/{scan_id}` | Fetch scan status and results |
| `GET` | `/api/scans` | List all scans (paginated) |
| `GET` | `/api/findings` | Query findings with severity/type filters |
| `POST` | `/api/scan/ssl` | SSL/TLS certificate deep analysis |
| `POST` | `/api/scan/headers` | HTTP security headers audit |
| `POST` | `/api/scan/ports` | TCP port scan via Nmap |
| `GET` | `/ws/scan/{scan_id}` | WebSocket — real-time scan progress |

### AI & Threat Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ai/analyze` | Groq LLaMA AI threat analysis on findings |
| `POST` | `/api/nlp` | Natural language query → scan parameters |
| `POST` | `/ai-security/api/zero-day/predict` | Zero-day exploitation risk prediction |
| `POST` | `/ai-security/api/behavioral/profile` | UEBA entity profile analysis |
| `POST` | `/ai-security/api/attack-patterns/analyze` | Kill-chain stage correlation |
| `POST` | `/ai-security/api/red-team/engagements` | Create AI-planned red team engagement |
| `POST` | `/autonomous-redteam/api/simulate` | Run full kill-chain simulation |

### Threat Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/threat-feed/api/feed` | Live global threat intelligence feed |
| `GET` | `/threat-feed/api/threat-map` | Geo-distributed threat map data |
| `POST` | `/threat-feed/api/submit-ioc` | Submit IOC to the federation |
| `GET` | `/api/correlations` | IOC correlation clusters (AlienVault OTX) |
| `GET` | `/attack-navigator/api/matrix` | Full ATT&CK matrix with APT overlays |
| `POST` | `/darkweb/api/check-domain` | Dark web exposure check |
| `POST` | `/darkweb/api/check-email` | Breach record lookup for email |

### Compliance & Bug Bounty

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/compliance/api/frameworks` | List available compliance frameworks |
| `POST` | `/compliance/api/assess` | Run automated compliance gap assessment |
| `GET` | `/bug-bounty/api/hackerone/programs` | Browse HackerOne public programs |
| `POST` | `/bug-bounty/api/hackerone/submit` | Submit a bug report to HackerOne |
| `GET` | `/bug-bounty/api/cve/search` | Search NVD CVE database |

### Infrastructure

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/quantum/api/keypair` | Generate post-quantum (Kyber-768) keypair |
| `POST` | `/quantum/api/encrypt` | Hybrid AES-256-GCM + PQC encryption |
| `GET` | `/vpn/api/peers` | List WireGuard peers |
| `POST` | `/vpn/api/peers` | Add a new WireGuard peer |
| `GET` | `/federation/api/nodes` | List federated scan nodes |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/report` | Generate PDF security report |
| `GET` | `/reports/download/{filename}` | Download generated report |

---

## Architecture

```
optisec-recon-pro/
├── web/                        # FastAPI web application
│   ├── app.py                  # Application factory, routes, middleware
│   ├── auth.py                 # JWT + bcrypt + API key authentication
│   ├── database.py             # SQLAlchemy 2.0 async engine
│   ├── models.py               # User, Target, Scan, Finding, Report ORM models
│   ├── schemas.py              # 25+ Pydantic request/response models
│   ├── license.py              # HMAC-SHA256 license engine
│   ├── websocket_manager.py    # Real-time scan progress via WebSocket
│   ├── routers/                # 17 feature routers (one per module)
│   ├── templates/              # Jinja2 dark-theme HTML templates
│   └── static/                 # CSS, JS, and assets
│
├── modules/                    # Security module library
│   ├── recon/                  # Subdomain, DNS, WHOIS, Nmap
│   ├── vuln/                   # XSS, SQLi, SSRF, LFI, redirect
│   ├── osint/                  # Email, social, geo, phone, username
│   ├── ai_advanced/            # Zero-day, UEBA, kill-chain, red team, autonomous
│   ├── threat_intel/           # MITRE ATT&CK, IOC, global feed
│   ├── darkweb/                # Breach intel, paste scanner, Tor monitor
│   ├── bug_bounty/             # HackerOne, Bugcrowd, Intigriti, CVE pipeline
│   ├── compliance/             # ISO 27001, NIST CSF 2.0, GDPR, PCI-DSS
│   ├── firewall/               # AI DPI firewall + NGFW v2
│   ├── quantum/                # Post-quantum cryptography (PQC)
│   ├── vpn/                    # WireGuard management
│   ├── federation/             # Multi-node distributed scanning
│   └── report/                 # PDF generation via ReportLab
│
├── cli/                        # Command-line interface with NLP parser
├── data/                       # Runtime data, keys, behavioral profiles
├── docs/screenshots/           # Platform screenshots (25 pages)
├── optisec.sh                  # One-command launcher
└── requirements.txt
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Web Framework** | FastAPI 0.104+ (async, OpenAPI 3.1) |
| **ASGI Server** | Uvicorn with uvloop |
| **Database ORM** | SQLAlchemy 2.0 (async) |
| **Database Drivers** | aiosqlite (default) · asyncpg (PostgreSQL) |
| **Migrations** | Alembic |
| **Authentication** | python-jose (JWT) · bcrypt 4.x |
| **AI / LLM** | Groq API (LLaMA 3) |
| **Threat Intel** | AlienVault OTX · MITRE ATT&CK · CISA KEV · NVD |
| **Templates** | Jinja2 · dark theme (accent `#00ff88`) |
| **Frontend** | Vanilla JS · Chart.js · WebSocket |
| **PDF Reports** | ReportLab |
| **Cryptography** | PQC (Kyber-768, Dilithium, SPHINCS+) · AES-256-GCM |
| **VPN** | WireGuard |
| **HTTP Client** | httpx (async) · requests |
| **Scheduler** | APScheduler |
| **Port Scanner** | Nmap (via python-nmap) |

---

## License Tiers

OPTISEC Recon Pro uses a built-in HMAC-SHA256 license system. Activate your license at `/license`.

| Feature | Free | Pro | Enterprise |
|---------|:----:|:---:|:----------:|
| Recon Engine | ✅ | ✅ | ✅ |
| Vulnerability Scanner | ✅ | ✅ | ✅ |
| OSINT Intelligence | ✅ | ✅ | ✅ |
| Report Generation | ✅ | ✅ | ✅ |
| WebSocket Live Progress | ✅ | ✅ | ✅ |
| AI Threat Analysis | ❌ | ✅ | ✅ |
| Zero-Day Prediction | ❌ | ✅ | ✅ |
| Kill-Chain Correlation | ❌ | ✅ | ✅ |
| AI Red Team Planner | ❌ | ✅ | ✅ |
| Autonomous Red Team | ❌ | ✅ | ✅ |
| Dark Web Intelligence | ❌ | ✅ | ✅ |
| ATT&CK Navigator | ❌ | ✅ | ✅ |
| UEBA Behavioral Analytics | ❌ | ✅ | ✅ |
| Global Threat Feed | ❌ | ✅ | ✅ |
| Bug Bounty Integration | ❌ | ✅ | ✅ |
| CVE Pipeline | ❌ | ✅ | ✅ |
| Compliance Checker | ❌ | ✅ | ✅ |
| Post-Quantum Cryptography | ❌ | ✅ | ✅ |
| WireGuard VPN Manager | ❌ | ✅ | ✅ |
| AI Firewall / NGFW v2 | ❌ | ✅ | ✅ |
| Federated Scanning | ❌ | ❌ | ✅ |
| Multi-Tenant | ❌ | ❌ | ✅ |
| SLA Support | ❌ | ❌ | ✅ |
| **Max Targets** | 5 | 50 | Unlimited |
| **Max Users** | 1 | 5 | Unlimited |
| **Price** | Free | $149/yr | Contact us |

---

## Security

### Responsible Disclosure

If you discover a security vulnerability in OPTISEC Recon Pro, please report it responsibly:

- **Email:** ahssanali84.syber@gmail.com
- **Subject:** `[SECURITY] <brief description>`
- Please do **not** open a public GitHub issue for security vulnerabilities.

We aim to acknowledge reports within 48 hours and provide a fix or mitigation within 14 days.

### Security Hardening (Production)

```bash
# Use a strong, randomly generated JWT secret
JWT_SECRET=$(openssl rand -hex 64)

# Use PostgreSQL instead of SQLite
DATABASE_URL=postgresql+asyncpg://optisec:password@localhost/optisec

# Run behind a reverse proxy (Nginx / Caddy) with TLS
# Never expose Uvicorn directly to the internet

# Change default admin credentials immediately
FIRST_ADMIN_PASSWORD=<strong-unique-password>
```

---

## Contributing

Contributions are welcome. Please follow these steps:

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make your changes** — keep commits atomic and well-described:
   ```bash
   git commit -m "feat: add your feature description"
   ```

3. **Test** your changes locally:
   ```bash
   source venv/bin/activate
   python -m uvicorn web.app:app --reload
   ```

4. **Push** to your fork and **open a Pull Request** against `master`.

### Guidelines

- Follow existing code style (no formatter is enforced, but match surrounding code)
- New security modules should live under `modules/` with a corresponding router in `web/routers/`
- Include at least one screenshot in `docs/screenshots/` for new UI pages
- Do not commit `.env` files, credentials, or API keys

---

## About

**OPTISEC** is an independent cybersecurity engineering project dedicated to building open-source, production-ready security tooling for the modern threat landscape.

OPTISEC Recon Pro is the flagship platform — designed to give security professionals the same intelligence capabilities typically reserved for enterprise SOC teams, delivered as a self-hosted, open-source package that anyone can deploy, extend, and own.

> *"Security is not a product, it's a process — and that process deserves professional tooling."*

**Built by [Ehsan Ali](https://github.com/OptisecDev)**

| | |
|---|---|
| **GitHub** | [github.com/OptisecDev/optisec-recon-pro](https://github.com/OptisecDev/optisec-recon-pro) |
| **Issues** | [github.com/OptisecDev/optisec-recon-pro/issues](https://github.com/OptisecDev/optisec-recon-pro/issues) |
| **Email** | ahssanali84.syber@gmail.com |

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with dedication by **Ehsan Ali** · OPTISEC © 2026

<sub>If OPTISEC Recon Pro helps your security work, consider giving it a ⭐ on GitHub</sub>

</div>
