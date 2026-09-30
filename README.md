<div align="center">

<img src="docs/screenshots/landing.png" alt="OPTISEC v4.0 SINGULARITY" width="100%">

# OPTISEC v4.0 SINGULARITY

### Enterprise Security Intelligence Platform

[![License](https://img.shields.io/badge/License-Proprietary-red.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Status](https://img.shields.io/badge/Status-Production-00ff88.svg?style=for-the-badge)](https://github.com/OptisecDev/optisec-recon-pro)
[![Version](https://img.shields.io/badge/Version-4.0.0--SINGULARITY-bc8cff.svg?style=for-the-badge)](https://github.com/OptisecDev/optisec-recon-pro/releases)
[![OSINT Engine](https://img.shields.io/badge/OSINT%20Engine-v5.0-bc8cff.svg?style=for-the-badge)](#osint-engine-v50--world-class-intelligence)
[![OSINT Sources](https://img.shields.io/badge/OSINT%20Sources-8-00d4ff.svg?style=for-the-badge)](#osint-engine-v50--world-class-intelligence)
[![Tests](https://img.shields.io/badge/Tests-72%20Passing-00ff88.svg?style=for-the-badge&logo=pytest&logoColor=white)](tests/test_unified_osint.py)
[![Stars](https://img.shields.io/github/stars/OptisecDev/optisec-recon-pro?style=for-the-badge&color=00ff88)](https://github.com/OptisecDev/optisec-recon-pro/stargazers)

**A full-stack, AI-powered security intelligence platform built for bug bounty hunters,  
red teamers, and enterprise SOC teams — featuring 12 delivered scanning modules  
and full Arabic/English NLP, with MITRE ATT&CK mapping, autonomous red-team simulation,  
and post-quantum-ready cryptography tooling in active development ([roadmap](#roadmap)).**

[Live Demo](https://optisec-recon-pro.onrender.com/demo) · [API Docs](https://optisec-recon-pro.onrender.com/docs) · [License Store](https://optisecdev.github.io/optisec-store) · [Report Bug](https://github.com/OptisecDev/optisec-recon-pro/issues) · [Request Feature](https://github.com/OptisecDev/optisec-recon-pro/issues)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features Matrix — 12 Delivered Modules](#features-matrix--12-delivered-modules)
  - [🛠️ In Active Development](#-in-active-development--built-not-yet-fully-launched)
  - [Bug Bounty Submission Safety](#bug-bounty-submission-safety)
- [OSINT Engine v5.0 — World-Class Intelligence](#osint-engine-v50--world-class-intelligence)
- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
  - [Quick Start (Local)](#quick-start-local)
  - [Docker Compose](#docker-compose)
  - [Deploy to Render](#deploy-to-render)
- [API Documentation](#api-documentation)
- [Licensing Tiers](#licensing-tiers)
- [Ethical Use Policy](#ethical-use-policy)
- [Security & Responsible Disclosure](#security--responsible-disclosure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License & Contact](#license--contact)

---

## Overview

**OPTISEC v4.0 SINGULARITY** is a comprehensive bug bounty and penetration testing platform that consolidates the entire security research workflow into a single, unified web dashboard: subdomain enumeration, vulnerability scanning, OSINT, and AI-assisted analysis, with several further modules — MITRE ATT&CK mapping, autonomous red-team simulation, quantum-safe crypto, compliance auditing, next-gen firewall DPI, and a global threat feed — already in the codebase and actively being hardened for production (see [Roadmap](#roadmap)).

> **بالعربية:** **OPTISEC v4.0 SINGULARITY** منصة استخبارات أمنية متكاملة موجهة لصائدي الثغرات (Bug Bounty) وفرق الاختراق الأخلاقي وفرق العمليات الأمنية (SOC)، تجمع وحدات فحص واستخبارات فعلية — من استكشاف النطاقات الفرعية إلى الفحص الأمني والتحليل بالذكاء الاصطناعي — في لوحة تحكم واحدة، مع دعم كامل للغة العربية في واجهة الأوامر الطبيعية (NLP) ووحدات استخبارات مفتوحة المصدر (OSINT) مخصصة للسياق العراقي (البحث بالهوية الوطنية، لوحات المركبات). وحدات أخرى — خريطة MITRE ATT&CK، محاكاة الفريق الأحمر المستقل، التشفير ما بعد الكمّي، تدقيق الامتثال، وخلاصة التهديدات العالمية — موجودة في الكود وقيد التطوير النشط، انظر [خارطة الطريق](#roadmap).

### Why OPTISEC?

| Problem | OPTISEC Solution |
|---------|-----------------|
| Fragmented tooling (Nmap, Burp, nuclei, theHarvester…) | Single unified dashboard with 12 delivered modules |
| Manual report writing takes hours | One-click professional PDF reports |
| No Arabic-language security tooling | Native Arabic + English NLP command interface |
| Bug bounty context switching between H1/Bugcrowd | Unified bug bounty management with direct HackerOne/Bugcrowd submission APIs — every real submission requires an explicit preview + confirmation step, see [Bug Bounty Submission Safety](#bug-bounty-submission-safety) |
| Quantum threats to modern encryption | Kyber-768 post-quantum key encapsulation module — currently roadmap, see [below](#-in-active-development--built-not-yet-fully-launched) |
| SOC teams need correlation across threat feeds | IOC correlation engine with AlienVault OTX integration |

---

## Features Matrix — 12 Delivered Modules

### Core Scanning Engine

| Module | Capabilities | Tier |
|--------|-------------|------|
| **Reconnaissance** | Subdomain enumeration (wordlist + DNS brute), DNS lookup (A/MX/TXT/NS/CNAME), WHOIS, Nmap service detection, SSL/TLS analysis, Security headers grading, Port scanning | FREE+ |
| **Vulnerability Scanner** | XSS (reflected/stored), SQL Injection, SSRF (cloud metadata bypass), LFI (path traversal), Open Redirect | FREE+ |
| **OSINT Engine v5.0** | Unified 8-source intelligence search (Amass, theHarvester, Maigret, Holehe, crt.sh, Wayback, DNS Full, WHOIS) with confidence scoring + correlation engine — see [deep dive](#osint-engine-v50--world-class-intelligence) — plus email discovery, social media footprint, phone intelligence, IP geolocation, username search (200+ platforms), device fingerprinting, national ID lookup (Iraq), vehicle plate recon, cell tower triangulation | FREE/PRO |

### AI & Intelligence

| Module | Capabilities | Tier |
|--------|-------------|------|
| **AI Security Analysis** | Groq LLaMA-3.3-70B powered threat analysis, CVE mapping, attack chain reconstruction, remediation prioritization | PRO+ |
| **Behavioral UEBA** | User and Entity Behavior Analytics, anomaly detection, insider threat profiling | PRO+ |
| **Zero-Day Prediction** | Groq LLM-powered vulnerability forecasting against NVD/CISA KEV data (heuristic fallback if no API key is set), exploit probability scoring | PRO+ |
| **Attack Pattern Engine** | Known malicious pattern library, payload classification, kill chain analysis | PRO+ |

### Platform & Integration

| Module | Capabilities | Tier |
|--------|-------------|------|
| **Bug Bounty Platform** | HackerOne program browser + real report submission, Bugcrowd program discovery + real submission (both gated by an explicit preview + confirmation step — see [below](#bug-bounty-submission-safety)), Intigriti program browsing (read-only — no submission API yet), CVE pipeline (NVD/MITRE) | PRO+ |
| **Threat Intelligence** | AlienVault OTX live feed, HIBP breach detection, Honeypot detection, IOC correlation clustering | ENTERPRISE |
| **Federated Scanning** | Multi-node OPTISEC cluster coordination, distributed scan tasks, node health monitoring | ENTERPRISE |

### Infrastructure Security

| Module | Capabilities | Tier |
|--------|-------------|------|
| **AI Firewall (WAF)** | Rule-based traffic analysis (entropy & pattern scoring), IP whitelist/blacklist, custom rule engine | PRO+ |
| **WireGuard VPN** | Peer management, key generation + QR codes, config export | PRO+ |

### 🛠️ In Active Development — built, not yet fully launched

These modules already have real routers, database models, and passing test
coverage in this repository — they are not vaporware — but each ships a
meaningfully smaller slice of its headline claim than earlier drafts of this
README implied, and the public [landing page](web/templates/landing.html)
correctly lists them under its own "roadmap — coming soon" section rather
than as delivered features. Don't rely on any of these for a real
engagement or compliance sign-off yet.

| Module | Actual current state | Code |
|--------|----------------------|------|
| **MITRE ATT&CK Navigator** | Real technique-mapping UI over a real MITRE dataset; cross-campaign APT correlation is not built yet | `modules/threat_intel/attack_navigator.py`, `modules/threat_intel/mitre.py` |
| **Autonomous Red Team** | Phases 1 (recon) and 3 (web vuln scan) run real scans; the other kill-chain phases (weaponization, post-exploitation, lateral movement, objective completion) return *simulated* findings, not genuine autonomous exploitation | `modules/ai_advanced/autonomous_redteam.py` |
| **Quantum-Safe Crypto** | Kyber-768 KEM runs in simulated mode by default; real PQC requires the optional `liboqs` backend, which most deployments don't install | `modules/quantum/encryption.py` |
| **Compliance Checker** | Questionnaire-driven framework scoring (ISO 27001, NIST CSF, GDPR, PCI-DSS) with one automated probe (HTTPS/TLS signal detection) — not a full automated compliance scan | `modules/compliance/checker.py` |
| **NGFW v2** | Real heuristic Deep Packet Inspection (entropy/pattern-based anomaly scoring) — explicitly *not* a trained ML model despite the "next-gen" name | `modules/firewall/ngfw_v2.py` |
| **Global Threat Feed** | The UI and correlation logic are real, and the URLhaus stream is backed by a live sync job — but every other listed source (Mandiant, CISA KEV, Spamhaus, MISP, Feodo Tracker, Abuse.ch) is fabricated sample data today, not a live feed, despite being labeled with those real vendor/source names in the running app | `modules/threat_intel/global_feed.py` |

### Platform Features

- **Real-time WebSocket** — Live scan progress streaming (`ws://host/ws/scan/{scan_id}`)
- **Arabic/English NLP** — Natural language command interface (`افحص tesla.com عن ثغرات XSS`)
- **Role-Based Access** — Admin / Analyst / Viewer permission model
- **PDF Reports** — Professional executive-grade security reports with ReportLab
- **REST API** — Full OpenAPI 3.0 spec at `/docs` and `/redoc`
- **Demo Mode** — One-click `/demo` login with pre-populated findings and targets

### Bug Bounty Submission Safety

`POST /bug-bounty/api/hackerone/submit` and `POST /bug-bounty/api/bugcrowd/submit`
call the real HackerOne / Bugcrowd APIs the moment `HACKERONE_API_TOKEN` /
`BUGCROWD_API_TOKEN` is configured — under the platform's single shared
credential, not a per-user one. To make a real submission impossible
without an explicit, per-report human confirmation:

1. `POST /bug-bounty/api/{hackerone,bugcrowd}/submit/preview` — accepts the
   draft report and returns the *exact* content that would be sent, plus a
   `confirm_token` bound to that content via HMAC and valid for 10 minutes.
2. `POST /bug-bounty/api/{hackerone,bugcrowd}/submit` — refuses with `400`
   unless the request echoes back `"confirmed": true` and that same
   `confirm_token`. Editing so much as one field after preview invalidates
   the token and forces a fresh preview; the token also can't be replayed by
   a different account.

This is enforced server-side (`web/routers/bug_bounty.py`), so it holds
regardless of what the web UI does or whether a caller talks to the API
directly. Unit tests with a mocked `submit_report`/`bc_submit_report`
assert the external call is never invoked without a valid, matching,
unexpired confirmation (`tests/test_bug_bounty_submission_controls.py`).
A per-user submission quota (`RATE_LIMIT_BUG_BOUNTY_SUBMIT`, default 5/hour,
shared across both platforms) applies on top of the confirmation gate.

---

## OSINT Engine v5.0 — World-Class Intelligence

The OSINT module (`/api/osint/unified-search`) was rebuilt from a handful of
single-purpose lookups into a parallel, multi-source intelligence engine
modeled on professional tools like Maltego and SpiderFoot: dispatch every
applicable source at once, merge what they find into one record per
real-world entity, and score each one for trust and risk before it ever
reaches a human.

### 8 Integrated Sources

Sources are dispatched automatically based on `target_type` (`domain`,
`email`, `username`, `ip`, or `auto`-detected), and every source runs under
its own independent timeout so one slow or failing source never blocks the
rest of the `asyncio.gather()` batch.

| Source | Target Type | What It Finds | Install |
|--------|:---:|----------------|---------|
| **Amass** | domain | Passive subdomain enumeration aggregating multiple intel APIs | `go install github.com/owasp-amass/amass/v4/...@master` / `apt install amass` |
| **theHarvester** | domain, email, ip | Emails and hosts via free OSINT engines (DuckDuckGo, crt.sh, DNSDumpster, HackerTarget, RapidDNS) | `pip install theHarvester` |
| **Maigret** | username | Username footprint across 500+ social platforms | `pip install maigret` |
| **Holehe** | email | Checks which online services an email is registered with | `pip install holehe` |
| **crt.sh** | domain | Subdomains extracted from public Certificate Transparency logs | none — public API |
| **Wayback Machine** | domain | Historical hostnames pulled from the Internet Archive CDX index | none — public API |
| **DNS Full** | domain | A / AAAA / MX / TXT / NS / SOA records plus explicit SPF / DMARC presence checks | none — `dnspython` |
| **WHOIS** | domain | Registrar, creation/expiry/update dates, name servers, registration status | none — `python-whois` |

Check what's actually runnable in your environment at any time with:

```bash
curl -H "Authorization: Bearer $TOKEN" https://your-instance/api/osint/sources-status
```

```json
{
  "sources": [
    { "source": "amass", "available": true, "requires_api_key": false, "last_used": "2026-06-30T21:14:02+00:00" },
    { "source": "theharvester", "available": true, "requires_api_key": false, "last_used": null },
    { "source": "maigret", "available": false, "requires_api_key": false, "last_used": null },
    { "source": "holehe", "available": true, "requires_api_key": false, "last_used": null },
    { "source": "crtsh", "available": true, "requires_api_key": false, "last_used": "2026-06-30T21:14:02+00:00" },
    { "source": "wayback", "available": true, "requires_api_key": false, "last_used": "2026-06-30T21:14:03+00:00" },
    { "source": "dns_full", "available": true, "requires_api_key": false, "last_used": "2026-06-30T21:14:01+00:00" },
    { "source": "whois", "available": true, "requires_api_key": false, "last_used": "2026-06-30T21:14:04+00:00" }
  ]
}
```

None of the 8 sources require an API key — the subprocess-based tools
(Amass, theHarvester, Maigret, Holehe) run as free/local binaries, and the
direct-API sources (crt.sh, Wayback, DNS, WHOIS) query public endpoints.

### Confidence Scoring Engine (0–100)

Every merged entity gets a trust score from `modules/osint/confidence_engine.py`,
calculated in three steps:

1. **Base score** — the reliability weight of the single most-trusted source
   that reported the entity, calibrated by how the data was obtained:

   | Source | Reliability | Rationale |
   |--------|:---:|-----------|
   | crt.sh | 90 | Cryptographically-anchored — a CA actually issued the cert |
   | DNS Full | 90 | Protocol-level fact — the record actually resolves |
   | WHOIS | 85 | Authoritative registry data |
   | Amass | 80 | Aggregates multiple passive intel APIs itself |
   | theHarvester | 70 | Scrapes search engines — occasional false positives |
   | Holehe | 70 | Probes auth endpoints — occasional false positives |
   | Wayback Machine | 65 | Confirms a URL was *crawled*, not that the host still resolves |
   | Maigret | 60 | Username-matching across 500+ sites has the highest false-positive rate |

2. **Corroboration bonus** — `+15` for every *additional* independent source
   that reports the same entity. A subdomain confirmed by both crt.sh and
   live DNS resolution is far more credible than one seen via a single
   passive source.
3. **Freshness adjustment** — `+5` if the finding's timestamp is under 90
   days old, `-10` if it's over 2 years old, `0` otherwise.

The final score is clamped to `[0, 100]`.

### Correlation & Deduplication Engine

`modules/osint/correlation_engine.py` collapses findings reported by
multiple sources into one record per real-world entity, the same way
Maltego's graph view collapses duplicate nodes pulled in by different
transforms:

- Every finding is keyed by `(type, lowercased value)`.
- The first sighting of a key keeps its fields and starts a `sources` list
  and an `occurrences` counter.
- Every later sighting of the same key appends its source name (if new),
  increments `occurrences`, and backfills any field the merged record
  doesn't already hold a non-empty value for — a richer source's detail
  (e.g. crt.sh's certificate issuer) is never clobbered by a sparser source
  reporting the same entity later.
- `build_entity_graph()` then adds a best-effort `related_to` link per
  entity — an email links to the domain after its `@`; a subdomain links to
  the apex domain it ends with, if that apex also appears in the result set.

### Bilingual Executive Summary

Every search returns a one-line verdict in **both Arabic and English**
(`summary.executive_summary.ar` / `.en`), picking out the single
highest-severity entity found (critical > high > medium > low > info) so a
non-technical reader can skim the headline without reading the full
`entities` list.

### Example Response

```bash
curl -X POST https://your-instance/api/osint/unified-search \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "target_type": "auto"}'
```

```json
{
  "target": "example.com",
  "target_type": "domain",
  "elapsed_seconds": 4.82,
  "summary": {
    "total_findings": 47,
    "unique_entities": 39,
    "severity_breakdown": { "critical": 0, "high": 1, "medium": 3, "low": 33, "info": 2 },
    "executive_summary": {
      "ar": "تم رصد 39 كيان لـ example.com، أبرزها نطاق فرعي بخطورة عالية (legacy.example.com).",
      "en": "Detected 39 entities for example.com; most notably a high-severity subdomain (legacy.example.com)."
    }
  },
  "entities": [
    {
      "type": "subdomain",
      "value": "legacy.example.com",
      "tls": false,
      "sources": ["crtsh", "wayback"],
      "occurrences": 2,
      "confidence": 95,
      "severity": "high",
      "related_to": "example.com"
    },
    {
      "type": "whois_record",
      "value": "example.com",
      "registrar": "RESERVED-Internet Assigned Numbers Authority",
      "creation_date": "1995-08-14T04:00:00",
      "expiration_date": "2027-08-13T04:00:00",
      "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
      "sources": ["whois"],
      "occurrences": 1,
      "confidence": 85,
      "severity": "info",
      "related_to": null
    },
    {
      "type": "spf_status",
      "record_type": "SPF",
      "value": "missing",
      "sources": ["dns_full"],
      "occurrences": 1,
      "confidence": 90,
      "severity": "medium",
      "related_to": null
    }
  ],
  "raw_sources": [
    { "source": "amass", "available": true, "results": [{ "type": "subdomain", "value": "legacy.example.com" }] },
    { "source": "crtsh", "available": true, "results": [{ "type": "subdomain", "value": "legacy.example.com", "issuer": "Let's Encrypt", "not_before": "2026-05-02T10:11:00" }] },
    { "source": "wayback", "available": true, "results": [{ "type": "subdomain", "value": "legacy.example.com", "source_url": "http://legacy.example.com/" }] },
    { "source": "dns_full", "available": true, "results": [{ "type": "spf_status", "record_type": "SPF", "value": "missing" }] },
    { "source": "whois", "available": true, "results": [{ "type": "whois_record", "domain_name": "EXAMPLE.COM", "registrar": "RESERVED-Internet Assigned Numbers Authority" }] },
    { "source": "theharvester", "available": true, "results": [] }
  ]
}
```

### 72 Passing Tests

The engine ships with full unit coverage in `tests/test_unified_osint.py` —
72 tests across target-type detection, the rate limiter, every source
parser, `crt.sh`/Wayback response parsing, `sources-status`, confidence
scoring, severity classification, deduplication/merging, and entity-graph
building:

```bash
pytest tests/test_unified_osint.py -v
# ........................................................................ [100%]
# 72 passed
```

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
│  │       Module Engine (12 delivered · 6 🛠️ in active dev)         │ │
│  │                                                                 │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │ │
│  │  │  recon/  │ │  vuln/   │ │  osint/  │ │  ai / ai_advanced│  │ │
│  │  │ subdom   │ │  xss     │ │  phone   │ │  groq_analyzer   │  │ │
│  │  │ dns      │ │  sqli    │ │  username│ │  behavioral      │  │ │
│  │  │ whois    │ │  ssrf    │ │  geo_ip  │ │  zero_day        │  │ │
│  │  │ nmap     │ │  lfi     │ │  nat_id  │ │  attack_patterns │  │ │
│  │  │ ssl      │ │  redirect│ │  device  │ │  🛠️ autonomous_rt│  │ │
│  │  │ headers  │ └──────────┘ └──────────┘ └──────────────────┘  │ │
│  │  │ ports    │                                                   │ │
│  │  └──────────┘ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │ │
│  │               │bug_bounty│ │🛠️compliance│ threat_intel/   │  │ │
│  │               │hackerone │ │iso_27001 │ │  otx_feed        │  │ │
│  │               │bugcrowd  │ │nist_csf  │ │  🛠️mitre_attack  │  │ │
│  │               │intigriti*│ │pci_dss   │ │  ioc_correlations│  │ │
│  │               │cve_pipe  │ │gdpr/hipaa│ │  🛠️global_feed   │  │ │
│  │               └──────────┘ └──────────┘ └──────────────────┘  │ │
│  │               *browse-only, no submit API                     │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │ │
│  │  │ firewall │ │   vpn/   │ │ 🛠️quantum/│ │  federation/     │  │ │
│  │  │ ai_waf   │ │wireguard │ │ kyber768 │ │  multi_node_scan │  │ │
│  │  │ 🛠️ngfw_v2│ │ peer_mgmt│ │ aes_gcm  │ │  distributed_rt  │  │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘  │ │
│  │                        🛠️ = in active development, see below  │ │
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

    subgraph Modules["Module Engine — delivered"]
        Recon["🔍 Recon<br/>subdomain·dns·nmap·ssl"]
        Vuln["🎯 Vuln Scanner<br/>xss·sqli·ssrf·lfi"]
        OSINT["🕵️ OSINT<br/>phone·username·geo·device"]
        AI["🤖 AI Engine<br/>Groq LLaMA-3.3-70B"]
        BugBounty["💰 Bug Bounty<br/>H1·Bugcrowd (confirm-gated)"]
        ThreatIntel["🌍 Threat Intel<br/>OTX·HIBP·IOC correlation"]
    end

    subgraph Roadmap["🛠️ In active development — not fully launched"]
        Compliance["🛠️ Compliance<br/>ISO27001·NIST·GDPR"]
        AttackNav["🛠️ ATT&CK Navigator"]
        RedTeam["🛠️ Autonomous RT<br/>real recon+webscan, rest simulated"]
        Quantum["🛠️ Quantum Crypto<br/>Kyber-768 PQC, simulated by default"]
        GlobalFeed["🛠️ Global Threat Feed<br/>mostly sample data today"]
    end

    Modules --> DB["🗄️ SQLite / PostgreSQL"]
    Modules --> OTX["AlienVault OTX"]
    Modules --> Groq["Groq API"]
    Modules --> H1["HackerOne API"]
    Modules --> BC["Bugcrowd API"]
```

---

### Content-Security-Policy (CSP)

`style-src` and `script-src` both run with no `unsafe-inline`. Every former
`style="..."` HTML attribute was mechanically extracted into
`web/static/css/inline-extracted.css` as a `class="ie<hash>"` rule with
`!important` on every declaration — `!important` was required to reproduce
inline style's old cascade precedence, since a class alone has lower
specificity than the attribute it replaced.

**Rule: never let an extracted `!important` declaration sit on a property
that JS also assigns via `element.style.<prop>` / `setProperty()`.** The
`!important` class permanently wins over that assignment and the element
freezes on whichever state the class encodes, no matter what the JS does —
this bit the platform once, silently breaking every `showTab()`-style tab
switcher, several modals, and a couple of progress bars/toggle switches
(fixed across 17 templates; see `web/static/css/inline-extracted.css`'s
header comment for the full writeup).

- **`display` toggled by JS** (tabs, modals, show/hide panels): give the
  element `class="is-hidden"` for its initial hidden state (`style.css`)
  instead of a static extracted `display:none` class, and toggle it from JS
  with `window.optisecSetVisible(el, visible, displayValue)`
  (`web/static/js/main.js`) — never `el.style.display = ...` directly.
- **Any other property JS assigns** (`width`, `background`, `left`, …):
  drop `!important` from just that one declaration in the extracted class
  (the plain, non-`!important` rule still sets the correct initial value;
  JS's inline `style.<prop>` assignment then wins the cascade normally on
  top of it), or route the value through `data-dyn-style="..."` +
  `optisecApplyDynStyles()` if it's genuinely data-driven per instance.
- There is no committed generator script for `inline-extracted.css` — the
  extraction was a one-off pass (commit `53a7f60`). Anyone re-running or
  extending it by hand must apply the same rule; see
  `tests/test_style_extraction.py` for the static guard that checks it.

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

| OSINT Engine | IOC Correlations |
|:---:|:---:|
| ![OSINT](docs/screenshots/osint.png) | ![Correlations](docs/screenshots/correlations.png) |

| Global Threat Feed | Attack Patterns |
|:---:|:---:|
| ![Threat Feed](docs/screenshots/threat_feed.png) | ![Attack Patterns](docs/screenshots/attack_patterns.png) |

**MITRE ATT&CK Navigator**

![ATT&CK](docs/screenshots/attack_navigator.png)

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
| **Cryptography** | cryptography (AES-GCM) + Kyber-768 (simulated; real via optional `liboqs`) | ≥ 41.0 |
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
# — or use the bundled startup script, which also handles the venv/deps for you —
./start.sh web

# Dashboard: http://localhost:8000
# API Docs:  http://localhost:8000/docs
# ReDoc:     http://localhost:8000/redoc
# Demo:      http://localhost:8000/demo  (one-click demo account)
```

**First-run admin account** is created automatically. The password is never
printed to stdout/logs. Set `FIRST_ADMIN_USER`/`FIRST_ADMIN_PASSWORD` in your
environment to choose it yourself; otherwise a random strong password is
generated and written once to a chmod-600 file at
`/tmp/optisec_initial_creds_admin_<timestamp>.txt` — log in once, then delete
that file. See `SECURITY.md` for details.

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

### Eternal Core — Recon Engine (HIBP Breach Data)

The Eternal Core subsystem (`app/`, TimescaleDB + MinIO hybrid storage, its own
`.env.eternal` file — see [Docker Compose](#docker-compose) above) resolves
`POST /scan` email lookups against the real [HaveIBeenPwned](https://haveibeenpwned.com)
v3 API via `app/services/external/hibp_service.py`.

1. Get an API key at **https://haveibeenpwned.com/API/Key**. Note that HIBP
   removed its free tier in 2019 — a paid subscription (billed monthly,
   cheapest tier is a few dollars/month) is required for the
   `breachedaccount` endpoint used here.
2. Add it to `.env.eternal` (already git-ignored, never committed):
   ```
   HIBP_API_KEY=your_hibp_key_here
   ```
3. If the key is missing, invalid, or HIBP is unreachable, `scan_email`
   automatically falls back to mock breach data and records a warning in
   `audit_logs` (`action` ending in `:hibp_fallback_warning`) so the fallback
   is visible in the audit trail. The scan response's `result.source` field
   is always `"HIBP"` or `"mock_fallback"` so callers know which one they got.

Only breach names, titles, and dates are ever persisted to `recon_artifacts`
— no passwords, hashes, or other leaked personal data.

### Deploy to Render

One-click deployment on [Render.com](https://render.com):

1. Fork this repository
2. Create a new **Web Service** on Render pointing to your fork
3. Set the following environment variables in Render dashboard:

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | ✅ | Random string ≥ 32 characters |
| `DATABASE_URL` | ✅ | Render PostgreSQL URL (`postgresql+asyncpg://...`) |
| `FIRST_ADMIN_PASSWORD` | ✅ | Initial admin password — set this yourself; if omitted, a random one is generated and written once to a local file (see [SECURITY.md](SECURITY.md)), never to logs |
| `DEMO_INITIAL_PASSWORD` | Optional | Initial demo account password; the "Try Demo" button bypasses this entirely |
| `GROQ_API_KEY` | Optional | Enables AI analysis features |
| `OTX_API_KEY` | Optional | AlienVault OTX threat feed |
| `HACKERONE_API_TOKEN` | Optional | HackerOne integration |
| `BUGCROWD_API_TOKEN` | Optional | Bugcrowd integration |
| `DARKWEB_SCAN_INTERVAL_HOURS` | Optional | Dark web monitoring re-scan interval, default `24` |

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

OPTISEC exposes **201 REST + WebSocket endpoints** across 29 API groups, all fully typed with Pydantic v2 schemas and documented in the live OpenAPI 3.0 spec. Interactive API documentation is available at runtime:

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
| Compliance Checker 🛠️ | ❌ | ✅ | ✅ |
| Behavioral UEBA | ❌ | ✅ | ✅ |
| Zero-Day Prediction | ❌ | ✅ | ✅ |
| Attack Patterns | ❌ | ✅ | ✅ |
| AI Firewall + NGFW 🛠️ | ❌ | ✅ | ✅ |
| WireGuard VPN | ❌ | ✅ | ✅ |
| Quantum Crypto (PQC) 🛠️ | ❌ | ✅ | ✅ |
| REST API Access | ❌ | ✅ | ✅ |
| Autonomous Red Team 🛠️ | ❌ | ❌ | ✅ |
| MITRE ATT&CK Navigator 🛠️ | ❌ | ❌ | ✅ |
| Global Threat Feed 🛠️ | ❌ | ❌ | ✅ |
| IOC Correlations | ❌ | ❌ | ✅ |
| Federated Scanning | ❌ | ❌ | ✅ |
| User Management | ❌ | ❌ | ✅ |
| Multi-node Deployment | ❌ | ❌ | ✅ |

🛠️ = the license gate itself is real and enforced, but the underlying module
is still in active development — see [In Active
Development](#-in-active-development--built-not-yet-fully-launched) for
exactly what each one does and doesn't do today. The NGFW half of "AI
Firewall + NGFW" is the 🛠️ part; the AI Firewall (WAF) half is fully delivered.

### Activate a License

```bash
# Via web dashboard: Settings → License → Enter Key
# Via API (admin only):
curl -X POST https://your-instance/api/license/activate \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "OPTISEC-PRO-XXXX-XXXX-XXXX"}'
```

> **Purchase a license:** [optisecdev.github.io/optisec-store](https://optisecdev.github.io/optisec-store) · **Contact:** [ahssanali84.syber@gmail.com](mailto:ahssanali84.syber@gmail.com) for PRO/ENTERPRISE inquiries.

---

## Ethical Use Policy

OPTISEC's OSINT, vulnerability scanning, and autonomous red team modules are
**dual-use security tools**. They are built for defenders and authorized
researchers, not for surveilling people. The standard below follows the
same authorization-first posture as the [OWASP Testing
Guide](https://owasp.org/www-project-web-security-testing-guide/) and the
**PTES** (Penetration Testing Execution Standard): no scan, lookup, or
correlation against a target is legitimate without documented authorization
over that target.

### ✅ Permitted Use

| Use Case | Requirement |
|----------|-------------|
| **Penetration testing** | Written authorization (engagement letter / rules of engagement) scoped to the exact assets being tested |
| **Bug bounty hunting** | Target is in-scope per the program's published policy (HackerOne / Bugcrowd / Intigriti scope rules) |
| **SOC / threat intel operations** | Investigating assets, infrastructure, or IOCs your organization owns or is contractually responsible for defending |
| **Security research & education** | Self-owned lab environments, CTF infrastructure, or domains/accounts you personally control |

### ⛔ Prohibited Use

| Use Case | Why It's Prohibited |
|----------|----------------------|
| **Profiling individuals without consent** | Running username/phone/email/national-ID/vehicle-plate OSINT modules against a private person who has not authorized the search is stalking-adjacent and may violate harassment and privacy statutes regardless of intent |
| **Unlawful private-data collection** | Aggregating PII beyond what a target has knowingly made public, or combining sources to deanonymize someone, violates data-protection law (GDPR, CCPA, and local equivalents) even when each individual data point is technically public |
| **Out-of-scope or unauthorized targets** | Scanning any domain, IP range, account, or person not explicitly covered by your authorization — including "adjacent" infrastructure discovered mid-engagement — without first getting written sign-off to expand scope |
| **Mass / indiscriminate targeting** | Bulk-running OSINT or vulnerability modules across targets with no individual authorization, including speculative "see what turns up" sweeps |

### Enforcement

- Authorization is the user's sole responsibility — OPTISEC does not, and
  cannot, verify that a given target/scan is authorized.
- Misuse of OSINT or scanning modules against unauthorized targets may
  violate computer-crime law (e.g. the U.S. CFAA, EU Cybercrime
  Directive, or local equivalents) independent of any OPTISEC license
  terms, and is the operator's personal legal liability.
- License access may be revoked for credible reports of unauthorized or
  abusive use; see [Responsible Disclosure](#responsible-disclosure) below
  to report misuse you become aware of.

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

> Modules already in the codebase but not yet promoted to "delivered" —
> MITRE ATT&CK Navigator, Autonomous Red Team, Quantum-Safe Crypto,
> Compliance Checker, NGFW v2, and Global Threat Feed — are tracked in
> [🛠️ In Active Development](#-in-active-development--built-not-yet-fully-launched)
> above, alongside exactly what each one does and doesn't do today. The
> items below are the next tier out: not started yet.

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
> Platform-wide milestone — independent of the [OSINT Engine v5.0](#osint-engine-v50--world-class-intelligence), which already shipped as a module-level upgrade.
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
