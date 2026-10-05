# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-10-05

First tagged pre-launch release. Highlights summarized from the git history.

### Added

- Same-origin crawler for the vulnerability scanner.
- Real post-quantum cryptography via liboqs: key generation, KEM, hybrid
  mode, and sign/verify.
- Unified OSINT Engine v5.0 (Amass, theHarvester, Maigret, Holehe wrappers),
  passive sources (crt.sh, Wayback, DNS, WHOIS, VirusTotal, AbuseIPDB,
  SecurityTrails, URLScan, and more), confidence and correlation engines.
- OSINT Network Intelligence, Dark Web Intelligence, Vulnerability
  Intelligence (NVD + EPSS + CISA KEV + ExploitDB), and AI Threat Narrative.
- Dark Web Monitoring module with a periodic scheduler.
- Isolated SSH/FTP/HTTP-admin honeypot module.
- Opt-in, PII-safe real-time threat sharing.
- CVE Submission Pipeline as a drafting-only assistant.
- IOC detection engine backed by the database, with AlienVault OTX sync,
  scan correlation, and an URLhaus feed.
- AI triage engine in the scan pipeline, with Groq TPM/TPD rate limiting.
- WAF-aware classification for XSS, SQLi, LFI, SSRF, and Open Redirect
  findings.
- MITRE ATT&CK (T1190) mapping of scanner-confirmed findings.
- GraphQL vulnerability probe.
- Eternal Core recon engine (TimescaleDB, MinIO) with real HIBP breach data.
- Per-user subscription and license-key redemption, and automated
  NOWPayments crypto checkout with SMTP license delivery.
- Scan watchdog that auto-fails orphaned running/pending scans.

### Changed

- Relicensed from proprietary to the GNU AGPL-3.0, with a NOTICE file and
  a CONTRIBUTING.md that includes a dual-licensing contributor agreement.
- MITRE ATT&CK Navigator now uses real MITRE ATT&CK data; NGFW uses real
  geolocation data.
- Threat Feed now uses real OTX and geolocation data; fabricated campaigns
  and confidence values removed.
- Simulated and sample data (red team findings, threat feed samples, attack
  chains, dark web mock surface, demo traffic) is explicitly labeled and
  excluded from scores, counters, and compliance results.
- OSINT: fabricated National ID / Truecaller results removed; Cell Tower and
  Device results labeled honestly.
- AI Red Team plans are labeled by provenance (AI vs. template).
- Admin Auth Log moved from a local file to a durable database table.
- Docker base image pinned by digest, with BuildKit cache mounts.
- Content-hash cache-busting for all local CSS/JS.
- Groq model switched to `openai/gpt-oss-120b`, with JSON mode and retries.
- Session idle timeout raised to 24h with a frontend heartbeat.
- Uvicorn workers reduced to 1 and `VULN_SCAN_CONCURRENCY` to 4 for
  stability on small instances.

### Fixed

- XSS findings are only marked CONFIRMED after verifying an executable
  context; false-positive fragment matching removed.
- Subdomain enumeration verifies a live host before counting a DNS hit.
- OSINT scans no longer hang past the per-module timeout.
- CVE Pipeline surfaces real errors; 402 responses render an HTML upgrade
  page.
- VPN: server keypair is generated lazily and the Endpoint port is
  normalized; WireGuard fallback uses valid X25519 keys.
- NLP command input: silent failures removed, explicit 400 responses.
- Double-issuance race in the NOWPayments webhook.
- Neon Postgres connectivity (SSL, PgBouncer statement cache, cold starts).

### Security

- License secret hardened: `OPTISEC_LICENSE_SECRET` fails closed in
  production, and the legacy public-default verification path is removed,
  so forged keys are rejected.
- Module-by-module security audit (7-10 September 2026): per-user scoping
  (IDOR) fixes, stored-XSS escaping (honeypot, attack navigator, threat
  feed), SSRF guards (compliance probe, OSINT network scan, targets), rate
  limits and input caps on sensitive endpoints, atomic license-key
  redemption, and removal of secret leaks (federation node API keys, raw
  external-API errors).
- IDOR fixes for reports, Autonomous Red Team, and AI Red Team resources.
- Content-Security-Policy without `unsafe-inline`, plus HSTS, X-Frame-Options,
  COOP/CORP/COEP, Permissions-Policy, and SRI on CDN assets.
- Bug bounty submissions gated behind a preview step and an HMAC
  confirmation token.
- License-tier gate enforced on every PRO/ENTERPRISE API endpoint;
  admin-only access restored on instance-wide `/license` routes.
- Initial admin/demo passwords are no longer logged in plaintext.
- Authenticated WebSocket scan channel, trust-aware client IP resolution,
  hashed API keys, CSRF protection, Secure session cookie, open-redirect
  fix (CWE-601), and `defusedxml` for nmap output.
- WireGuard private keys and PSKs are no longer returned by peer-listing
  endpoints.
- Eternal Core: admin auth and rate limiting on scan endpoints, CORS fix,
  fail-fast on a missing field-encryption key.
- Dependency updates for known CVEs (Pillow, cryptography).

[Unreleased]: https://github.com/OptisecDev/optisec-recon-pro/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/OptisecDev/optisec-recon-pro/releases/tag/v0.9.0
