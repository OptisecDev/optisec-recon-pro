"""
Unified OSINT Engine v5.0
Parallel subprocess wrappers for Amass, theHarvester, Maigret, Holehe,
plus direct-API passive sources (crt.sh, Wayback Machine, DNS, WHOIS).

External tool installation notes:
  - Amass   : Go binary — `go install github.com/owasp-amass/amass/v4/...@master`
               or `apt install amass` / `brew install amass`
  - theHarvester : `pip install theHarvester` or `pipx install theHarvester`
  - Maigret  : `pip install maigret`
  - Holehe   : `pip install holehe`
  - crt.sh, Wayback, DNS, WHOIS : no external binary — pure Python (aiohttp,
    dnspython, python-whois), always "available".
"""

import asyncio
import json
import logging
import os
import re
import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
import dns.asyncresolver
import whois as _pythonwhois

logger = logging.getLogger("osint.unified")

# ── Per-tool timeouts (seconds) ───────────────────────────────────────────────
_TOOL_TIMEOUTS: dict[str, int] = {
    # amass v5 passive enum takes 10-15 min on large domains — not suited
    # for inline API calls. Kept for completeness; timeout acts as hard cap.
    "amass":       120,
    "theharvester":  60,
    "maigret":      120,
    "holehe":        45,
    "crtsh":         20,
    "wayback":       25,
    "dns_full":      15,
    "whois":         15,
    "network_intel": 25,
    "darkweb_intel": 30,
    # Free-tier direct-API sources (VirusTotal/AbuseIPDB/FullHunt/LeakCheck/
    # SecurityTrails/URLScan/Google Safe Browsing) — single HTTP round trips,
    # kept short so a slow/rate-limited provider never blocks the others.
    "virustotal": 15,
    "abuseipdb": 15,
    "fullhunt": 20,
    "leakcheck": 15,
}

# ── Free-tier direct-API source keys (all optional) ───────────────────────────
# Each source below degrades to available=False with a clear "requires API
# key" message when its key is unset — never raises, never silently no-ops.
VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
FULLHUNT_API_KEY = os.environ.get("FULLHUNT_API_KEY", "")
# LeakCheck works keyless via its public endpoint; LEAKCHECK_API_KEY only
# upgrades to the richer authenticated v2 endpoint.
LEAKCHECK_API_KEY = os.environ.get("LEAKCHECK_API_KEY", "")

_FREE_SOURCE_USER_AGENT = "OPTISEC-Recon-Pro-FreeIntel/1.0"


# ── Binary resolution: system PATH + venv bin + ~/bin ────────────────────────
# - pip tools (maigret, holehe, theHarvester) live in the venv bin dir
# - Go/system binaries (amass) may live in ~/bin which isn't always in PATH
_VENV_BIN  = Path(sys.executable).parent
_USER_BIN  = Path.home() / "bin"
_EXTRA_DIRS = [_VENV_BIN, _USER_BIN]


def _find_binary(name: str) -> str | None:
    """Return full path to binary: system PATH → venv bin → ~/bin."""
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_DIRS:
        p = d / name
        if p.is_file():
            return str(p)
    return None


# ── Source usage tracking (for /api/osint/sources-status) ────────────────────
_last_used: dict[str, float] = {}
# None of these sources need an API key: amass/theHarvester/maigret/holehe
# run as free/local tools, and crt.sh/Wayback/DNS/WHOIS are public APIs.
_SOURCE_REQUIRES_API_KEY: dict[str, bool] = {
    "amass": False,
    "theharvester": False,
    "maigret": False,
    "holehe": False,
    "crtsh": False,
    "wayback": False,
    "dns_full": False,
    "whois": False,
    # Works keyless (Shodan InternetDB + BGPView/RIPEstat + raw TLS
    # handshake) — SHODAN_API_KEY/CENSYS_* only enrich results, never gate
    # whether the source runs at all.
    "network_intel": False,
    # Works keyless too (psbdmp.ws + GitHub Code Search are free) — the
    # HIBP/IntelX/BreachDirectory/Leak-Lookup/OTX sources it also queries
    # each degrade individually to available=False without their own key.
    "darkweb_intel": False,
}
# Binary name to probe for each subprocess-based source (case differs from
# its `source` label, e.g. theHarvester's binary is camelCased).
_SOURCE_BINARY_NAME: dict[str, str] = {
    "amass": "amass",
    "theharvester": "theHarvester",
    "maigret": "maigret",
    "holehe": "holehe",
}


def _mark_used(name: str) -> None:
    _last_used[name] = time.time()


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    import datetime
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()


def get_sources_status() -> list[dict]:
    """
    Report every OSINT source's availability, API-key requirement, and last
    invocation time.

    Subprocess-based sources (amass/theHarvester/maigret/holehe) are
    "available" only if their binary is found on PATH/venv/~/bin — the same
    resolution _run_tool() itself uses, so this reflects the same truth the
    next real search would. Direct-API sources (crt.sh/Wayback/DNS/WHOIS)
    have no external binary dependency, so they're always available.
    """
    statuses: list[dict] = []
    for name, binary_name in _SOURCE_BINARY_NAME.items():
        statuses.append({
            "source": name,
            "available": _find_binary(binary_name) is not None,
            "requires_api_key": _SOURCE_REQUIRES_API_KEY.get(name, False),
            "last_used": _iso(_last_used.get(name)),
        })
    for name in ("crtsh", "wayback", "dns_full", "whois", "network_intel", "darkweb_intel"):
        statuses.append({
            "source": name,
            "available": True,
            "requires_api_key": _SOURCE_REQUIRES_API_KEY.get(name, False),
            "last_used": _iso(_last_used.get(name)),
        })
    return statuses


# ── Simple in-memory rate limiter ─────────────────────────────────────────────
_rate_store: dict[str, list[float]] = defaultdict(list)
_RATE_WINDOW = 60   # seconds
_RATE_MAX    = 10   # max requests per window per key


def _check_rate(key: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.monotonic()
    hits = [t for t in _rate_store[key] if now - t < _RATE_WINDOW]
    _rate_store[key] = hits
    if len(hits) >= _RATE_MAX:
        return False
    hits.append(now)
    return True


# ── Target-type auto-detection ────────────────────────────────────────────────
_RE_IP     = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_EMAIL  = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def detect_target_type(target: str) -> str:
    """Infer target type from its format."""
    t = target.strip()
    if _RE_IP.match(t):
        return "ip"
    if _RE_EMAIL.match(t):
        return "email"
    if _RE_DOMAIN.match(t):
        return "domain"
    return "username"


# ── Generic async subprocess runner ──────────────────────────────────────────

async def _run_tool(
    name: str,
    cmd: list[str],
    timeout: int,
    parse_fn,
) -> dict[str, Any]:
    """
    Run an external command, capture stdout/stderr, parse output.
    Never raises — errors are captured in the returned dict.
    """
    _mark_used(name.lower())
    binary = _find_binary(cmd[0])
    if not binary:
        logger.debug("[%s] binary not found: %s", name, cmd[0])
        return {
            "source": name,
            "available": False,
            "error": f"{cmd[0]} not installed or not in PATH/venv",
            "results": [],
        }
    cmd = [binary] + cmd[1:]

    logger.info("[%s] running: %s", name, " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
            logger.warning("[%s] timed out after %ds", name, timeout)
            return {
                "source": name,
                "available": True,
                "error": f"timed out after {timeout}s",
                "results": [],
            }

        out = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        if proc.returncode not in (0, 1, None):
            logger.warning("[%s] exit code %d: %s", name, proc.returncode, err[:300])

        parsed = parse_fn(out)
        logger.info("[%s] parsed %d results", name, len(parsed))
        return {
            "source": name,
            "available": True,
            "results": parsed,
            "stderr": (err[:500] if err.strip() else None),
        }

    except Exception as exc:
        logger.error("[%s] unexpected error: %s", name, exc)
        return {
            "source": name,
            "available": True,
            "error": str(exc),
            "results": [],
        }


async def _run_async_source(name: str, coro, timeout: int) -> dict[str, Any]:
    """
    Run an in-process async OSINT source (HTTP API call or library call,
    as opposed to an external subprocess) under a hard timeout.

    Mirrors _run_tool's contract so every source — subprocess-based or
    not — returns the same {source, available, results, error?} shape and
    a slow/failing source never blocks the others in asyncio.gather().
    """
    _mark_used(name)
    try:
        results = await asyncio.wait_for(coro, timeout=timeout)
        logger.info("[%s] parsed %d results", name, len(results))
        return {"source": name, "available": True, "results": results}
    except asyncio.TimeoutError:
        logger.warning("[%s] timed out after %ds", name, timeout)
        return {
            "source": name,
            "available": True,
            "error": f"timed out after {timeout}s",
            "results": [],
        }
    except Exception as exc:
        logger.error("[%s] unexpected error: %s", name, exc)
        return {"source": name, "available": True, "error": str(exc), "results": []}


# ── crt.sh (Certificate Transparency) ────────────────────────────────────────
# No installation required — queries the public crt.sh JSON API directly.

def _parse_crtsh_json(text: str, domain: str) -> list[dict]:
    """
    Parse crt.sh's JSON response into subdomain findings.

    Each certificate entry's `name_value` field can hold multiple newline-
    separated SANs (e.g. a single cert covering `foo.example.com` and
    `*.bar.example.com`); every one is extracted, wildcards stripped, and
    only names actually ending in the queried domain are kept.
    """
    try:
        entries = json.loads(text)
    except json.JSONDecodeError:
        return []

    domain_lower = domain.lower()
    seen: set[str] = set()
    results: list[dict] = []
    for entry in entries:
        name_value = entry.get("name_value", "") or ""
        for raw in name_value.split("\n"):
            sub = raw.strip().lower().lstrip("*.")
            if not sub or not sub.endswith(domain_lower) or sub in seen:
                continue
            seen.add(sub)
            results.append({
                "type": "subdomain",
                "value": sub,
                "issuer": entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", ""),
            })
    return results


async def _fetch_crtsh(domain: str) -> list[dict]:
    """
    Query crt.sh for certificates issued for `%.{domain}` and extract every
    subdomain named in those certificates' Subject Alternative Names.

    Certificate Transparency logs are append-only and publicly auditable,
    so this is one of the highest-signal passive subdomain sources: a name
    only appears here if a CA actually issued a certificate for it.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    timeout = aiohttp.ClientTimeout(total=_TOOL_TIMEOUTS["crtsh"])
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            text = await resp.text()
    return _parse_crtsh_json(text, domain)


async def _run_crtsh(domain: str) -> dict:
    return await _run_async_source("crtsh", _fetch_crtsh(domain), _TOOL_TIMEOUTS["crtsh"])


# ── Wayback Machine (CDX API) ────────────────────────────────────────────────
# No installation required — queries the public web.archive.org CDX API.

def _parse_wayback_cdx(text: str) -> list[dict]:
    """
    Parse the Wayback CDX API's JSON-array-of-arrays response into distinct
    subdomain findings.

    Row 0 is always the CDX column header (`["original"]`), not data, and
    is skipped. Output is capped at 300 unique hosts so a domain with a
    huge archive history doesn't balloon the response payload.
    """
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not rows or len(rows) < 2:
        return []

    seen: set[str] = set()
    results: list[dict] = []
    for row in rows[1:]:
        if not row:
            continue
        original_url = row[0]
        host = (urlparse(original_url).hostname or "").lower()
        if not host or host in seen:
            continue
        seen.add(host)
        results.append({"type": "subdomain", "value": host, "source_url": original_url})
        if len(results) >= 300:
            break
    return results


async def _fetch_wayback(domain: str) -> list[dict]:
    """
    Query the Wayback Machine's CDX API for every archived URL ever crawled
    under `*.{domain}` and extract the distinct hostnames.

    This surfaces subdomains and hosts that existed in the past but may no
    longer resolve or serve content — historical attack surface that active
    scanning and DNS-based enumeration both miss entirely.
    """
    url = (
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}"
        "&output=json&fl=original&collapse=urlkey&limit=5000"
    )
    timeout = aiohttp.ClientTimeout(total=_TOOL_TIMEOUTS["wayback"])
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            text = await resp.text()
    return _parse_wayback_cdx(text)


async def _run_wayback(domain: str) -> dict:
    return await _run_async_source("wayback", _fetch_wayback(domain), _TOOL_TIMEOUTS["wayback"])


# ── Full DNS enumeration ──────────────────────────────────────────────────────
# No installation required — uses dnspython's async resolver directly.

_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]


async def _fetch_dns_full(domain: str) -> list[dict]:
    """
    Resolve A/AAAA/MX/NS/TXT/SOA records for `domain`, then separately check
    SPF (inside the apex TXT records) and DMARC (TXT at `_dmarc.{domain}`).

    SPF/DMARC are reported as their own findings rather than raw TXT data
    because their *absence* is itself a security-relevant finding (email
    spoofing exposure) — see classify_severity() in confidence_engine.py.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    results: list[dict] = []
    for rtype in _DNS_RECORD_TYPES:
        try:
            answers = await resolver.resolve(domain, rtype)
            for r in answers:
                results.append({
                    "type": "dns_record",
                    "record_type": rtype,
                    "value": str(r).strip(),
                })
        except Exception:
            continue

    spf_present = any(
        r["record_type"] == "TXT" and "v=spf1" in r["value"].lower()
        for r in results
    )
    results.append({
        "type": "spf_status",
        "record_type": "SPF",
        "value": "present" if spf_present else "missing",
    })

    try:
        dmarc_answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_txt = " ".join(str(r).strip() for r in dmarc_answers)
        results.append({"type": "dmarc_record", "record_type": "DMARC", "value": dmarc_txt})
    except Exception:
        results.append({"type": "dmarc_status", "record_type": "DMARC", "value": "missing"})

    return results


async def _run_dns_full(domain: str) -> dict:
    return await _run_async_source("dns_full", _fetch_dns_full(domain), _TOOL_TIMEOUTS["dns_full"])


# ── WHOIS ─────────────────────────────────────────────────────────────────────
# No installation required — uses python-whois, which is sync, so it runs in
# a worker thread (asyncio.to_thread) rather than blocking the event loop.

def _whois_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value) if value is not None else ""


def _whois_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


async def _fetch_whois(domain: str) -> list[dict]:
    """
    Look up WHOIS registration data for `domain`: registrar, creation/
    expiration/update dates, name servers and registration status.

    Domain age and time-to-expiry are classic OSINT pivots — a domain
    registered days ago is a strong phishing/infra-reuse signal, and one
    expiring soon may be about to lapse and become re-registrable.
    """
    w = await asyncio.to_thread(_pythonwhois.whois, domain)
    record = {
        "type": "whois_record",
        "domain_name": _whois_str(getattr(w, "domain_name", None)),
        "registrar": _whois_str(getattr(w, "registrar", None)),
        "creation_date": _whois_str(getattr(w, "creation_date", None)),
        "expiration_date": _whois_str(getattr(w, "expiration_date", None)),
        "updated_date": _whois_str(getattr(w, "updated_date", None)),
        "name_servers": _whois_list(getattr(w, "name_servers", None)),
        "status": _whois_list(getattr(w, "status", None)),
        "value": domain,
    }
    return [record]


async def _run_whois(domain: str) -> dict:
    return await _run_async_source("whois", _fetch_whois(domain), _TOOL_TIMEOUTS["whois"])


# ── Network Intelligence (Shodan/Censys/BGP/SSL) ──────────────────────────────
# No installation required — modules/osint/network_intelligence.py queries
# free/keyless public APIs (Shodan InternetDB, BGPView/RIPEstat) plus a raw
# TLS handshake against the target itself. Always runs in passive mode here
# (deep_scan=False); active service fingerprinting is reserved for the
# explicit POST /api/osint/network-scan endpoint.

def _network_intel_to_findings(data: dict) -> list[dict]:
    """Reframe gather_network_intelligence()'s output as unified-engine
    findings ({type, value, ...}) so it flows through the same confidence/
    correlation/severity pipeline as every other source."""
    findings: list[dict] = []
    ip = data.get("ip")
    if not ip:
        return findings

    for key in ("shodan", "censys"):
        src = data.get(key) or {}
        if not src.get("available"):
            continue
        for port in src.get("open_ports") or []:
            findings.append({
                "type": "open_port", "value": f"{ip}:{port}",
                "port": port, "source_detail": key,
            })
        for vuln in src.get("vulnerabilities") or []:
            cve_id = vuln.get("cve") if isinstance(vuln, dict) else vuln
            severity = vuln.get("severity") if isinstance(vuln, dict) else "high"
            if cve_id:
                findings.append({
                    "type": "cve", "value": cve_id,
                    "severity": severity, "source_detail": key,
                })

    bgp = data.get("bgp") or {}
    if bgp.get("available") and bgp.get("asn"):
        findings.append({
            "type": "asn", "value": f"AS{bgp['asn']}",
            "asn_name": bgp.get("asn_name"), "country": bgp.get("country"),
        })

    ssl_res = data.get("ssl") or {}
    for issue in ssl_res.get("vulnerabilities") or []:
        findings.append({
            "type": "ssl_issue", "value": issue.get("title"),
            "severity": issue.get("severity"),
        })

    return findings


async def _fetch_network_intel(target: str) -> list[dict]:
    from modules.osint.network_intelligence import gather_network_intelligence
    data = await gather_network_intelligence(target, deep_scan=False)
    return _network_intel_to_findings(data)


async def _run_network_intel(target: str) -> dict:
    return await _run_async_source(
        "network_intel", _fetch_network_intel(target), _TOOL_TIMEOUTS["network_intel"]
    )


# ── Dark Web & Breach Intelligence (HIBP/IntelX/BreachDirectory/...) ─────────
# No installation required — modules/osint/darkweb_intelligence.py queries
# official breach/leak APIs (HIBP, IntelligenceX, BreachDirectory,
# Leak-Lookup, psbdmp.ws, GitHub Code Search, AlienVault OTX). Most sources
# are optional and degrade to available=False without their own key.
# GitHub Code Search is skipped here (include_github=False) to keep this
# general-purpose search fast; it still runs on the dedicated
# POST /api/osint/darkweb-scan endpoint.

def _darkweb_intel_to_findings(data: dict) -> list[dict]:
    """Reframe gather_darkweb_intelligence()'s output as unified-engine
    findings ({type, value, ...}) so it flows through the same confidence/
    correlation/severity pipeline as every other source."""
    findings: list[dict] = []
    for b in data.get("breaches") or []:
        name = b.get("name") or b.get("title")
        if name:
            findings.append({
                "type": "breach", "value": name,
                # A breach is serious either way; verified ones get top severity.
                "severity": "critical" if b.get("verified") else "high",
                "verified": b.get("verified"), "breach_date": b.get("breach_date"),
                "data_classes": b.get("data_classes"),
            })
    for p in data.get("pastes") or []:
        ident = p.get("id") or p.get("url")
        if ident:
            findings.append({"type": "paste", "value": str(ident), "severity": "medium", "date": p.get("date")})
    for actor in data.get("threat_actors") or []:
        findings.append({"type": "threat_actor", "value": actor, "severity": "critical"})
    return findings


async def _fetch_darkweb_intel(target: str) -> list[dict]:
    from modules.osint.darkweb_intelligence import gather_darkweb_intelligence
    data = await gather_darkweb_intelligence(target, include_pastes=True, include_github=False)
    return _darkweb_intel_to_findings(data)


async def _run_darkweb_intel(target: str) -> dict:
    return await _run_async_source(
        "darkweb_intel", _fetch_darkweb_intel(target), _TOOL_TIMEOUTS["darkweb_intel"]
    )


# ── Free-tier direct-API sources (VirusTotal/AbuseIPDB/FullHunt/LeakCheck/
#    SecurityTrails/URLScan/Google Safe Browsing) ─────────────────────────────
# Every source below queries a provider's free tier directly — no external
# binary, no scraping. Keyed sources degrade to available=False with a clear
# message when their key is unset; URLScan and LeakCheck's public endpoint
# work fully keyless.

async def _run_query_source(name: str, coro, to_findings, timeout: int) -> dict[str, Any]:
    """
    Run one of the _query_*() direct-API source functions, convert its raw
    response into unified-engine findings via `to_findings`, and report both
    the findings and the raw response (`detail`) — UI cards and
    sources-status want the structured payload, the confidence/correlation/
    severity pipeline only wants the findings list.

    Mirrors _run_async_source's contract (never raises, hard timeout) but
    additionally honors the source's own `available`/`error` rather than
    always reporting available=True, since these sources can be legitimately
    unavailable (no API key configured).
    """
    _mark_used(name)
    try:
        data = await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("[%s] timed out after %ds", name, timeout)
        return {"source": name, "available": True, "error": f"timed out after {timeout}s", "results": []}
    except Exception as exc:
        logger.error("[%s] unexpected error: %s", name, exc)
        return {"source": name, "available": True, "error": str(exc), "results": []}

    findings = to_findings(data)
    logger.info("[%s] parsed %d results", name, len(findings))
    return {
        "source": name,
        "available": data.get("available", True),
        "results": findings,
        "error": data.get("error"),
        "detail": data,
    }


# ── 1. VirusTotal (free public API v3) ────────────────────────────────────────
# https://docs.virustotal.com/reference/overview — free tier: 500 requests/
# day, 4 requests/minute. Sign up: https://www.virustotal.com/gui/join-us

_VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
_VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def _vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY}


async def _query_virustotal(target: str, target_type: str) -> dict:
    """
    Query VirusTotal's free public API v3 for `target`'s reputation: the
    community vote totals, AV-vendor categories, and the
    last_analysis_stats breakdown (malicious/suspicious/harmless/undetected
    engine counts from VT's most recent scan).

    Returns {source, available, target, reputation, malicious_votes,
    suspicious_votes, categories, last_analysis_stats, error}. Never raises.
    """
    empty = {"source": "virustotal", "target": target, "reputation": None,
              "malicious_votes": None, "suspicious_votes": None,
              "categories": {}, "last_analysis_stats": {}}
    if not VT_API_KEY:
        return {**empty, "available": False, "error": "requires API key (VT_API_KEY, optional)"}

    url = _VT_IP_URL.format(ip=target) if target_type == "ip" else _VT_DOMAIN_URL.format(domain=target)
    timeout = aiohttp.ClientTimeout(total=_TOOL_TIMEOUTS["virustotal"])
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=_vt_headers()) as session:
            async with session.get(url) as resp:
                if resp.status == 404:
                    return {**empty, "available": True, "error": None}
                if resp.status == 401:
                    return {**empty, "available": True, "error": "invalid VirusTotal API key"}
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {**empty, "available": True, "error": str(exc)}

    attrs = ((data or {}).get("data") or {}).get("attributes") or {}
    votes = attrs.get("total_votes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "source": "virustotal", "available": True, "target": target,
        "reputation": attrs.get("reputation"),
        "malicious_votes": votes.get("malicious"),
        "suspicious_votes": stats.get("suspicious"),
        "categories": attrs.get("categories") or {},
        "last_analysis_stats": stats,
        "error": None,
    }


def _virustotal_to_findings(data: dict) -> list[dict]:
    """Surface VT's scan verdict as a single severity-scaled finding —
    skipped entirely when VT has never scanned the target (404/no key)."""
    findings: list[dict] = []
    if not data.get("available") or data.get("error") or not data.get("last_analysis_stats"):
        return findings

    stats = data["last_analysis_stats"]
    malicious = stats.get("malicious") or 0
    suspicious = stats.get("suspicious") or 0
    if malicious >= 3:
        severity = "critical"
    elif malicious > 0:
        severity = "high"
    elif suspicious > 0:
        severity = "medium"
    else:
        severity = "info"

    findings.append({
        "type": "vt_reputation", "value": data.get("target"),
        "severity": severity,
        "reputation": data.get("reputation"),
        "malicious_votes": data.get("malicious_votes"),
        "suspicious_votes": suspicious,
        "categories": data.get("categories"),
        "last_analysis_stats": stats,
    })
    return findings


async def _run_virustotal(target: str, target_type: str) -> dict:
    return await _run_query_source(
        "virustotal", _query_virustotal(target, target_type),
        _virustotal_to_findings, _TOOL_TIMEOUTS["virustotal"],
    )


# ── 2. AbuseIPDB (free tier) ──────────────────────────────────────────────────
# https://docs.abuseipdb.com/ — free tier: 1,000 checks/day.
# Sign up: https://www.abuseipdb.com/register

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def _abuseipdb_headers() -> dict:
    return {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}


async def _query_abuseipdb(ip: str) -> dict:
    """
    Check `ip` against AbuseIPDB's community-reported abuse database.

    Returns {source, available, target, abuse_confidence_score,
    total_reports, last_reported_at, usage_type, isp, country_code, error}.
    Never raises.
    """
    empty = {"source": "abuseipdb", "target": ip, "abuse_confidence_score": None,
              "total_reports": None, "last_reported_at": None,
              "usage_type": None, "isp": None, "country_code": None}
    if not ABUSEIPDB_API_KEY:
        return {**empty, "available": False, "error": "requires API key (ABUSEIPDB_API_KEY, optional)"}

    timeout = aiohttp.ClientTimeout(total=_TOOL_TIMEOUTS["abuseipdb"])
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=_abuseipdb_headers()) as session:
            async with session.get(_ABUSEIPDB_URL, params={"ipAddress": ip, "maxAgeInDays": "90"}) as resp:
                if resp.status == 401:
                    return {**empty, "available": True, "error": "invalid AbuseIPDB API key"}
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {**empty, "available": True, "error": str(exc)}

    d = (data or {}).get("data") or {}
    return {
        "source": "abuseipdb", "available": True, "target": ip,
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "last_reported_at": d.get("lastReportedAt"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "country_code": d.get("countryCode"),
        "error": None,
    }


def _abuseipdb_to_findings(data: dict) -> list[dict]:
    findings: list[dict] = []
    score = data.get("abuse_confidence_score")
    if not data.get("available") or data.get("error") or score is None:
        return findings

    if score >= 75:
        severity = "critical"
    elif score >= 50:
        severity = "high"
    elif score >= 25:
        severity = "medium"
    else:
        severity = "info"

    findings.append({
        "type": "abuse_report", "value": data.get("target"),
        "severity": severity,
        "abuse_confidence_score": score,
        "total_reports": data.get("total_reports"),
        "last_reported_at": data.get("last_reported_at"),
        "usage_type": data.get("usage_type"),
        "isp": data.get("isp"),
        "country_code": data.get("country_code"),
    })
    return findings


async def _run_abuseipdb(ip: str) -> dict:
    return await _run_query_source(
        "abuseipdb", _query_abuseipdb(ip), _abuseipdb_to_findings, _TOOL_TIMEOUTS["abuseipdb"],
    )


# ── 3. FullHunt (free tier) ───────────────────────────────────────────────────
# https://docs.fullhunt.io/ — free tier: limited monthly subdomain lookups.
# Sign up: https://fullhunt.io/auth/register/

_FULLHUNT_SUBDOMAINS_URL = "https://fullhunt.io/api/v1/domain/{domain}/subdomains"


def _fullhunt_headers() -> dict:
    return {"X-API-KEY": FULLHUNT_API_KEY}


async def _query_fullhunt(domain: str) -> dict:
    """
    Enumerate subdomains FullHunt has indexed for `domain`.

    FullHunt's free subdomains endpoint returns a plain hostname list; some
    paid responses instead return per-host objects carrying open ports/
    detected technologies, which are extracted opportunistically when
    present so this never under-reports against a richer plan.

    Returns {source, available, target, subdomains, hosts_count, ports,
    technologies, error}. Never raises.
    """
    empty = {"source": "fullhunt", "target": domain, "subdomains": [],
              "hosts_count": 0, "ports": [], "technologies": []}
    if not FULLHUNT_API_KEY:
        return {**empty, "available": False, "error": "requires API key (FULLHUNT_API_KEY, optional)"}

    url = _FULLHUNT_SUBDOMAINS_URL.format(domain=domain)
    timeout = aiohttp.ClientTimeout(total=_TOOL_TIMEOUTS["fullhunt"])
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=_fullhunt_headers()) as session:
            async with session.get(url) as resp:
                if resp.status == 401:
                    return {**empty, "available": True, "error": "invalid FullHunt API key"}
                if resp.status == 404:
                    return {**empty, "available": True, "error": None}
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {**empty, "available": True, "error": str(exc)}

    hosts_raw = (data or {}).get("hosts") or []
    subdomains: list[str] = []
    ports: set = set()
    technologies: set = set()
    for h in hosts_raw:
        if isinstance(h, dict):
            host = h.get("host") or h.get("subdomain")
            if host:
                subdomains.append(host)
            for p in (h.get("open_ports") or h.get("ports") or []):
                ports.add(p)
            for t in (h.get("technologies") or h.get("tags") or []):
                technologies.add(t)
        elif isinstance(h, str):
            subdomains.append(h)

    return {
        "source": "fullhunt", "available": True, "target": domain,
        "subdomains": subdomains,
        "hosts_count": (data or {}).get("hosts_count", len(subdomains)),
        "ports": sorted(ports), "technologies": sorted(technologies),
        "error": None,
    }


def _fullhunt_to_findings(data: dict) -> list[dict]:
    findings: list[dict] = []
    if not data.get("available") or data.get("error"):
        return findings
    for sub in data.get("subdomains") or []:
        findings.append({"type": "subdomain", "value": sub, "source_detail": "fullhunt"})
    target = data.get("target")
    for port in data.get("ports") or []:
        findings.append({
            "type": "open_port", "value": f"{target}:{port}",
            "port": port, "source_detail": "fullhunt",
        })
    return findings


async def _run_fullhunt(domain: str) -> dict:
    return await _run_query_source(
        "fullhunt", _query_fullhunt(domain), _fullhunt_to_findings, _TOOL_TIMEOUTS["fullhunt"],
    )


# ── 4. LeakCheck ──────────────────────────────────────────────────────────────
# https://leakcheck.io/api — public endpoint is free and keyless;
# LEAKCHECK_API_KEY (optional) upgrades to the richer authenticated v2
# endpoint. Sign up: https://leakcheck.io/register

_LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"
_LEAKCHECK_PRO_URL = "https://leakcheck.io/api/v2/query/{target}"


def _leakcheck_headers() -> dict:
    return {"X-API-Key": LEAKCHECK_API_KEY} if LEAKCHECK_API_KEY else {}


async def _query_leakcheck(target: str) -> dict:
    """
    Check `target` (email/username/domain) against LeakCheck's breach
    index. Always runs — the free public endpoint needs no key; setting
    LEAKCHECK_API_KEY switches to the authenticated v2 endpoint for fuller
    per-source detail.

    Returns {source, available, target, found, sources, fields, error}.
    Never raises.
    """
    empty = {"source": "leakcheck", "target": target, "found": False, "sources": [], "fields": []}
    timeout = aiohttp.ClientTimeout(total=_TOOL_TIMEOUTS["leakcheck"])
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=_leakcheck_headers()) as session:
            if LEAKCHECK_API_KEY:
                async with session.get(_LEAKCHECK_PRO_URL.format(target=target)) as resp:
                    if resp.status == 401:
                        return {**empty, "available": True, "error": "invalid LeakCheck API key"}
                    resp.raise_for_status()
                    data = await resp.json()
            else:
                async with session.get(_LEAKCHECK_PUBLIC_URL, params={"check": target}) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
    except aiohttp.ClientError as exc:
        return {**empty, "available": True, "error": str(exc)}

    if isinstance(data, dict) and data.get("success") is False:
        return {**empty, "available": True, "error": str(data.get("error") or "LeakCheck query failed")}

    found = bool((data or {}).get("found"))
    raw_sources = (data or {}).get("sources") or (data or {}).get("result") or []
    source_names = [s.get("name") if isinstance(s, dict) else str(s) for s in raw_sources]
    fields = (data or {}).get("fields") or []
    return {
        "source": "leakcheck", "available": True, "target": target,
        "found": found, "sources": source_names, "fields": fields, "error": None,
    }


def _leakcheck_to_findings(data: dict) -> list[dict]:
    findings: list[dict] = []
    if not data.get("available") or data.get("error") or not data.get("found"):
        return findings
    findings.append({
        "type": "leak_exposure", "value": data.get("target"),
        "severity": "high",
        "sources": data.get("sources"),
        "fields": data.get("fields"),
    })
    return findings


async def _run_leakcheck(target: str) -> dict:
    return await _run_query_source(
        "leakcheck", _query_leakcheck(target), _leakcheck_to_findings, _TOOL_TIMEOUTS["leakcheck"],
    )


# ── Amass ─────────────────────────────────────────────────────────────────────
# NOTE: Amass is a Go binary — not installable via pip.
# Install: go install github.com/owasp-amass/amass/v4/...@master
# or: apt install amass | brew install amass

def _parse_amass(out: str) -> list[dict]:
    results = []
    seen: set[str] = set()
    for line in out.splitlines():
        sub = line.strip()
        if sub and sub not in seen:
            seen.add(sub)
            results.append({"type": "subdomain", "value": sub})
    return results


async def _run_amass(domain: str) -> dict:
    # amass v5 writes progress bars to stdout — use -oA to write results
    # to a file instead, then read the file after the process exits.
    import tempfile, uuid
    _mark_used("amass")
    out_prefix = f"/tmp/amass_{uuid.uuid4().hex[:8]}"
    binary = _find_binary("amass")
    if not binary:
        return {"source": "amass", "available": False,
                "error": "amass not installed or not in PATH/venv", "results": []}
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "enum", "-d", domain, "-timeout", "1", "-oA", out_prefix,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=_TOOL_TIMEOUTS["amass"])
        except asyncio.TimeoutError:
            try:
                proc.kill(); await proc.communicate()
            except Exception:
                pass
            logger.warning("[amass] timed out after %ds", _TOOL_TIMEOUTS["amass"])

        txt_file = out_prefix + ".txt"
        if Path(txt_file).exists():
            content = Path(txt_file).read_text(errors="replace")
            Path(txt_file).unlink(missing_ok=True)
            results = _parse_amass(content)
            logger.info("[amass] parsed %d subdomains", len(results))
            return {"source": "amass", "available": True, "results": results}
        return {"source": "amass", "available": True,
                "error": "no output file produced", "results": []}
    except Exception as exc:
        logger.error("[amass] error: %s", exc)
        return {"source": "amass", "available": True, "error": str(exc), "results": []}


# ── theHarvester ──────────────────────────────────────────────────────────────
# Install: pip install theHarvester

def _parse_theharvester(out: str) -> list[dict]:
    results = []
    section: str | None = None
    seen: set[str] = set()

    for line in out.splitlines():
        stripped = line.strip()
        low = stripped.lower()

        if "emails found" in low or "email addresses" in low:
            section = "email"
            continue
        if "hosts found" in low or "interesting urls" in low:
            section = "host"
            continue
        if stripped.startswith("[*]") or not stripped:
            section = None
            continue

        if section == "email" and "@" in stripped and stripped not in seen:
            seen.add(stripped)
            results.append({"type": "email", "value": stripped})
        elif section == "host" and "." in stripped and stripped not in seen:
            seen.add(stripped)
            results.append({"type": "host", "value": stripped})

    return results


async def _run_theharvester(target: str, target_type: str) -> dict:
    domain = target.split("@")[-1] if target_type == "email" else target
    # Use only free sources that don't require API keys
    # Free sources that don't require API keys and complete in <30s
    _FREE_SOURCES = "duckduckgo,crtsh,dnsdumpster,hackertarget,rapiddns"
    return await _run_tool(
        "theHarvester",
        ["theHarvester", "-d", domain, "-b", _FREE_SOURCES, "-l", "100"],
        _TOOL_TIMEOUTS["theharvester"],
        _parse_theharvester,
    )


# ── Maigret ───────────────────────────────────────────────────────────────────
# Install: pip install maigret

def _parse_maigret(out: str) -> list[dict]:
    results = []
    seen: set[str] = set()

    # Try JSON first (when -J json flag is used)
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            for site, info in data.items():
                if not isinstance(info, dict):
                    continue
                status = info.get("status", {})
                status_id = (
                    status.get("id") if isinstance(status, dict)
                    else str(status)
                )
                if status_id in ("CLAIMED", "found"):
                    results.append({
                        "type": "profile",
                        "platform": site,
                        "url": info.get("url_user", ""),
                        "status": "found",
                    })
        return results
    except (json.JSONDecodeError, AttributeError):
        pass

    # Text output parser — maigret uses "[+] Platform: URL" format
    # Lines may be prefixed with progress info like "on N: [+] ..."
    for line in out.splitlines():
        if "[+]" not in line:
            continue
        # Strip ANSI codes and progress prefix
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
        clean = re.sub(r"^.*?\[\+\]", "[+]", clean).strip()
        # "[+] Platform: URL"
        m = re.match(r"\[\+\]\s+([^:]+):\s*(https?://\S+)?", clean)
        if m:
            platform = m.group(1).strip()
            url = (m.group(2) or "").strip()
            # Skip maigret status lines that aren't actual platforms
            if not url or "sites database" in platform.lower():
                continue
            key = platform.lower()
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": "profile",
                    "platform": platform,
                    "url": url,
                    "status": "found",
                })
    return results


async def _run_maigret(username: str) -> dict:
    return await _run_tool(
        "maigret",
        # --top-sites 500 limits to 500 most popular sites for speed
        # --no-color avoids ANSI codes in output
        # --no-progressbar keeps stdout clean for parsing
        # --no-recursion: don't chase extracted IDs (avoids cascading searches)
        # --top-sites 100: limit to 100 most popular sites for speed
        ["maigret", username, "--timeout", "10", "--no-color",
         "--no-progressbar", "--no-recursion", "--top-sites", "100"],
        _TOOL_TIMEOUTS["maigret"],
        _parse_maigret,
    )


# ── Holehe ────────────────────────────────────────────────────────────────────
# Install: pip install holehe

def _parse_holehe(out: str) -> list[dict]:
    results = []
    # Try JSON
    try:
        data = json.loads(out)
        if isinstance(data, list):
            for item in data:
                if item.get("exists"):
                    results.append({
                        "type": "account",
                        "platform": item.get("name", ""),
                        "domain": item.get("domain", ""),
                        "status": "registered",
                    })
        return results
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback: text output — holehe uses "[+] domain.com" for found accounts
    # Filter out the legend line: "[+] Email used, [-] Email not used, ..."
    _LEGEND = "email used"
    seen: set[str] = set()
    for line in out.splitlines():
        stripped = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if not (stripped.startswith("[+]") or "✔" in stripped):
            continue
        if _LEGEND in stripped.lower():
            continue
        # Extract domain: "[+] coroflot.com" → "coroflot.com"
        m = re.match(r"[\[✔\+\]]+\s+(.+)", stripped)
        domain = m.group(1).strip() if m else stripped
        if domain and domain not in seen:
            seen.add(domain)
            results.append({
                "type": "account",
                "platform": domain.split(".")[0].capitalize(),
                "domain": domain,
                "status": "registered",
            })
    return results


async def _run_holehe(email: str) -> dict:
    return await _run_tool(
        "holehe",
        ["holehe", email],
        _TOOL_TIMEOUTS["holehe"],
        _parse_holehe,
    )


# ── Unified dispatcher ────────────────────────────────────────────────────────

async def search_unified(
    target: str,
    target_type: str,
    rate_key: str = "global",
) -> dict[str, Any]:
    """
    Run all applicable OSINT tools in parallel for the given target.

    Args:
        target:      The target string (domain, email, username, or IP).
        target_type: One of "domain", "email", "username", "ip", "auto".
        rate_key:    Opaque key for rate-limiting (e.g. "user:42").

    Returns:
        Aggregated JSON dict with per-source results, total count, elapsed time.
    """
    if not _check_rate(rate_key):
        return {
            "error": "rate_limited",
            "message": f"Max {_RATE_MAX} requests per {_RATE_WINDOW}s exceeded",
            "target": target,
        }

    if target_type == "auto":
        target_type = detect_target_type(target)

    logger.info("unified_search start target=%r type=%s key=%s", target, target_type, rate_key)
    t0 = time.monotonic()

    tasks: list[asyncio.coroutines] = []
    labels: list[str] = []

    if target_type == "domain":
        tasks += [
            _run_amass(target),
            _run_theharvester(target, target_type),
            _run_crtsh(target),
            _run_wayback(target),
            _run_dns_full(target),
            _run_whois(target),
            _run_network_intel(target),
            _run_darkweb_intel(target),
        ]
        labels += ["amass", "theharvester", "crtsh", "wayback", "dns_full", "whois", "network_intel", "darkweb_intel"]

    elif target_type == "email":
        tasks += [_run_holehe(target), _run_theharvester(target, target_type), _run_darkweb_intel(target)]
        labels += ["holehe", "theharvester", "darkweb_intel"]

    elif target_type == "username":
        tasks += [_run_maigret(target)]
        labels += ["maigret"]

    elif target_type == "ip":
        tasks += [_run_theharvester(target, target_type), _run_network_intel(target)]
        labels += ["theharvester", "network_intel"]

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    by_source: list[dict] = []
    total = 0
    for label, raw in zip(labels, raw_results):
        if isinstance(raw, Exception):
            entry: dict = {"source": label, "error": str(raw), "results": []}
        else:
            entry = raw
        total += len(entry.get("results") or [])
        by_source.append(entry)

    elapsed = round(time.monotonic() - t0, 2)
    logger.info("unified_search done elapsed=%.2fs total=%d", elapsed, total)

    return {
        "target": target,
        "target_type": target_type,
        "elapsed_seconds": elapsed,
        "total_results": total,
        "sources": by_source,
    }
