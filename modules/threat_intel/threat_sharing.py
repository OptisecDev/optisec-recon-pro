"""
Threat Sharing — export locally-discovered *technical* IOCs and optionally
share a single one with the AlienVault OTX community.

SECURITY / PRIVACY NOTICE
-------------------------
This module deliberately only ever collects/handles *technical* indicators
— IPs, domains, file hashes, CVEs, URLs. It never touches customer identity
or scan-result data:

  - `collect_honeypot_iocs()` reads only attacker source IPs from
    HoneypotEvent — infrastructure that attacked *us*, not customer data.
  - `collect_darkweb_iocs()` reads only the already-public paste/GitHub
    locator URL from a DarkWebAlert's `detail` JSON — it never reads the
    DarkWebMonitor's watched domain/email (the customer's identity), which
    is intentionally left out of the returned dict entirely.
  - `collect_vulnerability_iocs()` sources CVEs from CISA's public KEV
    feed, not from this project's own Finding/Scan tables — so no client's
    scan results are ever exposed.
  - `validate_ioc()` is the last line of defense for the manual share path:
    it rejects anything that isn't a well-formed IP/domain/hash/CVE/URL,
    including anything containing '@' (email-shaped values).

Sharing is opt-in and off by default — see `config.ENABLE_THREAT_SHARING`
(env `ENABLE_THREAT_SHARING`, default `false`). Even when enabled, nothing
is pushed automatically: `share_ioc()` is only ever invoked by the explicit
POST /api/threat-feed/share endpoint, one IOC at a time, triggered by a
logged-in human.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import logging
import re
import uuid
from datetime import datetime
from typing import Any, Optional

import requests
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("threat_intel.threat_sharing")

_OTX_BASE = "https://otx.alienvault.com/api/v1"
_HEADERS_BASE = {
    "User-Agent": "OPTISEC-Platform/4.0 (Security Research)",
    "Accept": "application/json",
}

ALLOWED_IOC_TYPES = frozenset({"ip", "domain", "hash_md5", "hash_sha1", "hash_sha256", "cve", "url"})

_HASH_LENGTHS = {"hash_md5": 32, "hash_sha1": 40, "hash_sha256": 64}
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)

_OTX_INDICATOR_TYPE = {
    "ip": "IPv4",
    "domain": "domain",
    "hash_md5": "FileHash-MD5",
    "hash_sha1": "FileHash-SHA1",
    "hash_sha256": "FileHash-SHA256",
    "cve": "CVE",
    "url": "URL",
}


# ── Validation (the last line of defense against PII/free-text) ───────────

def validate_ioc(ioc_type: str, value: str) -> tuple[bool, str]:
    """Return (valid, error_message). Rejects anything that isn't a strict
    IP/domain/hash/CVE/URL shape — in particular anything containing '@'
    (email-shaped) is always rejected regardless of the declared type."""
    value = (value or "").strip()
    if not value:
        return False, "Empty IOC value"
    if "@" in value:
        return False, "Value looks like an email/identity, not a technical indicator — rejected"
    if ioc_type not in ALLOWED_IOC_TYPES:
        return False, f"Unsupported IOC type: {ioc_type}"

    if ioc_type == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False, "Invalid IP address"
        return True, ""

    if ioc_type == "domain":
        if not _DOMAIN_RE.match(value):
            return False, "Invalid domain format"
        return True, ""

    if ioc_type in _HASH_LENGTHS:
        expected_len = _HASH_LENGTHS[ioc_type]
        if not re.match(rf"^[a-fA-F0-9]{{{expected_len}}}$", value):
            return False, f"Invalid {ioc_type} hash format (expected {expected_len} hex chars)"
        return True, ""

    if ioc_type == "cve":
        if not _CVE_RE.match(value):
            return False, "Invalid CVE ID format (expected CVE-YYYY-NNNN)"
        return True, ""

    if ioc_type == "url":
        if not _URL_RE.match(value):
            return False, "Invalid URL format"
        return True, ""

    return False, f"Unsupported IOC type: {ioc_type}"


# ── Local IOC collection ───────────────────────────────────────────────────

async def collect_honeypot_iocs(db: AsyncSession, limit: int = 20) -> list[dict]:
    """Distinct attacker IPs from recent HIGH/CRITICAL honeypot events."""
    from web.models import HoneypotEvent

    stmt = (
        select(HoneypotEvent)
        .where(HoneypotEvent.risk_level.in_(["HIGH", "CRITICAL"]))
        .order_by(HoneypotEvent.created_at.desc())
        .limit(500)
    )
    rows = (await db.execute(stmt)).scalars().all()

    seen: dict[str, dict] = {}
    for e in rows:
        if e.source_ip in seen:
            continue
        seen[e.source_ip] = {
            "type": "ip",
            "value": e.source_ip,
            "source_module": "honeypot",
            "severity": e.risk_level,
            "last_seen": e.created_at.isoformat() if e.created_at else None,
            "context": {"service": e.service, "abuse_score": e.abuse_score, "country": e.country},
        }
        if len(seen) >= limit:
            break
    return list(seen.values())


async def collect_darkweb_iocs(db: AsyncSession, limit: int = 20) -> list[dict]:
    """Only the already-public paste/GitHub locator URL from recent alerts
    — the monitored domain/email (the customer's identity) is never read
    or returned here."""
    from web.models import DarkWebAlert

    stmt = (
        select(DarkWebAlert)
        .where(DarkWebAlert.source.in_(["paste", "github_secret"]))
        .order_by(DarkWebAlert.discovered_at.desc())
        .limit(200)
    )
    rows = (await db.execute(stmt)).scalars().all()

    out: list[dict] = []
    for a in rows:
        detail = a.detail or {}
        url = detail.get("url") or detail.get("html_url")
        if not url:
            continue
        out.append({
            "type": "url",
            "value": url,
            "source_module": "darkweb",
            "severity": a.severity,
            "last_seen": a.discovered_at.isoformat() if a.discovered_at else None,
            "context": {"source": a.source},
        })
        if len(out) >= limit:
            break
    return out


async def collect_vulnerability_iocs(limit: int = 20) -> list[dict]:
    """Recently-added CVEs from CISA's public Known Exploited
    Vulnerabilities catalog — deliberately not sourced from this project's
    own Finding/Scan tables, so no client scan result is ever exposed."""
    from modules.osint.vulnerability_intelligence import _query_cisa_kev

    kev = await _query_cisa_kev()
    vulns = kev.get("vulnerabilities") or []
    vulns_sorted = sorted(vulns, key=lambda v: v.get("date_added") or "", reverse=True)

    out: list[dict] = []
    for v in vulns_sorted[:limit]:
        cve_id = v.get("cve_id")
        if not cve_id:
            continue
        out.append({
            "type": "cve",
            "value": cve_id,
            "source_module": "vulnerability_intel",
            "severity": "CRITICAL" if v.get("known_ransomware_use") == "Known" else "HIGH",
            "last_seen": v.get("date_added"),
            "context": {"vendor": v.get("vendor_project"), "product": v.get("product")},
        })
    return out


async def collect_local_iocs(db: AsyncSession, per_source_limit: int = 20) -> list[dict]:
    """Merge honeypot + dark web + vulnerability-intel candidates into one
    list of technical IOCs eligible for export/sharing."""
    honeypot = await collect_honeypot_iocs(db, per_source_limit)
    darkweb = await collect_darkweb_iocs(db, per_source_limit)
    vuln = await collect_vulnerability_iocs(per_source_limit)

    all_iocs = honeypot + darkweb + vuln
    for ioc in all_iocs:
        ioc["id"] = hashlib.md5(f"{ioc['type']}:{ioc['value']}".encode()).hexdigest()[:12]
    return all_iocs


# ── Export (STIX-shaped JSON / CSV / plain JSON) ───────────────────────────

def _stix_pattern(ioc_type: str, value: str) -> Optional[str]:
    escaped = value.replace("'", "\\'")
    if ioc_type == "ip":
        return f"[ipv4-addr:value = '{escaped}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{escaped}']"
    if ioc_type == "url":
        return f"[url:value = '{escaped}']"
    if ioc_type == "hash_md5":
        return f"[file:hashes.MD5 = '{escaped}']"
    if ioc_type == "hash_sha1":
        return f"[file:hashes.'SHA-1' = '{escaped}']"
    if ioc_type == "hash_sha256":
        return f"[file:hashes.'SHA-256' = '{escaped}']"
    if ioc_type == "cve":
        return f"[vulnerability:name = '{escaped}']"
    return None


def build_stix_bundle(iocs: list[dict]) -> dict:
    """A minimal, dependency-free STIX 2.1-shaped bundle — this project has
    no `stix2`/`taxii2-client` dependency, so this hand-builds just the
    `indicator` SDO fields a STIX/TAXII-compatible consumer needs, without
    pulling in the full SDK for a handful of fields."""
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []
    for ioc in iocs:
        pattern = _stix_pattern(ioc.get("type", ""), ioc.get("value", ""))
        if not pattern:
            continue
        ioc_id = ioc.get("id") or hashlib.md5(f"{ioc.get('type')}:{ioc.get('value')}".encode()).hexdigest()[:12]
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, ioc_id)}",
            "created": now,
            "modified": now,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "labels": [ioc.get("source_module", "unknown")],
            "confidence": 70,
        })
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def build_csv(iocs: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "source_module", "severity", "last_seen"])
    for ioc in iocs:
        writer.writerow([
            ioc.get("type", ""), ioc.get("value", ""), ioc.get("source_module", ""),
            ioc.get("severity", ""), ioc.get("last_seen", ""),
        ])
    return buf.getvalue()


# ── Outbound sharing (AlienVault OTX) ──────────────────────────────────────

def _headers(api_key: str) -> dict:
    return {**_HEADERS_BASE, "X-OTX-API-KEY": api_key}


def share_ioc_to_otx(api_key: str, ioc_type: str, value: str, *, tlp: str = "AMBER", description: str = "") -> dict:
    """Create a single-indicator OTX pulse. Never raises — network/HTTP
    errors are captured in the return dict."""
    otx_type = _OTX_INDICATOR_TYPE.get(ioc_type)
    if not otx_type:
        return {"success": False, "error": f"Unsupported IOC type for OTX: {ioc_type}"}

    payload = {
        "name": f"OPTISEC Community Share — {ioc_type}:{value[:60]}",
        "description": description or "Shared via OPTISEC Recon Pro Threat Sharing module.",
        "public": True,
        "TLP": tlp.upper(),
        "indicators": [{"indicator": value, "type": otx_type}],
    }
    try:
        resp = requests.post(f"{_OTX_BASE}/pulses/create", json=payload, headers=_headers(api_key), timeout=20)
        resp.raise_for_status()
        data = resp.json()
        pulse_id = data.get("id")
        return {
            "success": True,
            "pulse_id": pulse_id,
            "pulse_url": f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else None,
        }
    except requests.exceptions.RequestException as exc:
        logger.warning("OTX pulse creation failed: %s", exc)
        return {"success": False, "error": str(exc)}


async def share_ioc(
    *, ioc_type: str, value: str, source_module: str = "manual",
    severity: str = "MEDIUM", tlp: str = "AMBER", description: str = "",
    enabled: Optional[bool] = None, api_key: Optional[str] = None,
) -> dict:
    """The single entry point for an explicit, human-triggered share
    action. Always returns a result dict describing what happened; never
    raises. `enabled`/`api_key` default to config.ENABLE_THREAT_SHARING /
    config.OTX_API_KEY but can be overridden (used by tests)."""
    import asyncio as _asyncio

    if enabled is None:
        from config import ENABLE_THREAT_SHARING as enabled
    if api_key is None:
        from config import OTX_API_KEY as api_key

    if not enabled:
        return {
            "status": "disabled",
            "message_en": "Threat sharing is disabled — set ENABLE_THREAT_SHARING=true in .env to enable it.",
            "message_ar": "مشاركة التهديدات معطّلة — فعّلها عبر ENABLE_THREAT_SHARING=true في ملف .env",
        }

    valid, err = validate_ioc(ioc_type, value)
    if not valid:
        return {"status": "invalid", "message_en": err, "message_ar": f"مؤشر غير صالح للمشاركة: {err}"}

    if not api_key:
        return {
            "status": "failed",
            "message_en": "OTX_API_KEY is not configured.",
            "message_ar": "لم يتم إعداد OTX_API_KEY — لا يمكن المشاركة.",
        }

    result = await _asyncio.to_thread(share_ioc_to_otx, api_key, ioc_type, value, tlp=tlp, description=description)
    if result.get("success"):
        return {
            "status": "success",
            "message_en": "IOC shared with the AlienVault OTX community.",
            "message_ar": "تمت مشاركة المؤشر مع مجتمع AlienVault OTX.",
            "pulse_id": result.get("pulse_id"),
            "pulse_url": result.get("pulse_url"),
        }
    return {
        "status": "failed",
        "message_en": f"Sharing failed: {result.get('error')}",
        "message_ar": f"فشلت المشاركة: {result.get('error')}",
    }
