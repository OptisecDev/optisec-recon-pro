"""
Dark Web Monitoring — persistent watchlist + new-leak alerting

Turns the one-shot `modules.osint.darkweb_intelligence.gather_darkweb_intelligence()`
scan into a continuous monitor:
  - Adds LeakCheck (https://leakcheck.io/api) as an extra source, reusing the
    same LEAKCHECK_API_KEY/endpoints already integrated in the Account
    Recovery project's unified OSINT engine
    (modules/osint/unified_engine.py) — the public endpoint is keyless and
    always runs; LEAKCHECK_API_KEY upgrades it to the richer v2 endpoint.
  - Normalizes every breach/paste/exposure/threat-actor/leak hit into a
    flat list of fingerprinted "leak events", so a caller (the
    /api/darkweb/monitor router) can diff today's events against
    previously-seen fingerprints and persist only the genuinely new ones
    with a discovery timestamp.
  - Provides Arabic labels/messages for every event, source and exposure
    level so alerts and reports can be rendered bilingually — the same
    `_ar`-suffixed convention used by modules/osint/threat_narrative.py.

Ethical use: only ever queries indicator/account-level lookups against
legal, publicly-documented indexes (HIBP, IntelligenceX, LeakCheck, etc.) —
never raw dark web scraping. See docs/OSINT.md's Ethical Use Policy.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any

import aiohttp

logger = logging.getLogger("darkweb.monitor")

# Same env var / endpoints as modules/osint/unified_engine.py's LeakCheck
# integration (Account Recovery project) — kept in sync deliberately so a
# single LEAKCHECK_API_KEY configures both.
LEAKCHECK_API_KEY = os.environ.get("LEAKCHECK_API_KEY", "")
LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"
LEAKCHECK_PRO_URL = "https://leakcheck.io/api/v2/query/{target}"

_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)
_USER_AGENT = "OPTISEC-Recon-Pro-DarkwebMonitor/1.0"


# ── 1. LeakCheck ────────────────────────────────────────────────────────────

def _leakcheck_headers() -> dict:
    return {"X-API-Key": LEAKCHECK_API_KEY, "User-Agent": _USER_AGENT} if LEAKCHECK_API_KEY else {"User-Agent": _USER_AGENT}


async def _query_leakcheck(target: str) -> dict:
    """
    Check `target` (email/username/domain) against LeakCheck's breach
    index. Always runs — the free public endpoint needs no key; setting
    LEAKCHECK_API_KEY switches to the authenticated v2 endpoint for fuller
    per-source detail.

    Returns {source, available, target, found, sources, fields, error}.
    Never raises.
    """
    empty = {"source": "leakcheck", "available": True, "target": target, "found": False, "sources": [], "fields": []}
    try:
        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT, headers=_leakcheck_headers()) as session:
            if LEAKCHECK_API_KEY:
                async with session.get(LEAKCHECK_PRO_URL.format(target=target)) as resp:
                    if resp.status == 401:
                        return {**empty, "error": "invalid LeakCheck API key"}
                    resp.raise_for_status()
                    data = await resp.json()
            else:
                async with session.get(LEAKCHECK_PUBLIC_URL, params={"check": target}) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
    except aiohttp.ClientError as exc:
        return {**empty, "error": str(exc)}

    if isinstance(data, dict) and data.get("success") is False:
        return {**empty, "error": str(data.get("error") or "LeakCheck query failed")}

    found = bool((data or {}).get("found"))
    raw_sources = (data or {}).get("sources") or (data or {}).get("result") or []
    source_names = [s.get("name") if isinstance(s, dict) else str(s) for s in raw_sources]
    fields = (data or {}).get("fields") or []
    return {"source": "leakcheck", "available": True, "target": target,
            "found": found, "sources": source_names, "fields": fields, "error": None}


# ── 2. Leak event normalization + fingerprinting ────────────────────────────
# Every darkweb_intelligence.py source shape (breach/paste/github_exposure/
# threat_actor) plus LeakCheck is flattened into one common event shape so
# the monitor router can diff/store/localize them uniformly:
#   {fingerprint, source, severity, title, detail}

def _fingerprint(source: str, *parts: str) -> str:
    """Stable dedupe key for a leak event — same source+identifying parts
    always hash to the same fingerprint, so re-checking a target never
    re-alerts on something already stored."""
    raw = "|".join((source, *(p or "" for p in parts)))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def build_leak_events(darkweb_result: dict, leakcheck_result: dict | None) -> list[dict]:
    """
    Flatten a gather_darkweb_intelligence() result and a _query_leakcheck()
    result into a single fingerprinted leak-event list.

    Never raises — every field is read defensively so a partial/degraded
    upstream result still produces whatever events it can.
    """
    events: list[dict] = []

    for b in darkweb_result.get("breaches") or []:
        name = b.get("name") or b.get("title") or "unknown"
        events.append({
            "fingerprint": _fingerprint("breach", name, b.get("alias") or ""),
            "source": "breach",
            "severity": "critical" if b.get("verified") else "high",
            "title": b.get("title") or name,
            "detail": b,
        })

    for p in darkweb_result.get("pastes") or []:
        identifier = str(p.get("id") or p.get("url") or "")
        events.append({
            "fingerprint": _fingerprint("paste", identifier),
            "source": "paste",
            "severity": "medium",
            "title": f"Paste mention ({p.get('source') or 'unknown source'})",
            "detail": p,
        })

    for g in darkweb_result.get("github_exposures") or []:
        events.append({
            "fingerprint": _fingerprint("github_secret", g.get("html_url") or ""),
            "source": "github_secret",
            "severity": "high",
            "title": f"Exposed secret in {g.get('repository') or 'unknown repo'}",
            "detail": g,
        })

    for actor in darkweb_result.get("threat_actors") or []:
        events.append({
            "fingerprint": _fingerprint("threat_actor", actor),
            "source": "threat_actor",
            "severity": "critical",
            "title": f"Threat actor mention: {actor}",
            "detail": {"actor": actor},
        })

    if leakcheck_result and leakcheck_result.get("found"):
        for src in (leakcheck_result.get("sources") or ["unknown"]):
            events.append({
                "fingerprint": _fingerprint("leakcheck", src),
                "source": "leakcheck",
                "severity": "high",
                "title": f"LeakCheck match: {src}",
                "detail": {"source_name": src, "fields": leakcheck_result.get("fields") or []},
            })

    return events


def diff_new_events(events: list[dict], known_fingerprints: set[str]) -> list[dict]:
    """Return only the events whose fingerprint isn't already in
    `known_fingerprints` — the set of fingerprints already persisted for
    this monitored target. Pure function, no I/O."""
    return [e for e in events if e["fingerprint"] not in known_fingerprints]


# ── 3. Arabic localization ───────────────────────────────────────────────────
# `_ar`-suffixed fields, matching modules/osint/threat_narrative.py's
# bilingual convention.

SOURCE_LABELS_AR: dict[str, str] = {
    "breach": "تسريب بيانات",
    "paste": "نشر في موقع لصق (Paste)",
    "github_secret": "سر مكشوف على GitHub",
    "threat_actor": "إشارة إلى جهة تهديد",
    "leakcheck": "تسريب مكتشف عبر LeakCheck",
}

SEVERITY_LABELS_AR: dict[str, str] = {
    "critical": "حرج",
    "high": "مرتفع",
    "medium": "متوسط",
    "low": "منخفض",
}

EXPOSURE_LEVEL_AR: dict[str, str] = {
    "Clean": "نظيف",
    "Exposed": "معرّض للخطر",
    "Compromised": "مخترق",
    "Critical": "حرج",
}


def localize_event(event: dict) -> dict:
    """Return a copy of `event` with source_ar/severity_ar labels added."""
    localized = dict(event)
    localized["source_ar"] = SOURCE_LABELS_AR.get(event.get("source"), event.get("source"))
    localized["severity_ar"] = SEVERITY_LABELS_AR.get(event.get("severity"), event.get("severity"))
    return localized


def build_arabic_alert_message(target: str, new_events: list[dict]) -> str:
    """Human-readable Arabic summary of newly-discovered leak events for
    `target` — used as the alert/report message shown in the dashboard."""
    if not new_events:
        return f"لم يتم رصد أي تسريبات جديدة لـ {target}."

    lines = [f"⚠ تنبيه: تم رصد {len(new_events)} تسريب(ات) جديدة لـ {target}:"]
    for e in new_events:
        source_ar = SOURCE_LABELS_AR.get(e.get("source"), e.get("source"))
        severity_ar = SEVERITY_LABELS_AR.get(e.get("severity"), e.get("severity"))
        lines.append(f"- [{severity_ar}] {source_ar}: {e.get('title')}")
    return "\n".join(lines)


# ── 4. Orchestrator ─────────────────────────────────────────────────────────

def _exc_to_leakcheck_error(value: Any, target: str) -> dict:
    if isinstance(value, Exception):
        logger.error("[leakcheck] unexpected error: %s", value)
        return {"source": "leakcheck", "available": False, "target": target,
                "found": False, "sources": [], "fields": [], "error": str(value)}
    return value


async def run_monitor_check(target: str, target_type: str | None = None,
                             include_pastes: bool = True, include_github: bool = True) -> dict:
    """
    Run a full dark web monitoring pass for `target`: HIBP + IntelligenceX +
    BreachDirectory + Leak-Lookup + psbdmp + GitHub + OTX (via
    gather_darkweb_intelligence) plus LeakCheck, in parallel.

    Returns {target, target_type, events, exposure, leakcheck, checked_at}.
    `events` is the fingerprinted, diff-ready leak event list from
    build_leak_events(). Never raises.
    """
    from modules.osint.darkweb_intelligence import gather_darkweb_intelligence

    target = target.strip()
    darkweb_task = gather_darkweb_intelligence(target, include_pastes=include_pastes, include_github=include_github)
    leakcheck_task = _query_leakcheck(target)

    darkweb_result, leakcheck_result = await asyncio.gather(darkweb_task, leakcheck_task, return_exceptions=True)

    if isinstance(darkweb_result, Exception):
        logger.error("[darkweb_intel] unexpected error: %s", darkweb_result)
        darkweb_result = {
            "target": target, "target_type": target_type or "domain",
            "breaches": [], "pastes": [], "github_exposures": [], "threat_actors": [],
            "exposure": {"score": 0, "exposure_level": "Clean", "breakdown": [], "recommendations": []},
        }
    leakcheck_result = _exc_to_leakcheck_error(leakcheck_result, target)

    events = build_leak_events(darkweb_result, leakcheck_result)

    return {
        "target": target,
        "target_type": target_type or darkweb_result.get("target_type"),
        "events": events,
        "exposure": darkweb_result.get("exposure"),
        "leakcheck": leakcheck_result,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
