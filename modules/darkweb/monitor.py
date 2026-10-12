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


async def _query_leakcheck(target: str, target_type: str = "domain") -> dict:
    """
    Check `target` against LeakCheck's breach index.

    With LEAKCHECK_API_KEY the v2 endpoint is called with an explicit
    `type` (domain/email/username — never "auto", see
    modules/darkweb/leak_records.LEAKCHECK_QUERY_TYPES), and each returned
    row becomes one leak record. Without a key the free public endpoint is
    used: it has no `type` parameter (it ignores one if sent), so it only ever
    receives targets that already passed modules/darkweb/targets validation,
    and results are recorded per source against the target itself
    (`type_enforced: False` flags this).

    Returns {source, available, target, query_type, type_enforced, found,
    sources, fields, records, error[, error_ar, status]}. Password values are
    classified and dropped — only field names survive. Never raises.
    """
    from modules.darkweb.leak_records import api_error, query_type_for, password_field_kind

    query_type = query_type_for("leakcheck", target_type)
    empty = {"source": "leakcheck", "available": True, "target": target, "query_type": query_type,
             "type_enforced": bool(LEAKCHECK_API_KEY), "found": False, "sources": [], "fields": [], "records": []}
    try:
        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT, headers=_leakcheck_headers()) as session:
            if LEAKCHECK_API_KEY:
                url = LEAKCHECK_PRO_URL.format(target=target)
                req = session.get(url, params={"type": query_type})
            else:
                req = session.get(LEAKCHECK_PUBLIC_URL, params={"check": target})
            async with req as resp:
                if resp.status == 404:
                    return empty
                if resp.status in (400, 401, 403, 422, 429):
                    detail = None
                    try:
                        detail = (await resp.json()).get("error")
                    except Exception:
                        pass
                    return {**empty, **api_error("leakcheck", resp.status, detail)}
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {**empty, "error": str(exc)}

    if isinstance(data, dict) and data.get("success") is False:
        return {**empty, **api_error("leakcheck", None, str(data.get("error") or "query failed"))}

    data = data or {}
    found = bool(data.get("found"))
    records: list[dict] = []
    source_names: list[str] = []
    all_fields: set[str] = set()

    if LEAKCHECK_API_KEY and isinstance(data.get("result"), list):
        for row in data["result"]:
            if not isinstance(row, dict):
                continue
            src = row.get("source") or {}
            name = (src.get("name") if isinstance(src, dict) else str(src)) or "Unknown source"
            date = src.get("breach_date") if isinstance(src, dict) else None
            fields = set(row.get("fields") or []) | {k for k in row if k not in ("source", "fields")}
            if "password" in fields:
                fields.discard("password")
                fields.add(password_field_kind(row.get("password")) or "password")
            email, username = row.get("email"), row.get("username")
            if target_type == "domain" and email:
                matched_field, matched_value = "email", email
            elif target_type == "username" and username:
                matched_field, matched_value = "username", username
            else:
                matched_field, matched_value = target_type, (email if target_type == "email" and email else target)
            if name not in source_names:
                source_names.append(name)
            all_fields |= fields
            records.append({"provider": "leakcheck", "source_name": name, "leak_date": date,
                            "matched_field": matched_field, "matched_value": matched_value,
                            "leaked_fields": sorted(fields)})
    else:
        fields = list(data.get("fields") or [])
        all_fields |= set(fields)
        for s in data.get("sources") or data.get("result") or []:
            name = (s.get("name") if isinstance(s, dict) else str(s)) or "Unknown source"
            date = s.get("date") if isinstance(s, dict) else None
            source_names.append(name)
            records.append({"provider": "leakcheck", "source_name": name, "leak_date": date or None,
                            "matched_field": target_type, "matched_value": target,
                            "leaked_fields": fields})
        if found and not records:
            records.append({"provider": "leakcheck", "source_name": "Unknown source", "leak_date": None,
                            "matched_field": target_type, "matched_value": target, "leaked_fields": fields})

    return {**empty, "found": found, "sources": source_names, "fields": sorted(all_fields),
            "records": records, "error": None}


# ── 2. Leak event normalization + fingerprinting ────────────────────────────
# Every darkweb_intelligence.py source shape (breach/paste/github_exposure/
# threat_actor) plus the per-record credential-leak providers (LeakCheck,
# BreachDirectory, Leak-Lookup, HIBP) is flattened into one common event shape
# so the monitor router can diff/store/localize them uniformly:
#   {fingerprint, source, severity, title, detail[, matched_field, leak_date,
#    leaked_fields]}

def _fingerprint(source: str, *parts: str) -> str:
    """Stable dedupe key for a non-record leak event (paste/github/actor) —
    same source+identifying parts always hash to the same fingerprint, so
    re-checking a target never re-alerts on something already stored."""
    raw = "|".join((source, *(p or "" for p in parts)))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# Cap per provider per check so a large domain can't flood the alert table in
# one run; the rest surface on later checks once these are deduped.
MAX_RECORDS_PER_PROVIDER = 100


def _hibp_records(darkweb_result: dict, target: str, target_type: str) -> list[dict]:
    from modules.darkweb.leak_records import canonical_fields
    records = []
    for b in darkweb_result.get("breaches") or []:
        name = b.get("title") or b.get("name") or "Unknown breach"
        alias = b.get("alias")
        if alias:
            matched_field, matched_value = "email", f"{alias}@{target}"
            fields = ["email"]
        else:
            matched_field, matched_value = target_type, target
            fields = canonical_fields(b.get("data_classes") or [])
        records.append({"provider": "hibp", "source_name": name, "leak_date": b.get("breach_date"),
                        "matched_field": matched_field, "matched_value": matched_value, "leaked_fields": fields})
    return records


def build_leak_events(darkweb_result: dict, leakcheck_result: dict | None,
                      target: str = "", target_type: str = "domain") -> list[dict]:
    """
    Flatten a gather_darkweb_intelligence() result and a _query_leakcheck()
    result into a single fingerprinted, deduped leak-event list.

    Credential-leak records are scored by
    modules/darkweb/leak_records.compute_severity and fingerprinted by
    (source + matched field + target). Never raises — every field is read
    defensively so a partial/degraded upstream result still produces
    whatever events it can.
    """
    from modules.darkweb.leak_records import record_to_event, merge_events

    target = target or darkweb_result.get("target") or (leakcheck_result or {}).get("target") or ""
    events: list[dict] = []

    lc = leakcheck_result or {}
    lc_records = lc.get("records")
    if lc_records is None and lc.get("found"):
        # Pre-records result shape ({found, sources, fields}) — one record per source.
        lc_records = [{"provider": "leakcheck", "source_name": str(s), "leak_date": None,
                       "matched_field": target_type, "matched_value": target,
                       "leaked_fields": lc.get("fields") or []}
                      for s in (lc.get("sources") or ["Unknown source"])]
    record_groups = [
        _hibp_records(darkweb_result, target, target_type),
        lc_records or [],
        (darkweb_result.get("breachdirectory") or {}).get("records") or [],
        (darkweb_result.get("leaklookup") or {}).get("records") or [],
    ]
    for group in record_groups:
        for rec in group[:MAX_RECORDS_PER_PROVIDER]:
            events.append(record_to_event(rec, target, target_type))

    for p in darkweb_result.get("pastes") or []:
        identifier = str(p.get("id") or p.get("url") or "")
        events.append({
            "fingerprint": _fingerprint("paste", identifier),
            "source": "paste",
            "severity": "medium",
            "title": f"Paste mention ({p.get('source') or 'unknown source'})",
            # Original keys kept: modules/threat_intel/threat_sharing.py reads detail["url"].
            "detail": {**p, "source_name": p.get("source") or "paste", "reference_url": p.get("url"),
                       "leak_date": p.get("date")},
        })

    for g in darkweb_result.get("github_exposures") or []:
        events.append({
            "fingerprint": _fingerprint("github_secret", g.get("html_url") or ""),
            "source": "github_secret",
            "severity": "high",
            "title": f"Exposed secret in {g.get('repository') or 'unknown repo'}",
            "detail": {**g, "source_name": "GitHub", "reference_url": g.get("html_url")},
        })

    for actor in darkweb_result.get("threat_actors") or []:
        events.append({
            "fingerprint": _fingerprint("threat_actor", actor),
            "source": "threat_actor",
            "severity": "critical",
            "title": f"Threat actor mention: {actor}",
            "detail": {"actor": actor, "source_name": "AlienVault OTX"},
        })

    merged = merge_events(events, target, target_type)
    for ev in merged:
        ev.pop("_matched_value", None)   # raw value: in-memory only
    return merged


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
    "hibp": "تسريب بيانات (HIBP)",
    "breachdirectory": "تسريب مكتشف عبر BreachDirectory",
    "leaklookup": "تسريب مكتشف عبر Leak-Lookup",
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

# Sources whose errors are surfaced to the user. Unconfigured optional sources
# (available=False, "requires API key") are expected and not reported.
_REPORTED_SOURCES = ("intelx", "breachdirectory", "leaklookup")


def collect_source_errors(darkweb_result: dict, leakcheck_result: dict | None) -> list[dict]:
    """[{source, error, error_ar}] for every configured source that failed."""
    errors = []
    candidates = [("leakcheck", leakcheck_result or {})]
    candidates += [(name, darkweb_result.get(name) or {}) for name in _REPORTED_SOURCES]
    for name, res in candidates:
        if res.get("error") and res.get("available", True):
            errors.append({"source": name, "error": res["error"],
                           "error_ar": res.get("error_ar") or res["error"], "status": res.get("status")})
    return errors


def check_succeeded(result: dict) -> bool:
    """A check counts as successful unless LeakCheck — the one source that
    always runs, keyed or not — failed and nothing else produced events."""
    lc = result.get("leakcheck") or {}
    return not (lc.get("error") and not result.get("events"))


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
    target_type = target_type or ("email" if "@" in target else "domain")
    darkweb_task = gather_darkweb_intelligence(target, include_pastes=include_pastes,
                                               include_github=include_github, target_type=target_type)
    leakcheck_task = _query_leakcheck(target, target_type)

    darkweb_result, leakcheck_result = await asyncio.gather(darkweb_task, leakcheck_task, return_exceptions=True)

    if isinstance(darkweb_result, Exception):
        logger.error("[darkweb_intel] unexpected error: %s", darkweb_result)
        darkweb_result = {
            "target": target, "target_type": target_type or "domain",
            "breaches": [], "pastes": [], "github_exposures": [], "threat_actors": [],
            "exposure": {"score": 0, "exposure_level": "Clean", "breakdown": [], "recommendations": []},
        }
    leakcheck_result = _exc_to_leakcheck_error(leakcheck_result, target)

    events = build_leak_events(darkweb_result, leakcheck_result, target, target_type)

    return {
        "target": target,
        "target_type": target_type,
        "events": events,
        "source_errors": collect_source_errors(darkweb_result, leakcheck_result),
        "exposure": darkweb_result.get("exposure"),
        "leakcheck": leakcheck_result,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
