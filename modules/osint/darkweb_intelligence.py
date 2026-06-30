"""
Dark Web & Breach Intelligence — Phase 2B

Every source here is an official API or a free, legal, publicly-documented
indexing service — never raw dark web scraping. Sources fall into two
groups:
  - Keyed (optional): IntelligenceX, BreachDirectory (RapidAPI), Leak-Lookup,
    GitHub (higher rate limit) and HIBP (required, paid-only — HIBP has no
    free tier) all degrade to available=False with a clear "requires API
    key" message when their key is unset, the same way Shodan/Censys degrade
    in network_intelligence.py.
  - Keyless: psbdmp.ws (free Pastebin archive search) and GitHub Code Search
    (works unauthenticated at a lower rate limit) always run.

Ethical use: this module only ever queries indicator/account-level lookups
against indexes those services already built and licensed for API access.
See docs/OSINT.md's Ethical Use Policy — only scan targets you are
authorized to assess.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any

import aiohttp

logger = logging.getLogger("osint.darkweb_intel")

HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
INTELX_API_KEY = os.environ.get("INTELX_API_KEY", "")
RAPIDAPI_KEY = os.environ.get("RAPIDAPI_KEY", "")
LEAKLOOKUP_API_KEY = os.environ.get("LEAKLOOKUP_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

HIBP_BREACHEDACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
HIBP_BREACHEDDOMAIN_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
HIBP_PASTEACCOUNT_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{account}"
INTELX_SEARCH_URL = "https://2.intelx.io/intelligent/search"
INTELX_RESULT_URL = "https://2.intelx.io/intelligent/search/result"
BREACHDIRECTORY_URL = "https://breachdirectory.p.rapidapi.com/"
LEAKLOOKUP_SEARCH_URL = "https://leak-lookup.com/api/search"
PSBDMP_SEARCH_URL = "https://psbdmp.ws/api/search/{term}"
PSBDMP_DUMP_URL = "https://psbdmp.ws/api/dump/{id}"
GITHUB_CODE_SEARCH_URL = "https://api.github.com/search/code"
OTX_INDICATOR_DOMAIN_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
OTX_INDICATOR_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)
_USER_AGENT = "OPTISEC-Recon-Pro-DarkwebIntel/1.0"

_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


def _exc_to_error(value: Any, source_name: str) -> dict:
    if isinstance(value, Exception):
        logger.error("[%s] unexpected error: %s", source_name, value)
        return {"source": source_name, "available": False, "error": str(value)}
    return value


def _is_email(target: str) -> bool:
    return bool(_RE_EMAIL.match(target.strip()))


def _email_domain(target: str) -> str:
    """Return the domain part of an email, or `target` unchanged if it isn't one."""
    target = target.strip()
    return target.split("@")[-1] if _is_email(target) else target


# ── 1. Have I Been Pwned (HIBP) ────────────────────────────────────────────────
# Official HIBP API v3 — https://haveibeenpwned.com/API/v3. Every endpoint
# below requires a paid hibp-api-key (HIBP_API_KEY, no free tier exists);
# without one we return a clear "requires API key" message rather than
# silently returning empty results.

def _hibp_headers() -> dict:
    return {"hibp-api-key": HIBP_API_KEY, "user-agent": _USER_AGENT}


def _hibp_no_key_result(source: str, target: str, **extra) -> dict:
    base = {"source": source, "available": False, "target": target, "error": "requires API key (HIBP_API_KEY)"}
    base.update(extra)
    return base


async def _query_hibp_email(email: str) -> dict:
    """
    List every breach HIBP has on file for `email` (API v3
    /breachedaccount/{email}).

    Returns {source, available, target, breaches, error}. `breaches` is a
    list of {name, title, domain, breach_date, data_classes, pwn_count,
    verified, is_sensitive}. Never raises.
    """
    if not HIBP_API_KEY:
        return _hibp_no_key_result("hibp_email", email, breaches=[])

    url = HIBP_BREACHEDACCOUNT_URL.format(account=email)
    try:
        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT, headers=_hibp_headers()) as session:
            async with session.get(url, params={"truncateResponse": "false"}) as resp:
                if resp.status == 404:
                    return {"source": "hibp_email", "available": True, "target": email, "breaches": [], "error": None}
                if resp.status == 401:
                    return {"source": "hibp_email", "available": True, "target": email,
                            "breaches": [], "error": "invalid HIBP API key"}
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {"source": "hibp_email", "available": True, "target": email, "breaches": [], "error": str(exc)}

    breaches = [
        {
            "name": b.get("Name"),
            "title": b.get("Title"),
            "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "data_classes": b.get("DataClasses", []),
            "pwn_count": b.get("PwnCount"),
            "verified": b.get("IsVerified", False),
            "is_sensitive": b.get("IsSensitive", False),
        }
        for b in data or []
    ]
    return {"source": "hibp_email", "available": True, "target": email, "breaches": breaches, "error": None}


async def _query_hibp_domain(domain: str) -> dict:
    """
    List every breached email alias HIBP has on file for `domain` (API v3
    /breacheddomain/{domain}) — requires the calling HIBP account to have
    verified ownership of the domain.

    Returns {source, available, target, breached_accounts, error}, where
    breached_accounts maps each local-part alias to the breach names it
    appeared in (HIBP doesn't expose per-breach verification status at this
    endpoint, unlike /breachedaccount). Never raises.
    """
    if not HIBP_API_KEY:
        return _hibp_no_key_result("hibp_domain", domain, breached_accounts={})

    url = HIBP_BREACHEDDOMAIN_URL.format(domain=domain)
    try:
        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT, headers=_hibp_headers()) as session:
            async with session.get(url) as resp:
                if resp.status == 404:
                    return {"source": "hibp_domain", "available": True, "target": domain,
                            "breached_accounts": {}, "error": None}
                if resp.status == 401:
                    return {"source": "hibp_domain", "available": True, "target": domain, "breached_accounts": {},
                            "error": "invalid HIBP API key, or domain not verified with HIBP"}
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {"source": "hibp_domain", "available": True, "target": domain, "breached_accounts": {}, "error": str(exc)}

    return {"source": "hibp_domain", "available": True, "target": domain, "breached_accounts": data or {}, "error": None}


async def _query_hibp_pastes(email: str) -> dict:
    """
    List Pastebin (and similar) paste dumps mentioning `email` (API v3
    /pasteaccount/{email}).

    Returns {source, available, target, pastes, error}, where each paste is
    {source, id, title, date, email_count}. Never raises.
    """
    if not HIBP_API_KEY:
        return _hibp_no_key_result("hibp_pastes", email, pastes=[])

    url = HIBP_PASTEACCOUNT_URL.format(account=email)
    try:
        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT, headers=_hibp_headers()) as session:
            async with session.get(url) as resp:
                if resp.status == 404:
                    return {"source": "hibp_pastes", "available": True, "target": email, "pastes": [], "error": None}
                if resp.status == 401:
                    return {"source": "hibp_pastes", "available": True, "target": email,
                            "pastes": [], "error": "invalid HIBP API key"}
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {"source": "hibp_pastes", "available": True, "target": email, "pastes": [], "error": str(exc)}

    pastes = [
        {
            "source": p.get("Source"),
            "id": p.get("Id"),
            "title": p.get("Title"),
            "date": p.get("Date"),
            "email_count": p.get("EmailCount"),
        }
        for p in data or []
    ]
    return {"source": "hibp_pastes", "available": True, "target": email, "pastes": pastes, "error": None}


# ── 2. IntelligenceX ───────────────────────────────────────────────────────────
# Official IntelligenceX API (https://intelx.io/integrations/api) — searches
# dark web leak indexes, paste sites and public breach dumps that IntelX has
# already crawled and indexed. Optional: degrades to available=False without
# INTELX_API_KEY. Only short previews are returned, never full leaked content.

_INTELX_MAX_RESULTS = 10
_INTELX_POLL_ATTEMPTS = 5
_INTELX_POLL_DELAY = 1.5


def _intelx_headers() -> dict:
    return {"x-key": INTELX_API_KEY, "user-agent": _USER_AGENT}


async def _query_intelx(target: str) -> dict:
    """
    Search IntelligenceX for `target` (email/domain/username) across its
    indexed dark web leaks, paste sites and public breach dumps.

    Two-step API: POST a search job, then poll the result endpoint with the
    returned search id until results are ready or _INTELX_POLL_ATTEMPTS is
    exhausted.

    Returns {source, available, target, result_count, preview, error}.
    `preview` holds only short (<=200 char) item-name snippets — never full
    leaked content, for the same reason this module never scrapes the dark
    web directly. Never raises.
    """
    if not INTELX_API_KEY:
        return {"source": "intelx", "available": False, "target": target,
                "result_count": 0, "preview": [], "error": "requires API key (INTELX_API_KEY, optional)"}

    body = {"term": target, "maxresults": _INTELX_MAX_RESULTS, "media": 0, "sort": 4, "terminate": []}
    try:
        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT, headers=_intelx_headers()) as session:
            async with session.post(INTELX_SEARCH_URL, json=body) as resp:
                if resp.status == 401:
                    return {"source": "intelx", "available": True, "target": target,
                            "result_count": 0, "preview": [], "error": "invalid IntelligenceX API key"}
                resp.raise_for_status()
                search_id = (await resp.json()).get("id")

            if not search_id:
                return {"source": "intelx", "available": True, "target": target,
                        "result_count": 0, "preview": [], "error": "IntelligenceX did not return a search id"}

            records: list[dict] = []
            for _ in range(_INTELX_POLL_ATTEMPTS):
                async with session.get(INTELX_RESULT_URL, params={"id": search_id, "limit": _INTELX_MAX_RESULTS}) as resp:
                    resp.raise_for_status()
                    payload = await resp.json()
                records = payload.get("records", []) or []
                # status 0 = search still running; anything else, or records
                # already present, means we're done polling.
                if payload.get("status", 0) != 0 or records:
                    break
                await asyncio.sleep(_INTELX_POLL_DELAY)
    except aiohttp.ClientError as exc:
        return {"source": "intelx", "available": True, "target": target,
                "result_count": 0, "preview": [], "error": str(exc)}

    preview = [
        {"name": r.get("name"), "bucket": r.get("bucket"), "date": r.get("date"),
         "snippet": (r.get("name") or "")[:200]}
        for r in records[:_INTELX_MAX_RESULTS]
    ]
    return {"source": "intelx", "available": True, "target": target,
            "result_count": len(records), "preview": preview, "error": None}


# ── 3. BreachDirectory (RapidAPI) ─────────────────────────────────────────────
# RapidAPI-hosted BreachDirectory listing —
# https://rapidapi.com/rohan-patra/api/breachdirectory. Optional: degrades
# to available=False without RAPIDAPI_KEY.

def _breachdirectory_headers() -> dict:
    return {"X-RapidAPI-Key": RAPIDAPI_KEY, "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"}


async def _query_breachdirectory(target: str) -> dict:
    """
    Look up `target` (email/username/domain) in BreachDirectory via its
    RapidAPI listing.

    Returns {source, available, target, entries, error}, where each entry is
    {email, username, password_hash, sources}. Never raises.
    """
    if not RAPIDAPI_KEY:
        return {"source": "breachdirectory", "available": False, "target": target,
                "entries": [], "error": "requires API key (RAPIDAPI_KEY, optional)"}

    try:
        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT, headers=_breachdirectory_headers()) as session:
            async with session.get(BREACHDIRECTORY_URL, params={"func": "auto", "term": target}) as resp:
                if resp.status in (401, 403):
                    return {"source": "breachdirectory", "available": True, "target": target,
                            "entries": [], "error": "invalid or unauthorized RapidAPI key"}
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {"source": "breachdirectory", "available": True, "target": target, "entries": [], "error": str(exc)}

    raw_entries = (data or {}).get("result", []) or []
    entries = [
        {
            "email": e.get("email") or e.get("line"),
            "username": e.get("username"),
            "password_hash": e.get("password") or e.get("hash"),
            "sources": e.get("sources", []),
        }
        for e in raw_entries
    ]
    return {"source": "breachdirectory", "available": True, "target": target, "entries": entries, "error": None}


# ── 4. Leak-Lookup ─────────────────────────────────────────────────────────────
# Official Leak-Lookup API — https://leak-lookup.com/api. Optional: degrades
# to available=False without LEAKLOOKUP_API_KEY.

def _leaklookup_query_type(target: str) -> str:
    t = target.strip()
    if _is_email(t):
        return "email_address"
    if _RE_IP.match(t):
        return "ip_address"
    return "domain"


async def _query_leaklookup(target: str) -> dict:
    """
    Search Leak-Lookup for `target` (email/domain/IP).

    Returns {source, available, target, sources_found, data_types, error}.
    `sources_found` lists the breach source names that mention the target;
    `data_types` is the union of leaked field names (e.g. "password",
    "ip_address") across all of them. Never raises.
    """
    if not LEAKLOOKUP_API_KEY:
        return {"source": "leaklookup", "available": False, "target": target,
                "sources_found": [], "data_types": [], "error": "requires API key (LEAKLOOKUP_API_KEY, optional)"}

    body = {"key": LEAKLOOKUP_API_KEY, "type": _leaklookup_query_type(target), "query": target}
    try:
        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT) as session:
            async with session.post(LEAKLOOKUP_SEARCH_URL, data=body) as resp:
                resp.raise_for_status()
                data = await resp.json()
    except aiohttp.ClientError as exc:
        return {"source": "leaklookup", "available": True, "target": target,
                "sources_found": [], "data_types": [], "error": str(exc)}

    if (data or {}).get("error"):
        return {"source": "leaklookup", "available": True, "target": target,
                "sources_found": [], "data_types": [], "error": str(data.get("message"))}

    message = (data or {}).get("message") or {}
    sources_found = list(message.keys()) if isinstance(message, dict) else []
    data_types: set[str] = set()
    if isinstance(message, dict):
        for field_sets in message.values():
            for field_set in field_sets or []:
                if isinstance(field_set, dict):
                    data_types.update(field_set.keys())

    return {"source": "leaklookup", "available": True, "target": target,
            "sources_found": sources_found, "data_types": sorted(data_types), "error": None}
