"""HackerOne API integration — program discovery, report submission, bounty tracking."""

import os
import asyncio
from datetime import datetime
from typing import Optional
import httpx

HACKERONE_API_BASE = "https://api.hackerone.com/v1"
H1_PUBLIC_SEARCH = "https://hackerone.com/programs/search"


def _get_creds() -> tuple[str, str]:
    username = os.environ.get("HACKERONE_USERNAME", "")
    token = os.environ.get("HACKERONE_API_TOKEN", "")
    return username, token


def _headers(username: str, token: str) -> dict:
    import base64
    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


_PUBLIC_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


async def search_programs(keyword: str = "", limit: int = 20) -> dict:
    """Search HackerOne programs — tries public API first, falls back to auth then demo."""
    params = {
        "query": keyword,
        "sort": "published_at",
        "direction": "DESC",
        "page": 1,
    }

    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
        try:
            r = await client.get(H1_PUBLIC_SEARCH, params=params, headers=_PUBLIC_HEADERS)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict):
                raise ValueError("unexpected response format")
            results = data.get("results", [])
            programs = []
            for p in results[:limit]:
                meta = p.get("meta", {})
                handle = p.get("handle") or p.get("url", "").lstrip("/")
                min_b = meta.get("minimum_bounty")
                currency = meta.get("default_currency", "usd").upper()
                programs.append({
                    "id": p.get("id"),
                    "handle": handle,
                    "name": p.get("name", handle),
                    "submission_state": meta.get("submission_state", "open"),
                    "offers_bounties": meta.get("offers_bounties", False),
                    "quick_to_bounty": meta.get("quick_to_bounty", False),
                    "quick_to_first_response": meta.get("quick_to_first_response", False),
                    "min_bounty": min_b,
                    "currency": currency,
                    "resolved_reports": meta.get("resolved_report_count"),
                    "logo": p.get("profile_picture"),
                    "about": p.get("about", ""),
                    "policy_snippet": (p.get("stripped_policy") or "")[:600],
                    "url": f"https://hackerone.com/{handle}",
                })
            return {"programs": programs, "total": data.get("total", len(programs)), "source": "public"}
        except Exception:
            pass

    # Authenticated API fallback
    username, token = _get_creds()
    if username and token:
        params2 = {"page[size]": limit}
        if keyword:
            params2["filter[keyword]"] = keyword
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                r = await client.get(
                    f"{HACKERONE_API_BASE}/hackers/programs",
                    params=params2,
                    headers=_headers(username, token),
                )
                r.raise_for_status()
                data = r.json()
                programs = []
                for p in data.get("data", []):
                    attrs = p.get("attributes", {})
                    handle = attrs.get("handle", "")
                    programs.append({
                        "id": p.get("id"),
                        "handle": handle,
                        "name": attrs.get("name", handle),
                        "submission_state": attrs.get("submission_state"),
                        "offers_bounties": True,
                        "quick_to_bounty": False,
                        "quick_to_first_response": False,
                        "min_bounty": None,
                        "currency": "USD",
                        "resolved_reports": None,
                        "logo": None,
                        "about": "",
                        "policy_snippet": "",
                        "url": f"https://hackerone.com/{handle}",
                    })
                return {"programs": programs, "total": len(programs), "source": "api"}
            except Exception as e:
                return {"error": str(e), "programs": [], "source": "api"}

    return _demo_programs(keyword, limit)


async def get_program_scope(handle: str) -> dict:
    username, token = _get_creds()
    if not username or not token:
        return _demo_scope(handle)

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(
                f"{HACKERONE_API_BASE}/hackers/programs/{handle}",
                headers=_headers(username, token),
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            rels = data.get("relationships", {})

            in_scope = []
            out_of_scope = []
            for scope in rels.get("structured_scopes", {}).get("data", []):
                s = scope.get("attributes", {})
                item = {
                    "asset": s.get("asset_identifier"),
                    "type": s.get("asset_type"),
                    "eligible_for_bounty": s.get("eligible_for_bounty"),
                    "eligible_for_submission": s.get("eligible_for_submission"),
                    "max_severity": s.get("max_severity"),
                    "instruction": s.get("instruction"),
                }
                if s.get("eligible_for_submission", True):
                    in_scope.append(item)
                else:
                    out_of_scope.append(item)

            bounty_table = attrs.get("bounty_table") or {}
            return {
                "handle": handle,
                "name": attrs.get("name"),
                "in_scope": in_scope,
                "out_of_scope": out_of_scope,
                "scopes": in_scope,
                "bounty_table": bounty_table,
                "response_sla": attrs.get("first_response_time"),
                "source": "api",
            }
        except Exception as e:
            return {"error": str(e), "handle": handle, "in_scope": [], "out_of_scope": [], "scopes": [], "source": "api"}


async def submit_report(
    program_handle: str,
    title: str,
    vulnerability_type: str,
    severity: str,
    description: str,
    impact: str,
    steps_to_reproduce: str,
) -> dict:
    username, token = _get_creds()
    if not username or not token:
        return {
            "status": "demo",
            "message": "Set HACKERONE_USERNAME and HACKERONE_API_TOKEN to submit real reports",
            "draft_id": f"DRAFT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        }

    severity_map = {
        "critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "info": "informational",
    }

    payload = {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle": program_handle,
                "title": title,
                "vulnerability_information": f"{description}\n\n**Impact**\n{impact}\n\n**Steps to Reproduce**\n{steps_to_reproduce}",
                "severity_rating": severity_map.get(severity.lower(), "medium"),
                "weakness": {"name": vulnerability_type},
            },
        }
    }

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.post(
                f"{HACKERONE_API_BASE}/hackers/reports",
                json=payload,
                headers=_headers(username, token),
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            return {
                "status": "submitted",
                "report_id": data.get("id"),
                "url": f"https://hackerone.com/reports/{data.get('id')}",
                "created_at": data.get("attributes", {}).get("created_at"),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


async def get_my_reports(state: str = "all", limit: int = 25) -> dict:
    username, token = _get_creds()
    if not username or not token:
        return _demo_reports()

    params = {"page[size]": limit, "sort": "-created_at"}
    if state != "all":
        params["filter[state][]"] = state

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(
                f"{HACKERONE_API_BASE}/hackers/me/reports",
                params=params,
                headers=_headers(username, token),
            )
            r.raise_for_status()
            data = r.json()
            reports = []
            for rep in data.get("data", []):
                attrs = rep.get("attributes", {})
                reports.append({
                    "id": rep.get("id"),
                    "title": attrs.get("title"),
                    "state": attrs.get("state"),
                    "severity": attrs.get("severity_rating"),
                    "bounty": attrs.get("bounty_amount"),
                    "created_at": attrs.get("created_at"),
                    "url": f"https://hackerone.com/reports/{rep.get('id')}",
                })
            return {"reports": reports, "total": len(reports), "source": "api"}
        except Exception as e:
            return {"error": str(e), "reports": [], "source": "api"}


def _demo_programs(keyword: str, limit: int) -> dict:
    programs = [
        {"id": "1", "handle": "shopify", "name": "Shopify", "submission_state": "open",
         "offers_bounties": True, "quick_to_bounty": True, "quick_to_first_response": False,
         "min_bounty": 500, "currency": "USD", "resolved_reports": 2414,
         "logo": "https://profile-photos.hackerone-user-content.com/variants/fjjiC5585s8WoDGHv2M5okbJ/190fe443f85acdf4118e495664805924efcc8e07aa6b2406d5edca2b2b9e3f9c",
         "about": "Shopify is a multi-channel commerce platform.",
         "policy_snippet": "We reward security researchers for finding vulnerabilities. Rewards up to $200,000.",
         "url": "https://hackerone.com/shopify"},
        {"id": "2", "handle": "twitter", "name": "Twitter / X", "submission_state": "open",
         "offers_bounties": True, "quick_to_bounty": False, "quick_to_first_response": False,
         "min_bounty": 140, "currency": "USD", "resolved_reports": 1823,
         "logo": None, "about": "Twitter is a social media platform.",
         "policy_snippet": "We welcome reports of security vulnerabilities in Twitter services.",
         "url": "https://hackerone.com/twitter"},
        {"id": "3", "handle": "github", "name": "GitHub", "submission_state": "open",
         "offers_bounties": True, "quick_to_bounty": True, "quick_to_first_response": True,
         "min_bounty": 617, "currency": "USD", "resolved_reports": 1456,
         "logo": None, "about": "GitHub is a code hosting platform for version control and collaboration.",
         "policy_snippet": "GitHub runs a bug bounty program to improve security for our users.",
         "url": "https://hackerone.com/github"},
        {"id": "4", "handle": "uber", "name": "Uber", "submission_state": "open",
         "offers_bounties": True, "quick_to_bounty": False, "quick_to_first_response": False,
         "min_bounty": 500, "currency": "USD", "resolved_reports": 952,
         "logo": None, "about": "Uber is a ride-sharing platform.",
         "policy_snippet": "Uber's bug bounty program covers all Uber products and services.",
         "url": "https://hackerone.com/uber"},
        {"id": "5", "handle": "dropbox", "name": "Dropbox", "submission_state": "open",
         "offers_bounties": True, "quick_to_bounty": False, "quick_to_first_response": False,
         "min_bounty": 216, "currency": "USD", "resolved_reports": 743,
         "logo": None, "about": "Dropbox is a cloud storage service.",
         "policy_snippet": "Dropbox's bug bounty program covers Dropbox core products.",
         "url": "https://hackerone.com/dropbox"},
    ]
    if keyword:
        kw = keyword.lower()
        programs = [p for p in programs if kw in p["name"].lower() or kw in p["handle"].lower()]
    return {"programs": programs[:limit], "total": len(programs), "source": "demo",
            "note": "Demo data — public API unavailable"}


def _demo_scope(handle: str) -> dict:
    return {
        "handle": handle,
        "name": handle.replace("-", " ").title(),
        "source": "demo",
        "in_scope": [
            {"asset": f"*.{handle}.com", "type": "URL", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "critical"},
            {"asset": f"api.{handle}.com", "type": "URL", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "critical"},
            {"asset": f"mobile.{handle}.com", "type": "URL", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "high"},
        ],
        "out_of_scope": [
            {"asset": "*.staging.* / *.dev.*", "type": "URL", "eligible_for_bounty": False,
             "eligible_for_submission": False, "max_severity": None},
        ],
        "scopes": [],
        "bounty_table": {},
        "note": "Set HACKERONE_USERNAME and HACKERONE_API_TOKEN for live scope data",
    }


def _demo_reports() -> dict:
    return {
        "reports": [
            {"id": "1234567", "title": "XSS in search parameter", "state": "resolved",
             "severity": "medium", "bounty": "500.00", "created_at": "2026-05-01T10:00:00Z",
             "url": "https://hackerone.com/reports/1234567"},
            {"id": "1234568", "title": "SSRF via webhook URL", "state": "triaged",
             "severity": "high", "bounty": None, "created_at": "2026-06-01T10:00:00Z",
             "url": "https://hackerone.com/reports/1234568"},
        ],
        "total": 2, "source": "demo",
    }
