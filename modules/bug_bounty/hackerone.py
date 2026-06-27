"""HackerOne API integration — program discovery, report submission, bounty tracking."""

import os
import asyncio
from datetime import datetime
from typing import Optional
import httpx

HACKERONE_API_BASE = "https://api.hackerone.com/v1"


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


async def search_programs(keyword: str = "", limit: int = 20) -> dict:
    username, token = _get_creds()
    if not username or not token:
        return _demo_programs(keyword, limit)

    params = {"page[size]": limit}
    if keyword:
        params["filter[keyword]"] = keyword

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(
                f"{HACKERONE_API_BASE}/hackers/programs",
                params=params,
                headers=_headers(username, token),
            )
            r.raise_for_status()
            data = r.json()
            programs = []
            for p in data.get("data", []):
                attrs = p.get("attributes", {})
                programs.append({
                    "id": p.get("id"),
                    "handle": attrs.get("handle"),
                    "name": attrs.get("name"),
                    "policy": attrs.get("policy", ""),
                    "bounty_table": attrs.get("bounty_table"),
                    "response_efficiency": attrs.get("response_efficiency_percentage"),
                    "submission_state": attrs.get("submission_state"),
                    "url": f"https://hackerone.com/{attrs.get('handle')}",
                })
            return {"programs": programs, "total": len(programs), "source": "api"}
        except Exception as e:
            return {"error": str(e), "programs": [], "source": "api"}


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

            scope_items = []
            for scope in rels.get("structured_scopes", {}).get("data", []):
                s = scope.get("attributes", {})
                scope_items.append({
                    "asset": s.get("asset_identifier"),
                    "type": s.get("asset_type"),
                    "eligible_for_bounty": s.get("eligible_for_bounty"),
                    "eligible_for_submission": s.get("eligible_for_submission"),
                    "max_severity": s.get("max_severity"),
                    "instruction": s.get("instruction"),
                })

            return {
                "handle": handle,
                "name": attrs.get("name"),
                "scopes": scope_items,
                "bounty_table": attrs.get("bounty_table"),
                "response_sla": attrs.get("first_response_time"),
                "source": "api",
            }
        except Exception as e:
            return {"error": str(e), "handle": handle, "scopes": [], "source": "api"}


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
         "response_efficiency": 97, "url": "https://hackerone.com/shopify"},
        {"id": "2", "handle": "twitter", "name": "Twitter", "submission_state": "open",
         "response_efficiency": 85, "url": "https://hackerone.com/twitter"},
        {"id": "3", "handle": "github", "name": "GitHub", "submission_state": "open",
         "response_efficiency": 92, "url": "https://hackerone.com/github"},
        {"id": "4", "handle": "uber", "name": "Uber", "submission_state": "open",
         "response_efficiency": 88, "url": "https://hackerone.com/uber"},
        {"id": "5", "handle": "dropbox", "name": "Dropbox", "submission_state": "open",
         "response_efficiency": 79, "url": "https://hackerone.com/dropbox"},
    ]
    if keyword:
        programs = [p for p in programs if keyword.lower() in p["name"].lower()]
    return {"programs": programs[:limit], "total": len(programs), "source": "demo",
            "note": "Set HACKERONE_USERNAME and HACKERONE_API_TOKEN for live data"}


def _demo_scope(handle: str) -> dict:
    return {
        "handle": handle, "name": handle.title(), "source": "demo",
        "scopes": [
            {"asset": f"*.{handle}.com", "type": "URL", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "critical"},
            {"asset": f"api.{handle}.com", "type": "URL", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "critical"},
            {"asset": f"mobile.{handle}.com", "type": "URL", "eligible_for_bounty": True,
             "eligible_for_submission": True, "max_severity": "high"},
        ],
        "note": "Set HACKERONE_USERNAME and HACKERONE_API_TOKEN for live scope",
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
