"""Bugcrowd + Intigriti API integration."""

import os
import asyncio
from typing import Optional
import httpx

BUGCROWD_API_BASE = "https://api.bugcrowd.com"
INTIGRITI_API_BASE = "https://api.intigriti.com/core/public/program"


# ── Bugcrowd ──────────────────────────────────────────────────────────────────

def _bc_headers() -> dict:
    token = os.environ.get("BUGCROWD_API_TOKEN", "")
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/vnd.bugcrowd.v4+json",
        "Content-Type": "application/json",
    }


async def bc_list_programs(limit: int = 20) -> dict:
    token = os.environ.get("BUGCROWD_API_TOKEN", "")
    if not token:
        return _bc_demo_programs()

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(
                f"{BUGCROWD_API_BASE}/programs",
                params={"page[limit]": limit, "filter[bounty_type]": "bug_bounty"},
                headers=_bc_headers(),
            )
            r.raise_for_status()
            data = r.json()
            programs = []
            for p in data.get("data", []):
                attrs = p.get("attributes", {})
                programs.append({
                    "id": p.get("id"),
                    "name": attrs.get("name"),
                    "code": attrs.get("code"),
                    "status": attrs.get("participation"),
                    "min_payout": attrs.get("min_payout"),
                    "max_payout": attrs.get("max_payout"),
                    "url": f"https://bugcrowd.com/{attrs.get('code')}",
                    "platform": "bugcrowd",
                })
            return {"programs": programs, "total": len(programs), "source": "api"}
        except Exception as e:
            return {"error": str(e), "programs": _bc_demo_programs()["programs"], "source": "demo"}


async def bc_get_targets(program_code: str) -> dict:
    token = os.environ.get("BUGCROWD_API_TOKEN", "")
    if not token:
        return _bc_demo_targets(program_code)

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(
                f"{BUGCROWD_API_BASE}/programs/{program_code}/targets",
                headers=_bc_headers(),
            )
            r.raise_for_status()
            data = r.json()
            targets = []
            for t in data.get("data", []):
                attrs = t.get("attributes", {})
                targets.append({
                    "name": attrs.get("name"),
                    "uri": attrs.get("uri"),
                    "category": attrs.get("category"),
                    "points": attrs.get("points"),
                    "priority": attrs.get("priority"),
                })
            return {"targets": targets, "program": program_code, "source": "api"}
        except Exception as e:
            return {"error": str(e), "targets": [], "source": "api"}


async def bc_submit_report(
    program_code: str,
    title: str,
    description: str,
    severity: str,
    vrt_id: str = "server_security_misconfiguration",
) -> dict:
    token = os.environ.get("BUGCROWD_API_TOKEN", "")
    if not token:
        return {"status": "demo", "message": "Set BUGCROWD_API_TOKEN to submit real reports"}

    payload = {
        "data": {
            "type": "submission",
            "attributes": {
                "title": title,
                "description": description,
                "severity": severity,
                "vrt_id": vrt_id,
            },
            "relationships": {
                "program": {"data": {"type": "program", "id": program_code}},
            },
        }
    }
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.post(
                f"{BUGCROWD_API_BASE}/submissions",
                json=payload,
                headers=_bc_headers(),
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            return {
                "status": "submitted",
                "id": data.get("id"),
                "url": f"https://bugcrowd.com/submissions/{data.get('id')}",
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


# ── Intigriti ─────────────────────────────────────────────────────────────────

def _ig_headers() -> dict:
    token = os.environ.get("INTIGRITI_API_TOKEN", "")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


async def ig_list_programs(limit: int = 20) -> dict:
    token = os.environ.get("INTIGRITI_API_TOKEN", "")
    if not token:
        return _ig_demo_programs()

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(
                f"{INTIGRITI_API_BASE}s",
                params={"limit": limit},
                headers=_ig_headers(),
            )
            r.raise_for_status()
            data = r.json()
            programs = []
            for p in data.get("records", []):
                programs.append({
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "handle": p.get("handle"),
                    "min_bounty": p.get("minBounty"),
                    "max_bounty": p.get("maxBounty"),
                    "status": p.get("status", {}).get("value"),
                    "url": f"https://app.intigriti.com/programs/{p.get('handle')}",
                    "platform": "intigriti",
                })
            return {"programs": programs, "total": len(programs), "source": "api"}
        except Exception as e:
            return {"error": str(e), "programs": _ig_demo_programs()["programs"], "source": "demo"}


async def ig_get_program(handle: str) -> dict:
    token = os.environ.get("INTIGRITI_API_TOKEN", "")
    if not token:
        return _ig_demo_program(handle)

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(
                f"{INTIGRITI_API_BASE}/{handle}",
                headers=_ig_headers(),
            )
            r.raise_for_status()
            p = r.json()
            domains = [d.get("endpoint") for d in p.get("domains", {}).get("inScope", [])]
            return {
                "handle": handle,
                "name": p.get("name"),
                "scopes": domains,
                "bounty_table": p.get("bountyTable", {}),
                "source": "api",
            }
        except Exception as e:
            return {"error": str(e), "handle": handle, "scopes": [], "source": "api"}


def _bc_demo_programs() -> dict:
    return {
        "programs": [
            {"id": "bc1", "name": "Tesla", "code": "tesla", "status": "open",
             "min_payout": 100, "max_payout": 15000,
             "url": "https://bugcrowd.com/tesla", "platform": "bugcrowd"},
            {"id": "bc2", "name": "Fitbit", "code": "fitbit", "status": "open",
             "min_payout": 100, "max_payout": 5000,
             "url": "https://bugcrowd.com/fitbit", "platform": "bugcrowd"},
            {"id": "bc3", "name": "Dell", "code": "dell", "status": "open",
             "min_payout": 200, "max_payout": 10000,
             "url": "https://bugcrowd.com/dell", "platform": "bugcrowd"},
        ],
        "total": 3, "source": "demo",
        "note": "Set BUGCROWD_API_TOKEN for live data",
    }


def _bc_demo_targets(code: str) -> dict:
    return {
        "targets": [
            {"name": "Main Website", "uri": f"https://www.{code}.com", "category": "website",
             "points": 500, "priority": "P1"},
            {"name": "API", "uri": f"https://api.{code}.com", "category": "api",
             "points": 750, "priority": "P1"},
        ],
        "program": code, "source": "demo",
    }


def _ig_demo_programs() -> dict:
    return {
        "programs": [
            {"id": "ig1", "name": "Proximus", "handle": "proximus", "status": "open",
             "min_bounty": 100, "max_bounty": 5000,
             "url": "https://app.intigriti.com/programs/proximus", "platform": "intigriti"},
            {"id": "ig2", "name": "Siemens", "handle": "siemens", "status": "open",
             "min_bounty": 250, "max_bounty": 20000,
             "url": "https://app.intigriti.com/programs/siemens", "platform": "intigriti"},
        ],
        "total": 2, "source": "demo",
        "note": "Set INTIGRITI_API_TOKEN for live data",
    }


def _ig_demo_program(handle: str) -> dict:
    return {
        "handle": handle, "name": handle.title(), "source": "demo",
        "scopes": [f"*.{handle}.com", f"api.{handle}.com"],
    }
