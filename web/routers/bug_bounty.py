"""Bug Bounty router — HackerOne, Bugcrowd, Intigriti, CVE Pipeline."""

import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, BugBountySubmission
from web.auth import get_current_user
from web.license import require_feature_or_402
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/bug-bounty", tags=["bug-bounty"])

# HACKERONE_API_TOKEN/BUGCROWD_API_TOKEN are one shared, instance-wide
# credential (see modules/bug_bounty/{hackerone,bugcrowd}.py) -- any PRO/
# ENTERPRISE user can trigger a real submission under that shared identity.
# This caps how many any single user can fire in a rolling window, so a
# careless or malicious account can't hammer the platform's own HackerOne/
# Bugcrowd account into a ban. Enforced via BugBountySubmission row counts
# (DB-backed, not the in-memory rate_limiter()) so it stays correct across
# the 2 Render workers and survives restarts.
BUG_BOUNTY_SUBMIT_WINDOW_MINUTES = 60


def _bug_bounty_submit_limit() -> int:
    return int(os.environ.get("RATE_LIMIT_BUG_BOUNTY_SUBMIT", "5"))


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


async def _enforce_submission_quota(db: AsyncSession, user: User) -> None:
    window_start = datetime.utcnow() - timedelta(minutes=BUG_BOUNTY_SUBMIT_WINDOW_MINUTES)
    limit = _bug_bounty_submit_limit()
    count = (await db.execute(
        select(func.count()).select_from(BugBountySubmission)
        .where(BugBountySubmission.user_id == user.id, BugBountySubmission.created_at >= window_start)
    )).scalar()
    if count >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Submission limit reached ({limit} per {BUG_BOUNTY_SUBMIT_WINDOW_MINUTES} min) — "
                   f"this protects the shared platform HackerOne/Bugcrowd account from abuse.",
        )


async def _record_submission(
    db: AsyncSession, user: User, platform: str, program: str,
    title: str, severity: str, result: dict,
) -> None:
    db.add(BugBountySubmission(
        user_id=user.id,
        platform=platform,
        program=program[:200],
        title=title[:300],
        severity=severity,
        status=result.get("status", "error" if result.get("error") else "submitted"),
        external_ref=str(result.get("report_id") or result.get("id") or result.get("url") or "")[:200],
    ))
    await db.commit()


def _require_nonempty(value: str, field: str) -> str:
    value = (value or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail=f"'{field}' is required")
    return value


@router.get("", response_class=HTMLResponse)
async def bug_bounty_home(request: Request, user: User = Depends(_user)):
    require_feature_or_402("bug_bounty", user)
    return templates.TemplateResponse(request, "bug_bounty.html", {
        "app_name": APP_NAME, "user": user, "active": "bug_bounty",
    })


# ── HackerOne ──────────────────────────────────────────────────────────────────

@router.get("/api/hackerone/programs")
async def h1_programs(keyword: str = "", limit: int = 20, user: User = Depends(_user)):
    require_feature_or_402("bug_bounty", user)
    from modules.bug_bounty.hackerone import search_programs
    return await search_programs(keyword, limit)


@router.get("/api/hackerone/scope/{handle}")
async def h1_scope(handle: str, user: User = Depends(_user)):
    require_feature_or_402("bug_bounty", user)
    from modules.bug_bounty.hackerone import get_program_scope
    return await get_program_scope(handle)


@router.get("/api/hackerone/reports")
async def h1_reports(state: str = "all", user: User = Depends(_user)):
    require_feature_or_402("bug_bounty", user)
    from modules.bug_bounty.hackerone import get_my_reports
    return await get_my_reports(state)


@router.post("/api/hackerone/submit")
async def h1_submit(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("bug_bounty", user)
    await _enforce_submission_quota(db, user)
    data = await request.json()
    program_handle = _require_nonempty(data.get("program_handle", ""), "program_handle")
    title = _require_nonempty(data.get("title", ""), "title")[:300]
    severity = data.get("severity", "medium")

    from modules.bug_bounty.hackerone import submit_report
    result = await submit_report(
        program_handle=program_handle,
        title=title,
        vulnerability_type=data.get("vuln_type", ""),
        severity=severity,
        description=(data.get("description", "") or "")[:20000],
        impact=(data.get("impact", "") or "")[:5000],
        steps_to_reproduce=(data.get("steps", "") or "")[:20000],
    )
    await _record_submission(db, user, "hackerone", program_handle, title, severity, result)
    return result


# ── Bugcrowd ──────────────────────────────────────────────────────────────────

@router.get("/api/bugcrowd/programs")
async def bc_programs(user: User = Depends(_user)):
    require_feature_or_402("bug_bounty", user)
    from modules.bug_bounty.bugcrowd import bc_list_programs
    return await bc_list_programs()


@router.get("/api/bugcrowd/targets/{code}")
async def bc_targets(code: str, user: User = Depends(_user)):
    require_feature_or_402("bug_bounty", user)
    from modules.bug_bounty.bugcrowd import bc_get_targets
    return await bc_get_targets(code)


@router.post("/api/bugcrowd/submit")
async def bc_submit(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("bug_bounty", user)
    await _enforce_submission_quota(db, user)
    data = await request.json()
    program_code = _require_nonempty(data.get("program_code", ""), "program_code")
    title = _require_nonempty(data.get("title", ""), "title")[:300]
    severity = data.get("severity", "medium")

    from modules.bug_bounty.bugcrowd import bc_submit_report
    result = await bc_submit_report(
        program_code=program_code,
        title=title,
        description=(data.get("description", "") or "")[:20000],
        severity=severity,
        # Previously always the router-level default regardless of what a
        # caller sent -- bc_submit_report already accepted vrt_id, it was
        # just never forwarded, so every report was silently mis-tagged.
        vrt_id=data.get("vrt_id") or "server_security_misconfiguration",
    )
    await _record_submission(db, user, "bugcrowd", program_code, title, severity, result)
    return result


# ── Intigriti ─────────────────────────────────────────────────────────────────

@router.get("/api/intigriti/programs")
async def ig_programs(user: User = Depends(_user)):
    require_feature_or_402("bug_bounty", user)
    from modules.bug_bounty.bugcrowd import ig_list_programs
    return await ig_list_programs()


@router.get("/api/intigriti/program/{handle}")
async def ig_program(handle: str, user: User = Depends(_user)):
    require_feature_or_402("bug_bounty", user)
    from modules.bug_bounty.bugcrowd import ig_get_program
    return await ig_get_program(handle)


# ── CVE Pipeline ──────────────────────────────────────────────────────────────
# Moved to web/routers/cve_submission.py, mounted at /api/cve (drafting only —
# see that module's docstring for why there is no submit-to-MITRE endpoint).
