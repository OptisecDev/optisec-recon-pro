"""Bug Bounty router — HackerOne, Bugcrowd, Intigriti, CVE Pipeline."""

from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/bug-bounty", tags=["bug-bounty"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def bug_bounty_home(request: Request, user: User = Depends(_user)):
    return templates.TemplateResponse(request, "bug_bounty.html", {
        "app_name": APP_NAME, "user": user, "active": "bug_bounty",
    })


# ── HackerOne ──────────────────────────────────────────────────────────────────

@router.get("/api/hackerone/programs")
async def h1_programs(keyword: str = "", limit: int = 20, user: User = Depends(_user)):
    from modules.bug_bounty.hackerone import search_programs
    return await search_programs(keyword, limit)


@router.get("/api/hackerone/scope/{handle}")
async def h1_scope(handle: str, user: User = Depends(_user)):
    from modules.bug_bounty.hackerone import get_program_scope
    return await get_program_scope(handle)


@router.get("/api/hackerone/reports")
async def h1_reports(state: str = "all", user: User = Depends(_user)):
    from modules.bug_bounty.hackerone import get_my_reports
    return await get_my_reports(state)


@router.post("/api/hackerone/submit")
async def h1_submit(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.bug_bounty.hackerone import submit_report
    return await submit_report(
        program_handle=data.get("program_handle", ""),
        title=data.get("title", ""),
        vulnerability_type=data.get("vuln_type", ""),
        severity=data.get("severity", "medium"),
        description=data.get("description", ""),
        impact=data.get("impact", ""),
        steps_to_reproduce=data.get("steps", ""),
    )


# ── Bugcrowd ──────────────────────────────────────────────────────────────────

@router.get("/api/bugcrowd/programs")
async def bc_programs(user: User = Depends(_user)):
    from modules.bug_bounty.bugcrowd import bc_list_programs
    return await bc_list_programs()


@router.get("/api/bugcrowd/targets/{code}")
async def bc_targets(code: str, user: User = Depends(_user)):
    from modules.bug_bounty.bugcrowd import bc_get_targets
    return await bc_get_targets(code)


@router.post("/api/bugcrowd/submit")
async def bc_submit(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.bug_bounty.bugcrowd import bc_submit_report
    return await bc_submit_report(
        program_code=data.get("program_code", ""),
        title=data.get("title", ""),
        description=data.get("description", ""),
        severity=data.get("severity", "medium"),
    )


# ── Intigriti ─────────────────────────────────────────────────────────────────

@router.get("/api/intigriti/programs")
async def ig_programs(user: User = Depends(_user)):
    from modules.bug_bounty.bugcrowd import ig_list_programs
    return await ig_list_programs()


@router.get("/api/intigriti/program/{handle}")
async def ig_program(handle: str, user: User = Depends(_user)):
    from modules.bug_bounty.bugcrowd import ig_get_program
    return await ig_get_program(handle)


# ── CVE Pipeline ──────────────────────────────────────────────────────────────
# Moved to web/routers/cve_submission.py, mounted at /api/cve (drafting only —
# see that module's docstring for why there is no submit-to-MITRE endpoint).
