"""Autonomous Red Team Engine router."""
import os

from fastapi import APIRouter, Request, Depends, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, Target
from web.auth import get_current_user, require_analyst_or_admin
from web.domain_verification import check_scan_authorization, denial_response
from web.license import require_feature_or_402
from web.rate_limit import rate_limiter
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/autonomous-redteam", tags=["autonomous_redteam"])

# start_autonomous_simulation() calls Groq under GROQ_API_KEY -- one
# instance-wide credential, not per-user (same shape as the fixes in
# web/routers/{bug_bounty,ai_security,osint}.py) -- and also runs real,
# expensive scanners (nmap, port scan, XSS/SQLi/SSRF) for Phases 1/3.
# Scan authorization (web/scan_authz.py) keeps this off infrastructure the
# user hasn't verified, but a single account could still flood the scan
# pipeline and the shared Groq quota with repeat calls.
_start_simulation_limiter = rate_limiter(
    "autonomous_rt_start", lambda: int(os.environ.get("RATE_LIMIT_AUTONOMOUS_RT_START", "5")), 60,
)


# What start_autonomous_simulation() really runs: _run_recon_phase() always,
# _run_web_scan_phase() only when phase 3 is selected
# (modules/ai_advanced/autonomous_redteam.py).
_RECON_PHASE_CHECKS = ("ports", "subdomain", "whois", "dns", "nmap")
_WEB_PHASE_CHECKS = ("xss", "sqli")


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


async def check_target_ownership(target_id: int, user: User, db: AsyncSession) -> Target:
    """Verify target_id refers to a Target row owned by user, mirroring the
    ownership check in web/app.py's /api/scan (Target.id + Target.user_id)."""
    target = (await db.execute(
        select(Target).where(Target.id == target_id, Target.user_id == user.id)
    )).scalar_one_or_none()
    if not target:
        raise HTTPException(
            404,
            "Target not found. Register it via the Targets page before starting a red team session.",
        )
    return target


@router.get("", response_class=HTMLResponse)
async def art_home(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("autonomous_redteam", user)
    from modules.ai_advanced.autonomous_redteam import list_sessions, get_payload_library, ATTACK_PHASES
    targets = (await db.execute(
        select(Target).where(Target.user_id == user.id).order_by(Target.created_at.desc())
    )).scalars().all()
    own_sessions = [s for s in list_sessions() if _owns_session(s, user)]
    return templates.TemplateResponse(request, "autonomous_redteam.html", {
        "app_name": APP_NAME, "user": user, "active": "autonomous_rt",
        "sessions": own_sessions[:10],
        "payload_library": get_payload_library(),
        "attack_phases": ATTACK_PHASES,
        "targets": targets,
    })


@router.post("/api/start", dependencies=[Depends(_start_simulation_limiter)])
async def start_simulation(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("autonomous_redteam", user)
    data = await request.json()
    try:
        target_id = int(data.get("target_id"))
    except (TypeError, ValueError):
        raise HTTPException(400, "target_id is required")
    target = await check_target_ownership(target_id, user, db)
    attack_types = data.get("attack_types", ["web"])
    if not isinstance(attack_types, list) or not all(isinstance(a, str) for a in attack_types):
        raise HTTPException(400, "attack_types must be a list of strings")
    from modules.ai_advanced.autonomous_redteam import start_autonomous_simulation, _select_phases
    # Owning the Target row only proves the user typed the URL in; the real
    # recon/web-scan phases still need scan authorization for it.
    checks = list(_RECON_PHASE_CHECKS)
    if any(p["phase"] == 3 for p in _select_phases(attack_types)):
        checks += _WEB_PHASE_CHECKS
    decision = await check_scan_authorization(db, user, target.url, checks, source="autonomous_rt_start")
    if not decision.ok:
        return denial_response(decision)
    session = await start_autonomous_simulation(
        target=target.url,
        attack_types=attack_types,
        stealth_level=data.get("stealth_level", "medium"),
        auto_exploit=data.get("auto_exploit", False),
        user_id=user.id,
    )
    return session


def _owns_session(session: dict, user: User) -> bool:
    return user.role == "admin" or session.get("user_id") == user.id


@router.get("/api/sessions")
async def list_sessions(user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam", user)
    from modules.ai_advanced.autonomous_redteam import list_sessions
    sessions = [s for s in list_sessions() if _owns_session(s, user)]
    return {"sessions": sessions}


@router.get("/api/sessions/{session_id}")
async def get_session(session_id: str, user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam", user)
    from modules.ai_advanced.autonomous_redteam import get_session
    session = get_session(session_id)
    if not session or not _owns_session(session, user):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/api/payload-library")
async def payload_library(user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam", user)
    from modules.ai_advanced.autonomous_redteam import get_payload_library
    return get_payload_library()


@router.get("/api/attack-phases")
async def attack_phases(user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam", user)
    from modules.ai_advanced.autonomous_redteam import ATTACK_PHASES
    return {"phases": ATTACK_PHASES}


@router.post("/api/generate-report/{session_id}")
async def generate_report(session_id: str, user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam", user)
    from modules.ai_advanced.autonomous_redteam import get_session, generate_pentest_report
    session = get_session(session_id)
    if not session or not _owns_session(session, user):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Session not found")
    return generate_pentest_report(session)
