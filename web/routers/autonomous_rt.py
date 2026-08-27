"""Autonomous Red Team Engine router."""
from fastapi import APIRouter, Request, Depends, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, Target
from web.auth import get_current_user, require_analyst_or_admin
from web.license import require_feature_or_402
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/autonomous-redteam", tags=["autonomous_redteam"])


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
    require_feature_or_402("autonomous_redteam")
    from modules.ai_advanced.autonomous_redteam import list_sessions, get_payload_library, ATTACK_PHASES
    targets = (await db.execute(
        select(Target).where(Target.user_id == user.id).order_by(Target.created_at.desc())
    )).scalars().all()
    return templates.TemplateResponse(request, "autonomous_redteam.html", {
        "app_name": APP_NAME, "user": user, "active": "autonomous_rt",
        "sessions": list_sessions()[:10],
        "payload_library": get_payload_library(),
        "attack_phases": ATTACK_PHASES,
        "targets": targets,
    })


@router.post("/api/start")
async def start_simulation(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("autonomous_redteam")
    data = await request.json()
    try:
        target_id = int(data.get("target_id"))
    except (TypeError, ValueError):
        raise HTTPException(400, "target_id is required")
    target = await check_target_ownership(target_id, user, db)
    from modules.ai_advanced.autonomous_redteam import start_autonomous_simulation
    session = await start_autonomous_simulation(
        target=target.url,
        attack_types=data.get("attack_types", ["web"]),
        stealth_level=data.get("stealth_level", "medium"),
        auto_exploit=data.get("auto_exploit", False),
    )
    return session


@router.get("/api/sessions")
async def list_sessions(user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam")
    from modules.ai_advanced.autonomous_redteam import list_sessions
    return {"sessions": list_sessions()}


@router.get("/api/sessions/{session_id}")
async def get_session(session_id: str, user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam")
    from modules.ai_advanced.autonomous_redteam import get_session
    session = get_session(session_id)
    if not session:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/api/payload-library")
async def payload_library(user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam")
    from modules.ai_advanced.autonomous_redteam import get_payload_library
    return get_payload_library()


@router.get("/api/attack-phases")
async def attack_phases(user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam")
    from modules.ai_advanced.autonomous_redteam import ATTACK_PHASES
    return {"phases": ATTACK_PHASES}


@router.post("/api/generate-report/{session_id}")
async def generate_report(session_id: str, user: User = Depends(_user)):
    require_feature_or_402("autonomous_redteam")
    from modules.ai_advanced.autonomous_redteam import get_session, generate_pentest_report
    session = get_session(session_id)
    if not session:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Session not found")
    return generate_pentest_report(session)
