"""Compliance Checker router — ISO 27001, NIST CSF, GDPR, PCI-DSS."""

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/compliance", tags=["compliance"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def compliance_home(request: Request, user: User = Depends(_user)):
    from modules.compliance.checker import get_frameworks
    return templates.TemplateResponse(request, "compliance.html", {
        "app_name": APP_NAME, "user": user, "active": "compliance",
        "frameworks": get_frameworks(),
    })


@router.get("/api/frameworks")
async def list_frameworks(user: User = Depends(_user)):
    from modules.compliance.checker import get_frameworks
    return get_frameworks()


@router.get("/api/frameworks/{framework}/controls")
async def framework_controls(framework: str, user: User = Depends(_user)):
    from modules.compliance.checker import get_framework_controls
    controls = get_framework_controls(framework)
    if not controls:
        from fastapi import HTTPException
        raise HTTPException(404, f"Framework '{framework}' not found")
    return {"framework": framework, "controls": controls}


@router.post("/api/assess")
async def assess(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.compliance.checker import assess_target
    target = data.get("target_url") or data.get("target", "")
    return await assess_target(
        target_url=target,
        framework=data.get("framework", "nist"),
        answers=data.get("answers", {}),
    )


@router.post("/api/probe")
async def probe_target(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.compliance.checker import auto_probe_target
    target = data.get("target_url") or data.get("target", "")
    return await auto_probe_target(target)
