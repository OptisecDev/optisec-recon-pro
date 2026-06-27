"""Compliance Checker router — ISO 27001, NIST CSF, GDPR, PCI-DSS."""

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from config import APP_NAME

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
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
    return await assess_target(
        target_url=data.get("target_url", ""),
        framework=data.get("framework", "nist"),
        answers=data.get("answers", {}),
    )


@router.post("/api/probe")
async def probe_target(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.compliance.checker import auto_probe_target
    return await auto_probe_target(data.get("target_url", ""))
