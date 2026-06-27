"""AI Firewall router — DPI, ML anomaly detection, rate limiting."""

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
router = APIRouter(prefix="/firewall", tags=["firewall"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def firewall_home(request: Request, user: User = Depends(_user)):
    from modules.firewall.ai_firewall import get_firewall_rules
    return templates.TemplateResponse(request, "firewall.html", {
        "app_name": APP_NAME, "user": user, "active": "firewall",
        "rules": get_firewall_rules(),
    })


@router.post("/api/inspect")
async def inspect_request_api(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.firewall.ai_firewall import inspect_request
    return inspect_request(
        method=data.get("method", "GET"),
        path=data.get("path", "/"),
        headers=data.get("headers", {}),
        body=data.get("request_body", ""),
        ip=data.get("ip", ""),
    )


@router.post("/api/analyze-logs")
async def analyze_logs(request: Request, user: User = Depends(_user)):
    data = await request.json()
    lines = data.get("logs", [])
    if isinstance(lines, str):
        lines = lines.strip().split("\n")
    from modules.firewall.ai_firewall import analyze_log_sample
    return await analyze_log_sample(lines)


@router.get("/api/rules")
async def get_rules(user: User = Depends(_user)):
    from modules.firewall.ai_firewall import get_firewall_rules
    return {"rules": get_firewall_rules()}


@router.post("/api/rate-check")
async def rate_check(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.firewall.ai_firewall import check_rate_limit
    return check_rate_limit(
        ip=data.get("ip", ""),
        window_seconds=data.get("window_seconds", 60),
        max_requests=data.get("max_requests", 100),
    )
