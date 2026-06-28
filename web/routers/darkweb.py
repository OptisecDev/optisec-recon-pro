"""Dark Web Intelligence router."""
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
router = APIRouter(prefix="/darkweb", tags=["darkweb"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def darkweb_home(request: Request, user: User = Depends(_user)):
    from modules.darkweb.intelligence import simulate_tor_monitor, get_monitored_keywords, get_breach_intelligence
    return templates.TemplateResponse(request, "darkweb.html", {
        "app_name": APP_NAME, "user": user, "active": "darkweb",
        "tor_monitor": simulate_tor_monitor(),
        "keywords": get_monitored_keywords(),
        "breach_intel": get_breach_intelligence(),
    })


@router.post("/api/check-domain")
async def check_domain(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.darkweb.intelligence import check_domain_breach
    return check_domain_breach(data.get("domain", ""))


@router.post("/api/check-email")
async def check_email(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.darkweb.intelligence import check_email_breach
    return check_email_breach(data.get("email", ""))


@router.post("/api/scan-paste")
async def scan_paste(request: Request, user: User = Depends(_user)):
    data = await request.json()
    content = data.get("content", "")
    if not content.strip():
        return {"error": "No content provided"}
    from modules.darkweb.intelligence import scan_paste_content
    return scan_paste_content(content)


@router.post("/api/add-keyword")
async def add_keyword(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.darkweb.intelligence import add_keyword_alert
    return add_keyword_alert(
        keyword=data.get("keyword", ""),
        category=data.get("category", "general"),
    )


@router.get("/api/keywords")
async def get_keywords(user: User = Depends(_user)):
    from modules.darkweb.intelligence import get_monitored_keywords
    return {"keywords": get_monitored_keywords()}


@router.post("/api/threat-report")
async def threat_report(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.darkweb.intelligence import generate_threat_report
    return generate_threat_report(data.get("domain", ""))


@router.get("/api/tor-monitor")
async def tor_monitor(user: User = Depends(_user)):
    from modules.darkweb.intelligence import simulate_tor_monitor
    return simulate_tor_monitor()


@router.get("/api/breach-intel")
async def breach_intel(user: User = Depends(_user)):
    from modules.darkweb.intelligence import get_breach_intelligence
    return get_breach_intelligence()
