"""Global Threat Intelligence Feed router."""
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
router = APIRouter(prefix="/threat-feed", tags=["threat_feed"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def feed_home(request: Request, user: User = Depends(_user)):
    from modules.threat_intel.global_feed import get_live_ioc_feed, get_threat_map, get_campaigns, get_feed_stats
    return templates.TemplateResponse(request, "threat_feed.html", {
        "app_name": APP_NAME, "user": user, "active": "threat_feed",
        "feed": get_live_ioc_feed(30),
        "threat_map": get_threat_map(),
        "campaigns": get_campaigns(),
        "stats": get_feed_stats(),
    })


@router.get("/api/feed")
async def live_feed(limit: int = 50, user: User = Depends(_user)):
    from modules.threat_intel.global_feed import get_live_ioc_feed
    return get_live_ioc_feed(min(limit, 100))


@router.get("/api/threat-map")
async def threat_map(user: User = Depends(_user)):
    from modules.threat_intel.global_feed import get_threat_map
    return get_threat_map()


@router.get("/api/campaigns")
async def get_campaigns(user: User = Depends(_user)):
    from modules.threat_intel.global_feed import get_campaigns
    return {"campaigns": get_campaigns()}


@router.post("/api/submit-ioc")
async def submit_ioc(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.threat_intel.global_feed import submit_ioc
    return submit_ioc(
        ioc_type=data.get("type", "ip"),
        value=data.get("value", ""),
        malware=data.get("malware", "unknown"),
        confidence=int(data.get("confidence", 70)),
        tlp=data.get("tlp", "AMBER"),
    )


@router.post("/api/correlate")
async def correlate(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.threat_intel.global_feed import correlate_iocs
    return correlate_iocs(data.get("iocs", []))


@router.get("/api/stats")
async def feed_stats(user: User = Depends(_user)):
    from modules.threat_intel.global_feed import get_feed_stats
    return get_feed_stats()
