"""Global Threat Intelligence Feed router — with live AlienVault OTX integration."""
import asyncio
import logging
from datetime import datetime

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from config import APP_NAME, OTX_API_KEY

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router = APIRouter(prefix="/threat-feed", tags=["threat_feed"])
logger = logging.getLogger(__name__)


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _build_feed(otx_iocs: list, fallback_feed: dict) -> dict:
    """Merge OTX real data with the existing feed structure."""
    if otx_iocs:
        iocs = otx_iocs
    else:
        iocs = fallback_feed.get("iocs", [])

    critical = sum(1 for i in iocs if i.get("threat_score", 0) >= 80)
    high = sum(1 for i in iocs if 65 <= i.get("threat_score", 0) < 80)
    medium = sum(1 for i in iocs if 40 <= i.get("threat_score", 0) < 65)

    avg = sum(i.get("threat_score", 0) for i in iocs) / max(len(iocs), 1)
    if avg >= 80:
        level = "CRITICAL"
    elif avg >= 65:
        level = "HIGH"
    elif avg >= 45:
        level = "ELEVATED"
    else:
        level = "GUARDED"

    by_type: dict = {}
    by_source: dict = {}
    for ioc in iocs:
        t = ioc.get("type", "unknown")
        s = ioc.get("source", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
        by_source[s] = by_source.get(s, 0) + 1

    return {
        "iocs": iocs,
        "total": len(iocs),
        "otx_live": bool(otx_iocs),
        "global_threat_level": level,
        "updated_at": datetime.utcnow().isoformat(),
        "stats": {
            "critical_iocs": critical,
            "high_iocs": high,
            "medium_iocs": medium,
            "by_type": by_type,
            "by_source": by_source,
        },
        "feed_sources": fallback_feed.get("feed_sources", []),
    }


@router.get("", response_class=HTMLResponse)
async def feed_home(request: Request, user: User = Depends(_user)):
    from modules.threat_intel.global_feed import get_live_ioc_feed, get_threat_map, get_campaigns, get_feed_stats

    fallback = get_live_ioc_feed(30)
    otx_iocs: list = []

    if OTX_API_KEY:
        try:
            from modules.threat_intel.otx_feed import fetch_otx_pulses
            otx_iocs = await asyncio.to_thread(fetch_otx_pulses, OTX_API_KEY, 50)
        except Exception as exc:
            logger.warning("OTX fetch failed, using fallback: %s", exc)

    feed = _build_feed(otx_iocs, fallback)

    return templates.TemplateResponse(request, "threat_feed.html", {
        "app_name": APP_NAME,
        "user": user,
        "active": "threat_feed",
        "feed": feed,
        "threat_map": get_threat_map(),
        "campaigns": get_campaigns(),
        "stats": get_feed_stats(),
        "otx_connected": bool(OTX_API_KEY and otx_iocs),
    })


@router.get("/api/feed")
async def live_feed(limit: int = 50, user: User = Depends(_user)):
    from modules.threat_intel.global_feed import get_live_ioc_feed

    fallback = get_live_ioc_feed(min(limit, 100))
    otx_iocs: list = []

    if OTX_API_KEY:
        try:
            from modules.threat_intel.otx_feed import fetch_otx_pulses
            otx_iocs = await asyncio.to_thread(fetch_otx_pulses, OTX_API_KEY, min(limit, 100))
        except Exception as exc:
            logger.warning("OTX fetch failed: %s", exc)

    return _build_feed(otx_iocs, fallback)


@router.get("/api/otx/test")
async def otx_test(user: User = Depends(_user)):
    """Test AlienVault OTX API connectivity."""
    if not OTX_API_KEY:
        return JSONResponse({"connected": False, "error": "OTX_API_KEY not configured"}, status_code=400)
    from modules.threat_intel.otx_feed import test_otx_connection
    result = await asyncio.to_thread(test_otx_connection, OTX_API_KEY)
    return JSONResponse(result)


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
    stats = get_feed_stats()
    stats["otx_configured"] = bool(OTX_API_KEY)
    return stats
