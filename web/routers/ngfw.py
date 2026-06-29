"""Next-Gen Firewall v2 router."""
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/ngfw", tags=["ngfw"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def ngfw_home(request: Request, user: User = Depends(_user)):
    from modules.firewall.ngfw_v2 import get_traffic_stats, get_geo_block_list, DPI_SIGNATURES
    return templates.TemplateResponse(request, "ngfw.html", {
        "app_name": APP_NAME, "user": user, "active": "ngfw",
        "stats": get_traffic_stats(),
        "geo_blocks": get_geo_block_list(),
        "dpi_rules": DPI_SIGNATURES[:10],
    })


@router.post("/api/inspect")
async def inspect(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.firewall.ngfw_v2 import deep_inspect
    return deep_inspect(
        method=data.get("method", "GET"),
        path=data.get("path", "/"),
        headers=data.get("headers", {}),
        body=data.get("body", ""),
        src_ip=data.get("src_ip", "127.0.0.1"),
        dst_port=int(data.get("dst_port", 80)),
        protocol=data.get("protocol", "HTTP"),
    )


@router.get("/api/stats")
async def traffic_stats(user: User = Depends(_user)):
    from modules.firewall.ngfw_v2 import get_traffic_stats
    return get_traffic_stats()


@router.post("/api/simulate-traffic")
async def simulate_traffic(request: Request, user: User = Depends(_user)):
    data = await request.json()
    n = min(int(data.get("count", 20)), 50)
    from modules.firewall.ngfw_v2 import simulate_traffic_burst
    results = simulate_traffic_burst(n)
    return {"results": results, "count": len(results)}


@router.get("/api/geo-blocks")
async def geo_blocks(user: User = Depends(_user)):
    from modules.firewall.ngfw_v2 import get_geo_block_list
    return get_geo_block_list()


@router.get("/api/rules")
async def get_rules(user: User = Depends(_user)):
    from modules.firewall.ngfw_v2 import DPI_SIGNATURES
    return {"rules": DPI_SIGNATURES, "total": len(DPI_SIGNATURES)}
