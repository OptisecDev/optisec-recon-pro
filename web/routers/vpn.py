"""WireGuard VPN router."""

from fastapi import APIRouter, Request, Depends, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path

from web.database import get_db
from web.models import User
from web.auth import get_current_user, require_admin
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/vpn", tags=["vpn"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


async def _admin(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    user = await get_current_user(request, db)
    require_admin(user)
    return user


@router.get("", response_class=HTMLResponse)
async def vpn_home(request: Request, user: User = Depends(_user)):
    from modules.vpn.wireguard import list_peers, get_wg_status
    peers = list_peers()
    status = await get_wg_status()
    return templates.TemplateResponse(request, "vpn.html", {
        "app_name": APP_NAME, "user": user, "active": "vpn",
        "peers": peers, "wg_status": status,
    })


@router.get("/api/status")
async def vpn_status(user: User = Depends(_user)):
    from modules.vpn.wireguard import get_wg_status
    return await get_wg_status()


@router.get("/api/peers")
async def list_peers_api(user: User = Depends(_user)):
    from modules.vpn.wireguard import list_peers
    return {"peers": list_peers()}


@router.post("/api/peers")
async def add_peer_api(request: Request, user: User = Depends(_admin)):
    data = await request.json()
    from modules.vpn.wireguard import add_peer
    return add_peer(
        name=data.get("name", ""),
        endpoint=data.get("endpoint", "YOUR_SERVER_IP"),
        port=data.get("port", 51820),
    )


@router.delete("/api/peers/{name}")
async def remove_peer_api(name: str, user: User = Depends(_admin)):
    from modules.vpn.wireguard import remove_peer
    return remove_peer(name)


@router.get("/api/peers/{name}/config")
async def peer_config(name: str, user: User = Depends(_admin)):
    from pathlib import Path
    config_path = Path(f"data/wireguard/{name}.conf")
    if not config_path.exists():
        from fastapi import HTTPException
        raise HTTPException(404, "Peer config not found")
    return PlainTextResponse(config_path.read_text(), media_type="text/plain")


@router.get("/api/peers/{name}/qr")
async def peer_qr(name: str, user: User = Depends(_admin)):
    from modules.vpn.wireguard import generate_qr_code
    qr = generate_qr_code(name)
    if not qr:
        return {"qr": None, "note": "Install qrcode[pil] package for QR support"}
    return {"qr": qr, "format": "base64_png"}


@router.post("/api/server/generate")
async def generate_server_config_api(request: Request, user: User = Depends(_admin)):
    data = await request.json()
    from modules.vpn.wireguard import generate_server_config
    result = generate_server_config(
        endpoint=data.get("endpoint", "YOUR_SERVER_IP"),
        port=data.get("port", 51820),
    )
    # Don't expose private key in response
    result.pop("config", None)
    return result
