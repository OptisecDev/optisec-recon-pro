"""Federated Scanning router."""

from fastapi import APIRouter, Request, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from web.database import get_db
from web.models import User
from web.auth import get_current_user, require_admin
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/federation", tags=["federation"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


async def _admin(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    user = await get_current_user(request, db)
    require_admin(user)
    return user


@router.get("", response_class=HTMLResponse)
async def federation_home(request: Request, user: User = Depends(_user)):
    from modules.federation.federated_scan import list_nodes, list_tasks, get_this_node
    return templates.TemplateResponse(request, "federation.html", {
        "app_name": APP_NAME, "user": user, "active": "federation",
        "nodes": list_nodes(),
        "tasks": list_tasks()[:20],
        "this_node": get_this_node(),
    })


@router.get("/api/this-node")
async def this_node(user: User = Depends(_user)):
    from modules.federation.federated_scan import get_this_node
    return get_this_node() or {"status": "not_initialized"}


@router.post("/api/initialize")
async def initialize_node(request: Request, user: User = Depends(_admin)):
    data = await request.json()
    from modules.federation.federated_scan import initialize_node as _init
    result = _init(
        name=data.get("name", "OptiSec Node"),
        endpoint=data.get("endpoint", ""),
        capabilities=data.get("capabilities", ["recon", "vuln", "osint"]),
        region=data.get("region", "default"),
    )
    # Don't expose API key
    safe = {k: v for k, v in result.items() if k != "api_key"}
    return safe


@router.get("/api/nodes")
async def list_nodes_api(user: User = Depends(_user)):
    from modules.federation.federated_scan import list_nodes
    return {"nodes": list_nodes()}


@router.post("/api/nodes")
async def register_node(request: Request, user: User = Depends(_admin)):
    data = await request.json()
    from modules.federation.federated_scan import register_peer
    return register_peer(
        name=data.get("name", ""),
        endpoint=data.get("endpoint", ""),
        api_key=data.get("api_key", ""),
        capabilities=data.get("capabilities", ["recon"]),
        region=data.get("region", "remote"),
    )


@router.delete("/api/nodes/{node_id}")
async def remove_node(node_id: str, user: User = Depends(_admin)):
    from modules.federation.federated_scan import remove_node as _remove
    return _remove(node_id)


@router.post("/api/nodes/{node_id}/ping")
async def ping_node_api(node_id: str, user: User = Depends(_user)):
    from modules.federation.federated_scan import ping_node
    return await ping_node(node_id)


@router.post("/api/nodes/ping-all")
async def ping_all_api(user: User = Depends(_user)):
    from modules.federation.federated_scan import ping_all_nodes
    return {"results": await ping_all_nodes()}


@router.post("/api/scan")
async def dispatch_scan(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.federation.federated_scan import dispatch_scan as _dispatch
    return await _dispatch(
        target=data.get("target", ""),
        scan_types=data.get("scan_types", ["recon"]),
        strategy=data.get("strategy", "parallel"),
        preferred_regions=data.get("regions"),
    )


@router.get("/api/tasks")
async def list_tasks_api(user: User = Depends(_user)):
    from modules.federation.federated_scan import list_tasks
    return {"tasks": list_tasks()}


@router.get("/api/tasks/{task_id}/results")
async def get_results(task_id: str, user: User = Depends(_user)):
    from modules.federation.federated_scan import collect_results
    return await collect_results(task_id)


# ── Federation API (called by peer nodes) ─────────────────────────────────────

@router.get("/api/federation/ping")
async def federation_ping(x_federation_key: Optional[str] = Header(None)):
    from modules.federation.federated_scan import get_this_node, _node_key
    node_key = _node_key()
    if x_federation_key != node_key:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    node = get_this_node()
    return {"status": "online", "node": node.get("name") if node else "unknown",
            "version": "2.0", "timestamp": __import__("datetime").datetime.utcnow().isoformat()}


@router.post("/api/federation/execute")
async def federation_execute(request: Request, x_federation_key: Optional[str] = Header(None)):
    from modules.federation.federated_scan import _node_key
    if x_federation_key != _node_key():
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    data = await request.json()
    return {
        "task_id": data.get("task_id"),
        "status": "accepted",
        "target": data.get("target"),
        "scan_types": data.get("scan_types"),
    }
