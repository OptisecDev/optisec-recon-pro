"""MITRE ATT&CK Navigator router."""
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
router = APIRouter(prefix="/attack-navigator", tags=["attack_navigator"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def navigator_home(request: Request, user: User = Depends(_user)):
    from modules.threat_intel.attack_navigator import get_full_matrix, get_apt_profiles, get_ioc_types
    return templates.TemplateResponse(request, "attack_navigator.html", {
        "app_name": APP_NAME, "user": user, "active": "attack_navigator",
        "matrix": get_full_matrix(),
        "apt_groups": get_apt_profiles(),
        "ioc_types": get_ioc_types(),
    })


@router.get("/api/matrix")
async def get_matrix(user: User = Depends(_user)):
    from modules.threat_intel.attack_navigator import get_full_matrix
    return get_full_matrix()


@router.get("/api/apt-profiles")
async def get_apt_profiles(user: User = Depends(_user)):
    from modules.threat_intel.attack_navigator import get_apt_profiles
    return {"groups": get_apt_profiles()}


@router.post("/api/detect-iocs")
async def detect_iocs(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.threat_intel.attack_navigator import detect_techniques_in_iocs
    return detect_techniques_in_iocs(data.get("iocs", []))


@router.post("/api/add-detection")
async def add_detection(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.threat_intel.attack_navigator import add_detection
    return add_detection(
        technique_id=data.get("technique_id", ""),
        confidence=int(data.get("confidence", 75)),
        source=data.get("source", "manual"),
        details=data.get("details", ""),
    )


@router.get("/api/detections")
async def get_detections(user: User = Depends(_user)):
    from modules.threat_intel.attack_navigator import get_detections, get_detections, get_matrix_coverage
    detections = get_detections(100)
    coverage = get_matrix_coverage(detections)
    return {"detections": detections, "coverage": coverage}


@router.get("/api/ioc-types")
async def ioc_types(user: User = Depends(_user)):
    from modules.threat_intel.attack_navigator import get_ioc_types
    return {"types": get_ioc_types()}
