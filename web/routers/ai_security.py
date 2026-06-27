"""AI Security router — Behavioral Analysis, Zero-Day Prediction, Attack Patterns, Red Team."""

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
router = APIRouter(prefix="/ai-security", tags=["ai-security"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


# ── Behavioral Analysis ────────────────────────────────────────────────────────

@router.get("/behavioral", response_class=HTMLResponse)
async def behavioral_home(request: Request, user: User = Depends(_user)):
    from modules.ai_advanced.behavioral import analyzer
    entities = analyzer.get_all_entities()
    high_risk = analyzer.list_high_risk(0.5)
    return templates.TemplateResponse(request, "behavioral.html", {
        "app_name": APP_NAME, "user": user, "active": "behavioral",
        "entities": entities, "high_risk": high_risk,
    })


@router.post("/api/behavioral/event")
async def record_event(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.ai_advanced.behavioral import analyzer
    return analyzer.record_event(
        entity_id=data.get("entity_id", ""),
        event=data.get("event", {}),
    )


@router.get("/api/behavioral/entities")
async def list_entities(user: User = Depends(_user)):
    from modules.ai_advanced.behavioral import analyzer
    return {"entities": analyzer.get_all_entities()}


@router.get("/api/behavioral/entities/{entity_id}")
async def get_entity(entity_id: str, user: User = Depends(_user)):
    from modules.ai_advanced.behavioral import analyzer
    profile = analyzer.get_profile(entity_id)
    if not profile:
        from fastapi import HTTPException
        raise HTTPException(404, f"Entity '{entity_id}' not found")
    # Don't send full event log in response
    profile["events"] = profile["events"][-10:]
    return profile


@router.get("/api/behavioral/high-risk")
async def high_risk_entities(threshold: float = 0.5, user: User = Depends(_user)):
    from modules.ai_advanced.behavioral import analyzer
    return {"entities": analyzer.list_high_risk(threshold)}


# ── Zero-Day Prediction ───────────────────────────────────────────────────────

@router.get("/zero-day", response_class=HTMLResponse)
async def zero_day_home(request: Request, user: User = Depends(_user)):
    from modules.ai_advanced.zero_day import list_predictions
    preds = list_predictions()
    return templates.TemplateResponse(request, "zero_day.html", {
        "app_name": APP_NAME, "user": user, "active": "zero_day",
        "predictions": preds[:10],
    })


@router.post("/api/zero-day/predict")
async def predict(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.ai_advanced.zero_day import predict_zero_days
    return await predict_zero_days(
        target_software=data.get("software", ""),
        version=data.get("version", ""),
    )


@router.get("/api/zero-day/predictions")
async def get_predictions(user: User = Depends(_user)):
    from modules.ai_advanced.zero_day import list_predictions
    return {"predictions": list_predictions()}


@router.get("/api/zero-day/trending")
async def trending(user: User = Depends(_user)):
    from modules.ai_advanced.zero_day import trending_threats
    return await trending_threats()


# ── Attack Pattern Recognition ────────────────────────────────────────────────

@router.get("/attack-patterns", response_class=HTMLResponse)
async def attack_patterns_home(request: Request, user: User = Depends(_user)):
    from modules.ai_advanced.attack_patterns import get_all_patterns, pattern_history
    return templates.TemplateResponse(request, "attack_patterns.html", {
        "app_name": APP_NAME, "user": user, "active": "attack_patterns",
        "patterns": get_all_patterns(),
        "history": pattern_history()[:10],
    })


@router.post("/api/attack-patterns/analyze")
async def analyze_patterns(request: Request, user: User = Depends(_user)):
    data = await request.json()
    text = data.get("text", "")
    events = data.get("events", [])
    from modules.ai_advanced.attack_patterns import analyze_text, analyze_events
    if text:
        return analyze_text(text)
    return analyze_events(events)


@router.get("/api/attack-patterns/library")
async def pattern_library(user: User = Depends(_user)):
    from modules.ai_advanced.attack_patterns import get_all_patterns
    return {"patterns": get_all_patterns()}


@router.get("/api/attack-patterns/history")
async def get_history(user: User = Depends(_user)):
    from modules.ai_advanced.attack_patterns import pattern_history
    return {"history": pattern_history()}


# ── AI Red Team ───────────────────────────────────────────────────────────────

@router.get("/red-team", response_class=HTMLResponse)
async def red_team_home(request: Request, user: User = Depends(_user)):
    from modules.ai_advanced.red_team import list_engagements, get_technique_library, ATTACK_CATEGORIES
    return templates.TemplateResponse(request, "red_team.html", {
        "app_name": APP_NAME, "user": user, "active": "red_team",
        "engagements": list_engagements()[:10],
        "categories": ATTACK_CATEGORIES,
        "technique_library": get_technique_library(),
    })


@router.post("/api/red-team/engagements")
async def create_engagement(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.ai_advanced.red_team import create_engagement as _create
    return await _create(
        target=data.get("target", ""),
        scope=data.get("scope", []),
        objectives=data.get("objectives", []),
        categories=data.get("categories", ["reconnaissance", "web_application"]),
        rules_of_engagement=data.get("roe", ""),
    )


@router.get("/api/red-team/engagements")
async def list_engagements_api(user: User = Depends(_user)):
    from modules.ai_advanced.red_team import list_engagements
    return {"engagements": list_engagements()}


@router.get("/api/red-team/engagements/{engagement_id}")
async def get_engagement_api(engagement_id: str, user: User = Depends(_user)):
    from modules.ai_advanced.red_team import get_engagement
    eng = get_engagement(engagement_id)
    if not eng:
        from fastapi import HTTPException
        raise HTTPException(404, f"Engagement {engagement_id} not found")
    return eng


@router.post("/api/red-team/engagements/{engagement_id}/findings")
async def log_finding(engagement_id: str, request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.ai_advanced.red_team import log_finding as _log
    return await _log(engagement_id, data)
