"""IOC Correlation Engine — web router."""
import asyncio

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/correlations", tags=["correlations"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def correlations_page(request: Request, user: User = Depends(_user)):
    from modules.ioc_correlation import load_cached, run_correlation

    data = load_cached()
    if not data:
        data = await asyncio.to_thread(run_correlation, True)

    return templates.TemplateResponse(request, "correlations.html", {
        "app_name": APP_NAME,
        "user": user,
        "active": "correlations",
        "data": data,
    })
