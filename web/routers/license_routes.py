"""Per-user SaaS license-key redemption — sold as SellApp "Unique Codes"
(see generate_licenses_admin.py for issuance). Independent of the
instance-wide signed-license engine in web/license.py: that engine gates
features for a whole self-hosted deployment via a single global key; this
router lets one authenticated account redeem a one-time key to upgrade its
own User.subscription_tier. Mounted at /api/subscription rather than
/api/license to avoid colliding with the existing /api/license/* routes in
web/app.py.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, LicenseKey
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME
from license_utils import hash_license_key

router = APIRouter(prefix="/api/subscription", tags=["subscription"])
page_router = APIRouter(tags=["subscription"])

_REDEEM_ERROR = "Invalid or already-redeemed license key"


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


class RedeemRequest(BaseModel):
    license_key: str


class RedeemResponse(BaseModel):
    success: bool
    tier: str


class StatusResponse(BaseModel):
    subscription_tier: str


@router.post("/redeem", response_model=RedeemResponse)
async def redeem_license(
    body: RedeemRequest,
    user: User = Depends(_user),
    db: AsyncSession = Depends(get_db),
):
    key_hash = hash_license_key(body.license_key.strip())

    result = await db.execute(
        select(LicenseKey).where(LicenseKey.key_hash == key_hash)
    )
    license_key = result.scalar_one_or_none()

    if license_key is None or license_key.redeemed_by is not None:
        raise HTTPException(status_code=400, detail=_REDEEM_ERROR)

    license_key.redeemed_by = user.id
    license_key.redeemed_at = datetime.utcnow()
    user.subscription_tier = license_key.tier
    await db.commit()

    return RedeemResponse(success=True, tier=license_key.tier)


@router.get("/status", response_model=StatusResponse)
async def subscription_status(user: User = Depends(_user)):
    return StatusResponse(subscription_tier=user.subscription_tier)


# ── Redeem page ─────────────────────────────────────────────────────────────
# Separate from /license (web/app.py) on purpose: that page activates the
# instance-wide OPS4-{TIER}-{payload}.{sig} signed engine, not a per-user
# SellApp key. Redeeming here only ever calls POST /api/subscription/redeem
# above, which upgrades this account's User.subscription_tier.

@page_router.get("/redeem", response_class=HTMLResponse, include_in_schema=False)
async def redeem_page(request: Request, user: User = Depends(_user)):
    return templates.TemplateResponse(request, "redeem.html", {
        "app_name": APP_NAME, "user": user, "active": "redeem",
    })
