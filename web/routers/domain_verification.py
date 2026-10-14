"""Domain verification API -- users prove they control a domain so active
scan checks are allowed against it (web/scan_authz.py,
web/domain_verification.py).

    POST   /api/domains/verify       {domain, method} -> record + instructions
    POST   /api/domains/{id}/check   run the DNS/file check now
    GET    /api/domains              the caller's own records
    DELETE /api/domains/{id}         remove one

Every lookup is scoped to the caller's user_id, so another user's record is
a 404, never a 403. Mutations need analyst/admin, and -- for cookie-
authenticated requests only -- the same double-submit CSRF token as
DELETE /targets/{id}. X-API-Key and Bearer clients skip CSRF: a browser
can't attach those headers to a cross-site request.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from web.auth import get_current_user, require_analyst_or_admin, verify_csrf_token
from web.database import get_db
from web.domain_verification import (
    STATUS_PENDING, VERIFY_METHODS, instructions, new_token, run_check, validate_domain,
)
from web.models import DomainVerification, User
from web.rate_limit import rate_limiter

router = APIRouter(prefix="/api/domains", tags=["Domain Verification"])

# Same cookie as web/app.py's CSRF_COOKIE_NAME (routers can't import web.app
# without a cycle); tests/test_domain_verification_router.py pins the two
# together.
CSRF_COOKIE_NAME = "csrf_secret"

# Caps table growth from a scripted loop of distinct domains.
MAX_RECORDS_PER_USER = 100

_create_limiter = rate_limiter(
    "domains_verify", lambda: int(os.environ.get("RATE_LIMIT_DOMAINS_VERIFY", "10")), 60,
)
# Each check is an outbound DNS query or HTTP fetch on the caller's behalf.
_check_limiter = rate_limiter(
    "domains_check", lambda: int(os.environ.get("RATE_LIMIT_DOMAINS_CHECK", "5")), 60,
)


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _require_csrf_for_cookie_auth(request: Request) -> None:
    if request.headers.get("X-API-Key") or request.headers.get("Authorization", "").startswith("Bearer "):
        return
    secret = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not verify_csrf_token(secret, request.headers.get("X-CSRF-Token", "")):
        raise HTTPException(403, "CSRF token missing or invalid")


def _to_dict(rec: DomainVerification) -> dict:
    return {
        "id": rec.id,
        "domain": rec.domain,
        "method": rec.method,
        "status": rec.status,
        "token": rec.token,
        "instructions": instructions(rec),
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
        "verified_at": rec.verified_at.isoformat() if rec.verified_at else None,
        "last_checked_at": rec.last_checked_at.isoformat() if rec.last_checked_at else None,
        "last_error": rec.last_error,
    }


async def _own_record(db: AsyncSession, user: User, record_id: int) -> DomainVerification:
    rec = (await db.execute(
        select(DomainVerification).where(
            DomainVerification.id == record_id, DomainVerification.user_id == user.id,
        )
    )).scalar_one_or_none()
    if rec is None:
        raise HTTPException(404, "Verification not found")
    return rec


async def _find(db: AsyncSession, user: User, domain: str, method: str):
    return (await db.execute(
        select(DomainVerification).where(
            DomainVerification.user_id == user.id,
            DomainVerification.domain == domain,
            DomainVerification.method == method,
        )
    )).scalar_one_or_none()


@router.post(
    "/verify",
    summary="Start verifying ownership of a domain",
    description=(
        "Returns a token and instructions. `method` is `dns_txt` (TXT record; covers the domain "
        "and all subdomains) or `http_file` (file at `/.well-known/optisec-verify.txt`; covers "
        "that exact host only). Idempotent per (domain, method). Requires **analyst** or **admin**."
    ),
    dependencies=[Depends(_create_limiter)],
)
async def start_verification(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_analyst_or_admin(user)
    _require_csrf_for_cookie_auth(request)
    try:
        data = await request.json()
    except ValueError:
        raise HTTPException(400, "Invalid JSON body")
    if not isinstance(data, dict):
        raise HTTPException(400, "Request body must be a JSON object")

    method = data.get("method")
    if method not in VERIFY_METHODS:
        raise HTTPException(400, f"method must be one of: {', '.join(VERIFY_METHODS)}")
    raw_domain = data.get("domain")
    if not isinstance(raw_domain, str):
        raise HTTPException(400, "domain is required")
    try:
        domain = validate_domain(raw_domain)
    except ValueError as e:
        raise HTTPException(400, str(e))

    rec = await _find(db, user, domain, method)
    if rec is not None:
        return JSONResponse(_to_dict(rec))

    count = (await db.execute(
        select(func.count()).select_from(DomainVerification).where(DomainVerification.user_id == user.id)
    )).scalar()
    if count >= MAX_RECORDS_PER_USER:
        raise HTTPException(403, f"Verification limit reached ({MAX_RECORDS_PER_USER}); delete unused ones first")

    rec = DomainVerification(user_id=user.id, domain=domain, method=method, token=new_token(), status=STATUS_PENDING)
    db.add(rec)
    try:
        await db.commit()
    except IntegrityError:
        # Concurrent duplicate request won the unique constraint -- return its row.
        await db.rollback()
        rec = await _find(db, user, domain, method)
        if rec is None:
            raise
        return JSONResponse(_to_dict(rec))
    await db.refresh(rec)
    return JSONResponse(_to_dict(rec), status_code=201)


@router.post(
    "/{record_id}/check",
    summary="Run the ownership check now",
    dependencies=[Depends(_check_limiter)],
)
async def check_verification(
    record_id: int, request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db),
):
    require_analyst_or_admin(user)
    _require_csrf_for_cookie_auth(request)
    rec = await _own_record(db, user, record_id)
    await run_check(rec)
    await db.commit()
    await db.refresh(rec)
    return JSONResponse(_to_dict(rec))


@router.get("", summary="List your domain verifications")
async def list_verifications(user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(DomainVerification)
        .where(DomainVerification.user_id == user.id)
        .order_by(DomainVerification.created_at.desc(), DomainVerification.id.desc())
    )).scalars().all()
    return JSONResponse({"verifications": [_to_dict(r) for r in rows]})


@router.delete("/{record_id}", summary="Delete a domain verification")
async def delete_verification(
    record_id: int, request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db),
):
    require_analyst_or_admin(user)
    _require_csrf_for_cookie_auth(request)
    rec = await _own_record(db, user, record_id)
    await db.delete(rec)
    await db.commit()
    return JSONResponse({"success": True})
