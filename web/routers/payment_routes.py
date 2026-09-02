"""Automated crypto checkout via NOWPayments — replaces the manual
USDT-transfer-plus-email PRO purchase flow. Independent of
web/routers/license_routes.py's redeem endpoint: that endpoint requires an
already-logged-in account to redeem a key it already owns; this router lets
an anonymous buyer (email only, no account/login) pay and receive a fresh
LicenseKey generated on the fly once NOWPayments confirms the payment.

Two routers on purpose: `router` is the JSON API
(POST /api/payments/create-invoice), `webhook_router` is the unauthenticated
IPN receiver (POST /webhooks/nowpayments) — kept separate so the webhook is
never accidentally covered by a prefix/dependency meant for the API side.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from license_utils import generate_license_key, hash_license_key
from web.database import get_db
from web.models import LicenseKey, PendingPayment
from web.services.email_delivery import send_license_key_email
from web.services.nowpayments_client import NowPaymentsError, build_order_id, create_invoice

logger = logging.getLogger("web.app")

router = APIRouter(prefix="/api/payments", tags=["payments"])
webhook_router = APIRouter(tags=["payments"])

PRO_PRICE_USD = 399.0

# Statuses where the payment is definitively over and no LicenseKey is
# ever generated. "partially_paid" is handled separately (logged for
# manual review, per the task spec) rather than lumped in here.
_TERMINAL_NO_KEY_STATUSES = {"failed", "expired", "refunded"}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class CreateInvoiceRequest(BaseModel):
    email: str


class CreateInvoiceResponse(BaseModel):
    invoice_url: str
    order_id: str


@router.post("/create-invoice", response_model=CreateInvoiceResponse)
async def create_payment_invoice(
    body: CreateInvoiceRequest,
    db: AsyncSession = Depends(get_db),
):
    email = body.email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address")

    order_id = build_order_id(tier="pro")

    try:
        result = await create_invoice(
            order_id=order_id,
            price_amount=PRO_PRICE_USD,
            customer_email=email,
        )
    except NowPaymentsError as exc:
        logger.warning(f"NOWPayments invoice creation failed for {email}: {exc}")
        raise HTTPException(
            status_code=502,
            detail="Could not start crypto checkout — please try again shortly, "
                   "or use the manual option on this page.",
        ) from exc

    payment_id = result.get("payment_id")
    pending = PendingPayment(
        order_id=order_id,
        email=email,
        tier="pro",
        price_amount=PRO_PRICE_USD,
        price_currency="usd",
        payment_id=str(payment_id) if payment_id else None,
        status="pending",
    )
    db.add(pending)
    await db.commit()

    return CreateInvoiceResponse(invoice_url=result["invoice_url"], order_id=order_id)


def _verify_ipn_signature(raw_body: bytes, signature_header: str, secret: str) -> tuple[bool, dict | None]:
    """Returns (is_valid, parsed_payload). parsed_payload is None if the
    body wasn't valid JSON at all (treated as an invalid signature too)."""
    if not signature_header or not secret:
        return False, None
    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False, None

    # NOWPayments' documented IPN scheme: sort payload keys, dump with no
    # extra whitespace, HMAC-SHA512 with the IPN secret, compare hex digest.
    sorted_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    computed = hmac.new(
        secret.encode("utf-8"), sorted_payload.encode("utf-8"), hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed, signature_header), payload


@webhook_router.post("/webhooks/nowpayments", include_in_schema=False)
async def nowpayments_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    raw_body = await request.body()
    signature = request.headers.get("x-nowpayments-sig", "")
    ipn_secret = os.environ.get("NOWPAYMENTS_IPN_SECRET", "")

    is_valid, payload = _verify_ipn_signature(raw_body, signature, ipn_secret)
    if not is_valid:
        logger.warning("NOWPayments webhook: signature verification failed")
        # A raised HTTPException(401) here would be caught by web/app.py's
        # global on_http_exception handler, which redirects any 401 outside
        # /api/* to /login (a 302, not a 401) — wrong for a webhook that
        # must see a real 401 to know not to retry-as-success. Return the
        # response directly instead, bypassing that handler entirely.
        return JSONResponse({"detail": "Invalid signature"}, status_code=401)

    order_id = payload.get("order_id")
    payment_id = payload.get("payment_id")
    payment_status = payload.get("payment_status")

    if not order_id:
        logger.warning("NOWPayments webhook: payload missing order_id")
        return {"status": "ignored"}

    result = await db.execute(select(PendingPayment).where(PendingPayment.order_id == order_id))
    pending = result.scalar_one_or_none()
    if pending is None:
        logger.warning(f"NOWPayments webhook: unknown order_id={order_id}")
        return {"status": "ignored"}

    # Idempotency: a LicenseKey was already generated for this order — never
    # generate a second one no matter how many times NOWPayments retries
    # this notification (retries are the documented reason the same
    # "finished" status can arrive more than once for one payment_id).
    if pending.license_key_hash:
        return {"status": "already_processed"}

    pending.payment_id = str(payment_id) if payment_id else pending.payment_id
    pending.updated_at = datetime.utcnow()

    if payment_status == "finished":
        raw_key = generate_license_key()
        key_hash = hash_license_key(raw_key)
        db.add(LicenseKey(
            key_hash=key_hash,
            tier=pending.tier,
            note=f"NOWPayments order={order_id} email={pending.email}",
        ))
        pending.license_key_hash = key_hash
        pending.status = "completed"
        await db.commit()

        await send_license_key_email(pending.email, raw_key, pending.tier, order_id)
    elif payment_status == "partially_paid":
        pending.status = "partially_paid"
        logger.warning(
            f"NOWPayments webhook: partially_paid order_id={order_id} — needs manual review"
        )
        await db.commit()
    elif payment_status in _TERMINAL_NO_KEY_STATUSES:
        pending.status = payment_status
        await db.commit()
    else:
        # An in-flight status (waiting/confirming/confirmed/sending/etc.) —
        # record it for visibility, no LicenseKey yet.
        pending.status = payment_status or pending.status
        await db.commit()

    return {"status": "ok"}
