"""NOWPayments crypto-invoice client — automates the PRO ($399) purchase
flow via NOWPayments' hosted invoice page instead of the old manual
USDT-transfer-plus-email process. See web/routers/payment_routes.py for the
endpoint that calls create_invoice() and the POST /webhooks/nowpayments IPN
handler that completes the purchase once payment_status == "finished".

Env vars read at call time (not import time), same convention as
modules/bug_bounty/hackerone.py, so tests can monkeypatch them freely:
NOWPAYMENTS_API_KEY, NOWPAYMENTS_SANDBOX, NOWPAYMENTS_IPN_CALLBACK_URL,
NOWPAYMENTS_APP_BASE_URL.
"""
from __future__ import annotations

import os
import uuid

import httpx

_API_BASE_LIVE = "https://api.nowpayments.io/v1"
_API_BASE_SANDBOX = "https://api-sandbox.nowpayments.io/v1"

# Fallback origin for success_url/cancel_url below when
# NOWPAYMENTS_APP_BASE_URL is unset — this project's live deployment
# (see README's "Live Demo" link), so a buyer is always redirected
# somewhere real rather than to a relative/broken URL.
_DEFAULT_APP_BASE_URL = "https://optisec-recon-pro.onrender.com"


class NowPaymentsError(Exception):
    """Raised when NOWPayments is unreachable, misconfigured, or returns an
    error/unexpected response. Callers (web/routers/payment_routes.py)
    catch this and return a clean 502 rather than letting it propagate."""


def _is_sandbox() -> bool:
    return os.environ.get("NOWPAYMENTS_SANDBOX", "false").strip().lower() == "true"


def _api_base() -> str:
    return _API_BASE_SANDBOX if _is_sandbox() else _API_BASE_LIVE


def build_order_id(tier: str = "pro") -> str:
    """Build a correlation id embedded in the NOWPayments invoice and
    echoed back verbatim in the IPN webhook payload's order_id field, so
    the webhook can look the purchase back up in PendingPayment without
    trusting anything else in the notification. Uses a real uuid4, not a
    counter/sequence, so an order_id can never be guessed or enumerated."""
    return f"reconpro|{uuid.uuid4()}|{tier}"


async def create_invoice(
    order_id: str,
    price_amount: float,
    customer_email: str,
    price_currency: str = "usd",
) -> dict:
    """Create a NOWPayments hosted invoice.

    Returns {"invoice_url": str, "payment_id": str | None, "raw": dict}.

    Uses NOWPayments' /invoice endpoint on both sandbox and live — only the
    API host differs between the two (NOWPayments' sandbox mirrors the live
    API 1:1). /v1/payment (a different, non-hosted flow) is deliberately
    NOT used even in sandbox: it returns pay_address/pay_amount instead of
    invoice_url, which doesn't fit this function's return contract.
    """
    api_key = os.environ.get("NOWPAYMENTS_API_KEY", "")
    if not api_key:
        raise NowPaymentsError("NOWPAYMENTS_API_KEY is not configured")

    payload = {
        "price_amount": price_amount,
        "price_currency": price_currency,
        "order_id": order_id,
        "order_description": "OPTISEC Recon Pro — PRO license (lifetime)",
        "is_fixed_rate": False,
    }
    if customer_email:
        payload["customer_email"] = customer_email
    callback_url = os.environ.get("NOWPAYMENTS_IPN_CALLBACK_URL", "").strip()
    if callback_url:
        payload["ipn_callback_url"] = callback_url

    # Where NOWPayments' hosted invoice page sends the buyer back to —
    # without these, a paid buyer is left stranded on NOWPayments' own
    # page with no path back to /redeem. Both point at the same page
    # (web/routers/license_routes.py's GET /redeem) with a ?payment=
    # query param the template reads to show a tailored message; see
    # web/templates/redeem.html.
    base_url = os.environ.get("NOWPAYMENTS_APP_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        base_url = _DEFAULT_APP_BASE_URL
    payload["success_url"] = f"{base_url}/redeem?payment=success"
    payload["cancel_url"] = f"{base_url}/redeem?payment=cancelled"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{_api_base()}/invoice",
                json=payload,
                headers={"x-api-key": api_key, "Content-Type": "application/json"},
            )
    except NowPaymentsError:
        raise
    except Exception as exc:
        raise NowPaymentsError(f"NOWPayments request failed: {exc}") from exc

    if resp.status_code >= 400:
        raise NowPaymentsError(
            f"NOWPayments invoice creation failed: {resp.status_code} {resp.text}"
        )

    data = resp.json()
    invoice_url = data.get("invoice_url")
    if not invoice_url:
        raise NowPaymentsError(f"NOWPayments response missing invoice_url: {data}")

    return {"invoice_url": invoice_url, "payment_id": data.get("id"), "raw": data}
