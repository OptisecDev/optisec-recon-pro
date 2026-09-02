"""License-key email delivery for automated NOWPayments purchases
(web/routers/payment_routes.py).

Two layers, in order: (1) a real SMTP send via
web/services/email_client.py's send_license_email(), (2) a local
chmod-600 per-order outbox file under data/pending_license_deliveries/
(same os.O_EXCL convention as web/app.py's _ensure_first_admin() initial-
credentials file) that is *always* written first, regardless of SMTP
outcome — a paid customer's key must never be silently lost even if SMTP
is misconfigured or the provider is down. The outbox record tracks a
`delivered` flag: `false` until a real send succeeds, then flipped to
`true`. resend_pending_deliveries.py (repo root) scans for delivered=false
records and retries them — the emergency path for "SMTP was down at
payment time."

WARNING, not INFO/logger.info: web.app's logger has no handler configured
and only WARNING+ reaches stderr in production (see the 2026-07-03 session
note in this project's memory) — every log line here must stay at WARNING
or higher to actually be visible.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from web.services.email_client import EmailDeliveryError, send_license_email

logger = logging.getLogger("web.app")

OUTBOX_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "pending_license_deliveries"

PRODUCT_NAME = "OPTISEC Recon Pro"


def _outbox_path(order_id: str) -> Path:
    safe_name = order_id.replace("|", "_")
    return OUTBOX_DIR / f"{safe_name}.txt"


def _write_outbox_record(email: str, raw_key: str, tier: str, order_id: str) -> Path:
    """Create the record once (O_EXCL — a retried webhook call for the same
    order_id just no-ops here, since the record already exists)."""
    file_path = _outbox_path(order_id)
    try:
        OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(
                f"email={email}\ntier={tier}\norder_id={order_id}\n"
                f"license_key={raw_key}\ndelivered=false\n"
            )
    except FileExistsError:
        pass  # already written by an earlier (idempotent-guarded) call
    except OSError as exc:
        logger.warning(
            f"NOWPayments: failed to write pending license delivery file "
            f"for order {order_id}: {exc}"
        )
    return file_path


def mark_delivered(order_id: str) -> None:
    """Flip an outbox record's delivered flag to true after a confirmed
    SMTP send — used by the webhook path below and by
    resend_pending_deliveries.py after a successful manual retry."""
    file_path = _outbox_path(order_id)
    try:
        if not file_path.exists():
            return
        lines = [l for l in file_path.read_text().splitlines() if not l.startswith("delivered=")]
        lines.append("delivered=true")
        file_path.write_text("\n".join(lines) + "\n")
    except OSError as exc:
        logger.warning(f"NOWPayments: failed to mark order {order_id} delivered: {exc}")


async def send_license_key_email(email: str, raw_key: str, tier: str, order_id: str) -> None:
    """Contract: never raises. A delivery failure here must not roll back
    the already-committed LicenseKey/PendingPayment update in the caller."""
    file_path = _write_outbox_record(email, raw_key, tier, order_id)

    try:
        await send_license_email(email, raw_key, PRODUCT_NAME)
    except EmailDeliveryError as exc:
        logger.warning(
            f"NOWPayments: SMTP delivery failed for order {order_id} ({email}): {exc}. "
            f"Key saved to {file_path} — retry with resend_pending_deliveries.py "
            f"once SMTP is fixed."
        )
        return
    except Exception as exc:  # belt-and-suspenders — this must never raise into the webhook
        logger.warning(
            f"NOWPayments: unexpected error sending license email for order {order_id} "
            f"({email}): {exc}. Key saved to {file_path}."
        )
        return

    mark_delivered(order_id)
    logger.warning(f"NOWPayments: PRO license key emailed to {email} (order {order_id}).")
