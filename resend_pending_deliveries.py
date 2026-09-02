"""Standalone CLI: scan data/pending_license_deliveries/ (see
web/services/email_delivery.py) for orders whose license key was written to
the local outbox but never confirmed delivered by email (delivered=false),
and retry sending them over SMTP (web/services/email_client.py). This is
the emergency path for "SMTP was misconfigured or down at payment time" —
safe to re-run any time, already-delivered records are skipped.

Usage:
    python resend_pending_deliveries.py             # resend everything pending
    python resend_pending_deliveries.py --dry-run    # list pending, send nothing
"""
import argparse
import asyncio
from pathlib import Path

from web.services.email_client import EmailDeliveryError, send_license_email
from web.services.email_delivery import OUTBOX_DIR, PRODUCT_NAME, mark_delivered


def _parse_record(path: Path) -> dict:
    fields = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key] = value
    return fields


def _pending_records() -> list[tuple[Path, dict]]:
    if not OUTBOX_DIR.exists():
        return []
    records = []
    for path in sorted(OUTBOX_DIR.glob("*.txt")):
        fields = _parse_record(path)
        if fields.get("delivered") != "true":
            records.append((path, fields))
    return records


async def resend_all(dry_run: bool = False) -> tuple[int, int]:
    """Returns (sent_count, failed_count)."""
    sent, failed = 0, 0
    for path, fields in _pending_records():
        email = fields.get("email")
        license_key = fields.get("license_key")
        order_id = fields.get("order_id", path.stem)

        if not email or not license_key:
            print(f"[skip] {path.name}: missing email/license_key fields")
            failed += 1
            continue

        if dry_run:
            print(f"[dry-run] would resend order={order_id} to {email}")
            continue

        try:
            await send_license_email(email, license_key, PRODUCT_NAME)
        except EmailDeliveryError as exc:
            print(f"[fail] order={order_id} to {email}: {exc}")
            failed += 1
            continue

        mark_delivered(order_id)
        print(f"[sent] order={order_id} to {email}")
        sent += 1

    return sent, failed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resend PRO license keys stuck in the pending-delivery outbox"
    )
    parser.add_argument("--dry-run", action="store_true", help="List pending deliveries without sending")
    args = parser.parse_args()

    sent, failed = asyncio.run(resend_all(dry_run=args.dry_run))
    if not args.dry_run:
        print(f"\nDone: {sent} sent, {failed} failed.")


if __name__ == "__main__":
    main()
