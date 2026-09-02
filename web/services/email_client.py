"""Standard-SMTP email delivery for automatically-issued NOWPayments
license keys (web/services/email_delivery.py). Plain smtplib +
email.mime.* — no third-party mail SDK — so any standard SMTP submission
endpoint works via the same six env vars: Gmail (App Password),
Resend/Mailgun SMTP, or a self-hosted relay. Nothing here is Gmail-specific
beyond the *default* host/port (smtp.gmail.com:587) — set SMTP_HOST/
SMTP_PORT to point at any other provider.
"""
from __future__ import annotations

import asyncio
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class EmailDeliveryError(Exception):
    """Raised for any SMTP configuration or send failure. Callers that need
    a "never raises" contract (see web/services/email_delivery.py) must
    catch this themselves — it is deliberately not swallowed here so a
    caller can distinguish "not configured" from "sent successfully"."""


def _smtp_config() -> dict:
    return {
        "host": os.environ.get("SMTP_HOST", "smtp.gmail.com"),
        "port": int(os.environ.get("SMTP_PORT", "587")),
        "username": os.environ.get("SMTP_USERNAME", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "from_email": os.environ.get("SMTP_FROM_EMAIL", ""),
        "from_name": os.environ.get("SMTP_FROM_NAME", "OPTISEC"),
    }


def _build_message(to_email: str, license_key: str, product_name: str, from_email: str, from_name: str) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Your {product_name} License Key"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email

    text_body = (
        f"Thank you for purchasing {product_name}!\n\n"
        f"Your license key:\n{license_key}\n\n"
        f"Redeem it on your account's license page to activate PRO access.\n"
    )
    html_body = (
        f"<p>Thank you for purchasing <strong>{product_name}</strong>!</p>"
        f"<p>Your license key:</p>"
        f"<p style=\"font-family:monospace;font-size:16px\">{license_key}</p>"
        f"<p>Redeem it on your account's license page to activate PRO access.</p>"
    )
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))
    return msg


def _send_sync(to_email: str, license_key: str, product_name: str) -> None:
    config = _smtp_config()
    if not config["username"] or not config["password"] or not config["from_email"]:
        raise EmailDeliveryError(
            "SMTP is not configured (SMTP_USERNAME/SMTP_PASSWORD/SMTP_FROM_EMAIL missing)"
        )

    msg = _build_message(to_email, license_key, product_name, config["from_email"], config["from_name"])

    try:
        with smtplib.SMTP(config["host"], config["port"], timeout=15) as server:
            server.starttls()
            server.login(config["username"], config["password"])
            server.sendmail(config["from_email"], [to_email], msg.as_string())
    except (smtplib.SMTPException, OSError) as exc:
        raise EmailDeliveryError(f"SMTP send failed: {exc}") from exc


async def send_license_email(to_email: str, license_key: str, product_name: str = "OPTISEC Recon Pro") -> None:
    """Send the license key by email over standard SMTP.

    Raises EmailDeliveryError on any configuration or send failure — this
    function does NOT swallow errors itself, unlike
    web/services/email_delivery.py's send_license_key_email(), which wraps
    this call and is the one that guarantees a "never raises" contract for
    the webhook handler.
    """
    await asyncio.to_thread(_send_sync, to_email, license_key, product_name)
