"""Unit tests for web/services/email_delivery.py's send_license_key_email()
and mark_delivered() — the layer between the NOWPayments webhook
(web/routers/payment_routes.py) and the real SMTP sender
(web/services/email_client.py). Full webhook-level coverage (that a delivery
failure never fails the webhook response) already lives in
tests/test_nowpayments_payment_flow.py; this file isolates the outbox-file
and delivered-flag behavior directly, with send_license_email mocked so no
real SMTP config/network is needed.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import web.services.email_delivery as email_delivery
from web.services.email_client import EmailDeliveryError


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _outbox(tmp_path, monkeypatch):
    monkeypatch.setattr(email_delivery, "OUTBOX_DIR", tmp_path)
    yield tmp_path


def _record_path(tmp_path, order_id: str):
    return tmp_path / f"{order_id.replace('|', '_')}.txt"


class TestSendLicenseKeyEmailSuccess:
    def test_smtp_success_marks_delivered_true(self, _outbox, monkeypatch):
        async def fake_send(*a, **kw):
            return None

        monkeypatch.setattr(email_delivery, "send_license_email", fake_send)

        _run(email_delivery.send_license_key_email("buyer@example.com", "OPS4-PRO-abc", "pro", "order-1"))

        content = _record_path(_outbox, "order-1").read_text()
        assert "delivered=true" in content
        assert "license_key=OPS4-PRO-abc" in content
        assert "email=buyer@example.com" in content


class TestSendLicenseKeyEmailFailureDoesNotRaise:
    def test_email_delivery_error_leaves_delivered_false_and_does_not_raise(self, _outbox, monkeypatch):
        async def failing_send(*a, **kw):
            raise EmailDeliveryError("SMTP not configured")

        monkeypatch.setattr(email_delivery, "send_license_email", failing_send)

        # Must not raise — this is the "never fails the webhook" contract.
        _run(email_delivery.send_license_key_email("buyer@example.com", "OPS4-PRO-abc", "pro", "order-2"))

        content = _record_path(_outbox, "order-2").read_text()
        assert "delivered=false" in content
        assert "license_key=OPS4-PRO-abc" in content

    def test_unexpected_exception_also_does_not_raise(self, _outbox, monkeypatch):
        async def crashing_send(*a, **kw):
            raise RuntimeError("something else entirely")

        monkeypatch.setattr(email_delivery, "send_license_email", crashing_send)

        _run(email_delivery.send_license_key_email("buyer@example.com", "OPS4-PRO-abc", "pro", "order-3"))

        content = _record_path(_outbox, "order-3").read_text()
        assert "delivered=false" in content


class TestMarkDelivered:
    def test_mark_delivered_flips_flag_on_existing_record(self, _outbox, monkeypatch):
        async def failing_send(*a, **kw):
            raise EmailDeliveryError("down")

        monkeypatch.setattr(email_delivery, "send_license_email", failing_send)
        _run(email_delivery.send_license_key_email("buyer@example.com", "OPS4-PRO-abc", "pro", "order-4"))
        assert "delivered=false" in _record_path(_outbox, "order-4").read_text()

        email_delivery.mark_delivered("order-4")
        assert "delivered=true" in _record_path(_outbox, "order-4").read_text()

    def test_mark_delivered_on_missing_record_is_a_noop(self, _outbox):
        email_delivery.mark_delivered("does-not-exist")  # must not raise
