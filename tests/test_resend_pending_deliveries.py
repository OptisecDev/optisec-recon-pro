"""Tests for resend_pending_deliveries.py — the CLI fallback that retries
license-key emails left in data/pending_license_deliveries/ with
delivered=false (see web/services/email_delivery.py). send_license_email is
mocked; no real SMTP/network involved.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import resend_pending_deliveries as resend_cli
import web.services.email_delivery as email_delivery
from web.services.email_client import EmailDeliveryError


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _outbox(tmp_path, monkeypatch):
    monkeypatch.setattr(email_delivery, "OUTBOX_DIR", tmp_path)
    monkeypatch.setattr(resend_cli, "OUTBOX_DIR", tmp_path)
    yield tmp_path


def _write_record(tmp_path, order_id: str, email: str, license_key: str, delivered: bool):
    path = tmp_path / f"{order_id}.txt"
    path.write_text(
        f"email={email}\ntier=pro\norder_id={order_id}\n"
        f"license_key={license_key}\ndelivered={'true' if delivered else 'false'}\n"
    )
    return path


class TestPendingRecordsDiscovery:
    def test_only_undelivered_records_are_picked_up(self, _outbox):
        _write_record(_outbox, "order-a", "a@example.com", "KEY-A", delivered=False)
        _write_record(_outbox, "order-b", "b@example.com", "KEY-B", delivered=True)

        records = resend_cli._pending_records()
        order_ids = [fields["order_id"] for _, fields in records]
        assert order_ids == ["order-a"]

    def test_empty_outbox_dir_returns_no_records(self, tmp_path, monkeypatch):
        empty_dir = tmp_path / "does-not-exist"
        monkeypatch.setattr(resend_cli, "OUTBOX_DIR", empty_dir)
        assert resend_cli._pending_records() == []


class TestResendAll:
    def test_dry_run_sends_nothing(self, _outbox, monkeypatch):
        _write_record(_outbox, "order-c", "c@example.com", "KEY-C", delivered=False)
        called = []

        async def fake_send(*a, **kw):
            called.append(a)

        monkeypatch.setattr(resend_cli, "send_license_email", fake_send)
        sent, failed = _run(resend_cli.resend_all(dry_run=True))

        assert sent == 0
        assert failed == 0
        assert called == []
        assert "delivered=false" in (_outbox / "order-c.txt").read_text()

    def test_successful_resend_marks_delivered_and_counts_sent(self, _outbox, monkeypatch):
        _write_record(_outbox, "order-d", "d@example.com", "KEY-D", delivered=False)

        async def fake_send(email, key, product_name):
            assert email == "d@example.com"
            assert key == "KEY-D"

        monkeypatch.setattr(resend_cli, "send_license_email", fake_send)
        sent, failed = _run(resend_cli.resend_all(dry_run=False))

        assert sent == 1
        assert failed == 0
        assert "delivered=true" in (_outbox / "order-d.txt").read_text()

    def test_failed_resend_leaves_record_pending_and_counts_failed(self, _outbox, monkeypatch):
        _write_record(_outbox, "order-e", "e@example.com", "KEY-E", delivered=False)

        async def failing_send(*a, **kw):
            raise EmailDeliveryError("still down")

        monkeypatch.setattr(resend_cli, "send_license_email", failing_send)
        sent, failed = _run(resend_cli.resend_all(dry_run=False))

        assert sent == 0
        assert failed == 1
        assert "delivered=false" in (_outbox / "order-e.txt").read_text()

    def test_multiple_pending_records_all_processed(self, _outbox, monkeypatch):
        _write_record(_outbox, "order-f", "f@example.com", "KEY-F", delivered=False)
        _write_record(_outbox, "order-g", "g@example.com", "KEY-G", delivered=False)
        _write_record(_outbox, "order-h", "h@example.com", "KEY-H", delivered=True)

        sent_to = []

        async def fake_send(email, key, product_name):
            sent_to.append(email)

        monkeypatch.setattr(resend_cli, "send_license_email", fake_send)
        sent, failed = _run(resend_cli.resend_all(dry_run=False))

        assert sent == 2
        assert failed == 0
        assert sorted(sent_to) == ["f@example.com", "g@example.com"]
