"""Tests for rate limiting on the NOWPayments payment endpoints
(web/rate_limit.py, wired into web/routers/payment_routes.py):
POST /api/payments/create-invoice and POST /webhooks/nowpayments.

Same TestClient/in-memory-SQLite convention as
tests/test_nowpayments_payment_flow.py. TestClient's default client host is
"testclient" (starlette), which is deterministic and shared across requests
in a test — exactly what's needed to trip a per-IP limiter.
"""
import asyncio
import hashlib
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
import web.database as database
import web.rate_limit as rate_limit
import web.routers.payment_routes as payment_routes
from web.database import Base, get_db
from web.models import PendingPayment


def _run(coro):
    return asyncio.run(coro)


def _sign(payload: dict, secret: str) -> str:
    sorted_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode(), sorted_payload.encode(), hashlib.sha512).hexdigest()


@pytest.fixture(autouse=True)
def _isolated_email_outbox(tmp_path, monkeypatch):
    import web.services.email_delivery as email_delivery
    monkeypatch.setattr(email_delivery, "OUTBOX_DIR", tmp_path)
    yield tmp_path


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    """The limiter's counters are module-level state shared across every
    test in the process — without this, an earlier test's requests from
    "testclient" would bleed into the next test's limit."""
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


@pytest.fixture
def client(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setenv("NOWPAYMENTS_IPN_SECRET", "test-ipn-secret")

    c = TestClient(app_module.app)
    yield c, session_factory

    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


class TestCreateInvoiceRateLimit:
    def test_requests_within_limit_pass(self, client, monkeypatch):
        c, _ = client
        monkeypatch.setenv("RATE_LIMIT_CREATE_INVOICE", "3")

        async def fake_create_invoice(order_id, price_amount, customer_email, price_currency="usd"):
            return {"invoice_url": "https://nowpayments.io/pay/abc", "payment_id": "np_1", "raw": {}}

        monkeypatch.setattr(payment_routes, "create_invoice", fake_create_invoice)

        for _ in range(3):
            resp = c.post("/api/payments/create-invoice", json={"email": "buyer@example.com"})
            assert resp.status_code == 200

    def test_exceeding_limit_returns_429_with_retry_after(self, client, monkeypatch):
        c, _ = client
        monkeypatch.setenv("RATE_LIMIT_CREATE_INVOICE", "2")

        async def fake_create_invoice(order_id, price_amount, customer_email, price_currency="usd"):
            return {"invoice_url": "https://nowpayments.io/pay/abc", "payment_id": "np_1", "raw": {}}

        monkeypatch.setattr(payment_routes, "create_invoice", fake_create_invoice)

        for _ in range(2):
            resp = c.post("/api/payments/create-invoice", json={"email": "buyer@example.com"})
            assert resp.status_code == 200

        resp = c.post("/api/payments/create-invoice", json={"email": "buyer@example.com"})
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_limit_is_env_tunable(self, client, monkeypatch):
        c, _ = client
        monkeypatch.setenv("RATE_LIMIT_CREATE_INVOICE", "1")

        async def fake_create_invoice(order_id, price_amount, customer_email, price_currency="usd"):
            return {"invoice_url": "https://nowpayments.io/pay/abc", "payment_id": "np_1", "raw": {}}

        monkeypatch.setattr(payment_routes, "create_invoice", fake_create_invoice)

        resp1 = c.post("/api/payments/create-invoice", json={"email": "buyer@example.com"})
        resp2 = c.post("/api/payments/create-invoice", json={"email": "buyer@example.com"})
        assert resp1.status_code == 200
        assert resp2.status_code == 429

    def test_invalid_email_requests_still_count_against_the_limit(self, client, monkeypatch):
        """The rate-limit dependency runs before body validation fails, so a
        flood of malformed requests is still throttled, not a free bypass."""
        c, _ = client
        monkeypatch.setenv("RATE_LIMIT_CREATE_INVOICE", "1")

        resp1 = c.post("/api/payments/create-invoice", json={"email": "not-an-email"})
        assert resp1.status_code == 400

        resp2 = c.post("/api/payments/create-invoice", json={"email": "not-an-email"})
        assert resp2.status_code == 429


class TestWebhookRateLimit:
    def test_normal_ipn_retry_volume_is_not_blocked(self, client, monkeypatch):
        """A handful of legitimate NOWPayments retry notifications for
        different orders must never be blocked by the flood backstop."""
        c, session_factory = client
        monkeypatch.setenv("RATE_LIMIT_NOWPAYMENTS_WEBHOOK", "30")

        async def seed(order_id):
            async with session_factory() as db:
                db.add(PendingPayment(
                    order_id=order_id, email="buyer@example.com", tier="pro",
                    price_amount=399.0, price_currency="usd", status="pending",
                ))
                await db.commit()

        for i in range(5):
            order_id = f"reconpro|order-{i}|pro"
            _run(seed(order_id))
            payload = {"order_id": order_id, "payment_id": f"p{i}", "payment_status": "waiting"}
            resp = c.post(
                "/webhooks/nowpayments",
                content=json.dumps(payload),
                headers={"content-type": "application/json",
                         "x-nowpayments-sig": _sign(payload, "test-ipn-secret")},
            )
            assert resp.status_code == 200

    def test_exceeding_webhook_limit_returns_429(self, client, monkeypatch):
        c, _ = client
        monkeypatch.setenv("RATE_LIMIT_NOWPAYMENTS_WEBHOOK", "2")

        payload = {"order_id": "reconpro|does-not-exist|pro", "payment_id": "p1", "payment_status": "waiting"}
        headers = {"content-type": "application/json",
                   "x-nowpayments-sig": _sign(payload, "test-ipn-secret")}

        for _ in range(2):
            resp = c.post("/webhooks/nowpayments", content=json.dumps(payload), headers=headers)
            assert resp.status_code == 200  # unknown order_id -> ignored, still 200

        resp = c.post("/webhooks/nowpayments", content=json.dumps(payload), headers=headers)
        assert resp.status_code == 429
