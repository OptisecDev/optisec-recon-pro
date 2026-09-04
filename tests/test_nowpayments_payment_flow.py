"""Tests for the NOWPayments automated crypto checkout flow: invoice
creation (web/services/nowpayments_client.py, POST /api/payments/create-invoice)
and the IPN webhook (POST /webhooks/nowpayments, web/routers/payment_routes.py).

Same conventions as tests/test_cve_pipeline.py / tests/test_license_feature_gate.py:
plain pytest, asyncio.run() for coroutines, an in-memory SQLite engine swapped
in for web.database.SessionLocal / get_db, and httpx.AsyncClient monkeypatched
so no real network call ever happens.

Safety invariants this suite protects:
  - a tampered/forged IPN payload is rejected with 401 and never processed
  - a LicenseKey is generated at most once per order_id, even if NOWPayments
    re-sends the same "finished" notification (idempotency)
  - "partially_paid" and terminal failure statuses never generate a key
"""
import asyncio
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
import web.database as database
from web.database import Base, get_db
from web.models import LicenseKey, PendingPayment
import web.services.nowpayments_client as npc
import web.routers.payment_routes as payment_routes
from license_utils import hash_license_key, verify_key_hash


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolated_email_outbox(tmp_path, monkeypatch):
    """Every test in this file hits the real send_license_key_email() via
    the webhook — redirect its file-based outbox into pytest's tmp_path so
    test runs never write into the real project data/pending_license_deliveries/."""
    import web.services.email_delivery as email_delivery
    monkeypatch.setattr(email_delivery, "OUTBOX_DIR", tmp_path)
    yield tmp_path


# ── httpx fakes (mirrors tests/test_cve_pipeline.py's _FakeAsyncClient) ────

class _FakeHttpResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text or json.dumps(self._json_data)

    def json(self):
        return self._json_data


class _FakeAsyncClient:
    def __init__(self, response=None, exc=None, **kw):
        self._response = response
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        if self._exc:
            raise self._exc
        return self._response


class _CapturingAsyncClient(_FakeAsyncClient):
    """Same fake as above, but records the JSON body of the last POST so
    tests can assert on the request payload (e.g. success_url/cancel_url),
    not just the response."""
    last_payload = None

    async def post(self, url, json=None, headers=None):
        _CapturingAsyncClient.last_payload = json
        return await super().post(url, json=json, headers=headers)


# ── 1. nowpayments_client.create_invoice ────────────────────────────────────

class TestBuildOrderId:
    def test_format_has_three_pipe_separated_parts(self):
        order_id = npc.build_order_id(tier="pro")
        parts = order_id.split("|")
        assert len(parts) == 3
        assert parts[0] == "reconpro"
        assert parts[2] == "pro"

    def test_uses_a_real_uuid4_not_a_sequence(self):
        a = npc.build_order_id()
        b = npc.build_order_id()
        assert a != b
        import uuid
        uuid.UUID(a.split("|")[1])  # raises ValueError if not a valid uuid


class TestCreateInvoice:
    def test_missing_api_key_raises(self, monkeypatch):
        monkeypatch.delenv("NOWPAYMENTS_API_KEY", raising=False)
        with pytest.raises(npc.NowPaymentsError, match="NOWPAYMENTS_API_KEY"):
            _run(npc.create_invoice(order_id="reconpro|x|pro", price_amount=399.0,
                                     customer_email="buyer@example.com"))

    def test_success_returns_invoice_url_and_payment_id(self, monkeypatch):
        monkeypatch.setenv("NOWPAYMENTS_API_KEY", "test-key")
        fake_resp = _FakeHttpResponse(200, {"id": "inv_123", "invoice_url": "https://nowpayments.io/pay/inv_123"})
        monkeypatch.setattr(npc.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(response=fake_resp))

        result = _run(npc.create_invoice(order_id="reconpro|x|pro", price_amount=399.0,
                                          customer_email="buyer@example.com"))
        assert result["invoice_url"] == "https://nowpayments.io/pay/inv_123"
        assert result["payment_id"] == "inv_123"

    def test_http_error_raises_nowpayments_error(self, monkeypatch):
        monkeypatch.setenv("NOWPAYMENTS_API_KEY", "test-key")
        fake_resp = _FakeHttpResponse(400, {"message": "bad request"}, text="bad request")
        monkeypatch.setattr(npc.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(response=fake_resp))

        with pytest.raises(npc.NowPaymentsError):
            _run(npc.create_invoice(order_id="reconpro|x|pro", price_amount=399.0,
                                     customer_email="buyer@example.com"))

    def test_response_missing_invoice_url_raises(self, monkeypatch):
        monkeypatch.setenv("NOWPAYMENTS_API_KEY", "test-key")
        fake_resp = _FakeHttpResponse(200, {"id": "inv_123"})
        monkeypatch.setattr(npc.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(response=fake_resp))

        with pytest.raises(npc.NowPaymentsError, match="invoice_url"):
            _run(npc.create_invoice(order_id="reconpro|x|pro", price_amount=399.0,
                                     customer_email="buyer@example.com"))

    def test_connection_error_raises_nowpayments_error(self, monkeypatch):
        monkeypatch.setenv("NOWPAYMENTS_API_KEY", "test-key")
        monkeypatch.setattr(npc.httpx, "AsyncClient",
                             lambda *a, **kw: _FakeAsyncClient(exc=ConnectionError("no network")))
        with pytest.raises(npc.NowPaymentsError):
            _run(npc.create_invoice(order_id="reconpro|x|pro", price_amount=399.0,
                                     customer_email="buyer@example.com"))

    def test_sandbox_flag_selects_sandbox_host(self, monkeypatch):
        monkeypatch.setenv("NOWPAYMENTS_SANDBOX", "true")
        assert npc._api_base() == npc._API_BASE_SANDBOX
        monkeypatch.setenv("NOWPAYMENTS_SANDBOX", "false")
        assert npc._api_base() == npc._API_BASE_LIVE


class TestCreateInvoiceRedirectUrls:
    """Point 1 of the 2026-09-04 UX audit fix: create_invoice() must send
    success_url/cancel_url so NOWPayments' hosted invoice page can redirect
    the buyer back to /redeem instead of stranding them."""

    def test_default_base_url_used_when_env_var_unset(self, monkeypatch):
        monkeypatch.setenv("NOWPAYMENTS_API_KEY", "test-key")
        monkeypatch.delenv("NOWPAYMENTS_APP_BASE_URL", raising=False)
        fake_resp = _FakeHttpResponse(200, {"id": "inv_1", "invoice_url": "https://nowpayments.io/pay/inv_1"})
        monkeypatch.setattr(npc.httpx, "AsyncClient", lambda *a, **kw: _CapturingAsyncClient(response=fake_resp))

        _run(npc.create_invoice(order_id="reconpro|x|pro", price_amount=399.0,
                                 customer_email="buyer@example.com"))

        payload = _CapturingAsyncClient.last_payload
        assert payload["success_url"] == "https://optisec-recon-pro.onrender.com/redeem?payment=success"
        assert payload["cancel_url"] == "https://optisec-recon-pro.onrender.com/redeem?payment=cancelled"

    def test_custom_base_url_env_var_is_used_and_trailing_slash_stripped(self, monkeypatch):
        monkeypatch.setenv("NOWPAYMENTS_API_KEY", "test-key")
        monkeypatch.setenv("NOWPAYMENTS_APP_BASE_URL", "https://custom.example.com/")
        fake_resp = _FakeHttpResponse(200, {"id": "inv_1", "invoice_url": "https://nowpayments.io/pay/inv_1"})
        monkeypatch.setattr(npc.httpx, "AsyncClient", lambda *a, **kw: _CapturingAsyncClient(response=fake_resp))

        _run(npc.create_invoice(order_id="reconpro|x|pro", price_amount=399.0,
                                 customer_email="buyer@example.com"))

        payload = _CapturingAsyncClient.last_payload
        assert payload["success_url"] == "https://custom.example.com/redeem?payment=success"
        assert payload["cancel_url"] == "https://custom.example.com/redeem?payment=cancelled"


# ── 2. IPN signature verification ───────────────────────────────────────────

def _sign(payload: dict, secret: str) -> str:
    sorted_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode(), sorted_payload.encode(), hashlib.sha512).hexdigest()


class TestVerifyIpnSignature:
    def test_valid_signature_accepted(self):
        payload = {"order_id": "reconpro|x|pro", "payment_status": "finished", "payment_id": "p1"}
        secret = "shh"
        sig = _sign(payload, secret)
        # deliberately unsorted key order in the raw body, like a real webhook
        raw_body = json.dumps({"payment_id": "p1", "order_id": "reconpro|x|pro", "payment_status": "finished"}).encode()
        is_valid, parsed = payment_routes._verify_ipn_signature(raw_body, sig, secret)
        assert is_valid is True
        assert parsed["order_id"] == "reconpro|x|pro"

    def test_tampered_payload_rejected(self):
        payload = {"order_id": "reconpro|x|pro", "payment_status": "finished"}
        secret = "shh"
        sig = _sign(payload, secret)
        tampered_body = json.dumps({"order_id": "reconpro|x|pro", "payment_status": "failed"}).encode()
        is_valid, _ = payment_routes._verify_ipn_signature(tampered_body, sig, secret)
        assert is_valid is False

    def test_wrong_secret_rejected(self):
        payload = {"order_id": "x", "payment_status": "finished"}
        sig = _sign(payload, "correct-secret")
        raw_body = json.dumps(payload).encode()
        is_valid, _ = payment_routes._verify_ipn_signature(raw_body, sig, "wrong-secret")
        assert is_valid is False

    def test_missing_signature_header_rejected(self):
        raw_body = json.dumps({"order_id": "x"}).encode()
        is_valid, _ = payment_routes._verify_ipn_signature(raw_body, "", "shh")
        assert is_valid is False

    def test_missing_secret_rejected(self):
        raw_body = json.dumps({"order_id": "x"}).encode()
        is_valid, _ = payment_routes._verify_ipn_signature(raw_body, "somesig", "")
        assert is_valid is False

    def test_invalid_json_body_rejected(self):
        is_valid, parsed = payment_routes._verify_ipn_signature(b"not json", "somesig", "shh")
        assert is_valid is False
        assert parsed is None


# ── 3 & 4. Full-stack TestClient: create-invoice + webhook end to end ──────

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


def _seed_pending_payment(session_factory, **overrides) -> str:
    defaults = dict(
        order_id="reconpro|11111111-1111-1111-1111-111111111111|pro",
        email="buyer@example.com", tier="pro",
        price_amount=399.0, price_currency="usd", status="pending",
    )
    defaults.update(overrides)

    async def go():
        async with session_factory() as db:
            pending = PendingPayment(**defaults)
            db.add(pending)
            await db.commit()

    _run(go())
    return defaults["order_id"]


def _post_webhook(c, payload: dict, secret: str = "test-ipn-secret", bad_sig: bool = False):
    sig = "deadbeef" if bad_sig else _sign(payload, secret)
    raw = json.dumps(payload)
    return c.post(
        "/webhooks/nowpayments",
        content=raw,
        headers={"content-type": "application/json", "x-nowpayments-sig": sig},
    )


class TestCreateInvoiceEndpoint:
    def test_rejects_invalid_email(self, client):
        c, _ = client
        resp = c.post("/api/payments/create-invoice", json={"email": "not-an-email"})
        assert resp.status_code == 400

    def test_success_creates_pending_payment_and_returns_invoice_url(self, client, monkeypatch):
        c, session_factory = client

        async def fake_create_invoice(order_id, price_amount, customer_email, price_currency="usd"):
            return {"invoice_url": "https://nowpayments.io/pay/abc", "payment_id": "np_1", "raw": {}}

        monkeypatch.setattr(payment_routes, "create_invoice", fake_create_invoice)

        resp = c.post("/api/payments/create-invoice", json={"email": "Buyer@Example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["invoice_url"] == "https://nowpayments.io/pay/abc"
        order_id = data["order_id"]
        assert order_id.startswith("reconpro|")

        async def fetch():
            async with session_factory() as db:
                result = await db.execute(select(PendingPayment).where(PendingPayment.order_id == order_id))
                return result.scalar_one_or_none()

        pending = _run(fetch())
        assert pending is not None
        assert pending.email == "buyer@example.com"  # normalized lowercase
        assert pending.status == "pending"

    def test_nowpayments_failure_returns_502(self, client, monkeypatch):
        c, _ = client

        async def failing_create_invoice(*a, **kw):
            raise npc.NowPaymentsError("boom")

        monkeypatch.setattr(payment_routes, "create_invoice", failing_create_invoice)
        resp = c.post("/api/payments/create-invoice", json={"email": "buyer@example.com"})
        assert resp.status_code == 502


class TestStalePendingPaymentExpiry:
    """Point 2 of the 2026-09-04 UX audit fix: a PendingPayment stuck at
    status="pending" with no webhook ever arriving (no cron/worker exists
    in this deployment) must eventually be marked "expired" rather than
    sitting there forever. Swept opportunistically on each
    POST /api/payments/create-invoice call — see
    payment_routes._expire_stale_pending_payments()."""

    @pytest.fixture(autouse=True)
    def _reset_create_invoice_rate_limit(self):
        # web/rate_limit.py's _buckets dict is module-global and keyed by
        # client IP, not per-TestClient-instance — every test in this class
        # calls POST /api/payments/create-invoice, so without this reset
        # they'd collectively trip RATE_LIMIT_CREATE_INVOICE (default 5)
        # and start seeing 429s unrelated to what's under test here.
        import web.rate_limit as rate_limit
        rate_limit._buckets["payments_create_invoice"].clear()
        yield

    @staticmethod
    def _patch_create_invoice(monkeypatch):
        async def fake_create_invoice(order_id, price_amount, customer_email, price_currency="usd"):
            return {"invoice_url": "https://nowpayments.io/pay/new", "payment_id": "np_new", "raw": {}}
        monkeypatch.setattr(payment_routes, "create_invoice", fake_create_invoice)

    def test_pending_payment_older_than_24h_is_marked_expired(self, client, monkeypatch):
        c, session_factory = client
        self._patch_create_invoice(monkeypatch)
        stale_order_id = _seed_pending_payment(
            session_factory,
            order_id="reconpro|22222222-2222-2222-2222-222222222222|pro",
            created_at=datetime.utcnow() - timedelta(hours=25),
        )

        resp = c.post("/api/payments/create-invoice", json={"email": "new-buyer@example.com"})
        assert resp.status_code == 200

        async def fetch():
            async with session_factory() as db:
                return (await db.execute(
                    select(PendingPayment).where(PendingPayment.order_id == stale_order_id)
                )).scalar_one()

        pending = _run(fetch())
        assert pending.status == "expired"
        assert pending.license_key_hash is None  # never generates a key

    def test_pending_payment_within_24h_is_left_untouched(self, client, monkeypatch):
        c, session_factory = client
        self._patch_create_invoice(monkeypatch)
        recent_order_id = _seed_pending_payment(
            session_factory,
            order_id="reconpro|33333333-3333-3333-3333-333333333333|pro",
            created_at=datetime.utcnow() - timedelta(hours=1),
        )

        resp = c.post("/api/payments/create-invoice", json={"email": "new-buyer2@example.com"})
        assert resp.status_code == 200

        async def fetch():
            async with session_factory() as db:
                return (await db.execute(
                    select(PendingPayment).where(PendingPayment.order_id == recent_order_id)
                )).scalar_one()

        pending = _run(fetch())
        assert pending.status == "pending"

    def test_already_resolved_payment_is_never_touched_even_if_old(self, client, monkeypatch):
        c, session_factory = client
        self._patch_create_invoice(monkeypatch)
        completed_order_id = _seed_pending_payment(
            session_factory,
            order_id="reconpro|44444444-4444-4444-4444-444444444444|pro",
            created_at=datetime.utcnow() - timedelta(hours=48),
            status="completed",
            license_key_hash="deadbeef" * 8,
        )

        resp = c.post("/api/payments/create-invoice", json={"email": "new-buyer3@example.com"})
        assert resp.status_code == 200

        async def fetch():
            async with session_factory() as db:
                return (await db.execute(
                    select(PendingPayment).where(PendingPayment.order_id == completed_order_id)
                )).scalar_one()

        pending = _run(fetch())
        assert pending.status == "completed"  # untouched, not clobbered to "expired"

    def test_custom_expiry_window_env_var_is_honored(self, monkeypatch, client):
        c, session_factory = client
        self._patch_create_invoice(monkeypatch)
        monkeypatch.setenv("PENDING_PAYMENT_EXPIRY_HOURS", "1")
        order_id = _seed_pending_payment(
            session_factory,
            order_id="reconpro|55555555-5555-5555-5555-555555555555|pro",
            created_at=datetime.utcnow() - timedelta(hours=2),
        )

        resp = c.post("/api/payments/create-invoice", json={"email": "new-buyer4@example.com"})
        assert resp.status_code == 200

        async def fetch():
            async with session_factory() as db:
                return (await db.execute(
                    select(PendingPayment).where(PendingPayment.order_id == order_id)
                )).scalar_one()

        pending = _run(fetch())
        assert pending.status == "expired"


class TestWebhookSignatureGate:
    def test_forged_signature_is_rejected_with_401(self, client):
        c, session_factory = client
        order_id = _seed_pending_payment(session_factory)
        resp = _post_webhook(c, {"order_id": order_id, "payment_id": "p1", "payment_status": "finished"},
                              bad_sig=True)
        assert resp.status_code == 401

    def test_valid_signature_is_accepted(self, client):
        c, session_factory = client
        order_id = _seed_pending_payment(session_factory)
        resp = _post_webhook(c, {"order_id": order_id, "payment_id": "p1", "payment_status": "waiting"})
        assert resp.status_code == 200


class TestWebhookFinishedGeneratesLicenseOnce:
    def test_finished_status_generates_and_stores_one_license_key(self, client):
        c, session_factory = client
        order_id = _seed_pending_payment(session_factory)

        resp = _post_webhook(c, {"order_id": order_id, "payment_id": "p1", "payment_status": "finished"})
        assert resp.status_code == 200

        async def fetch():
            async with session_factory() as db:
                pending = (await db.execute(
                    select(PendingPayment).where(PendingPayment.order_id == order_id)
                )).scalar_one()
                keys = (await db.execute(select(LicenseKey))).scalars().all()
                return pending, keys

        pending, keys = _run(fetch())
        assert pending.status == "completed"
        assert pending.license_key_hash is not None
        assert len(keys) == 1
        assert keys[0].key_hash == pending.license_key_hash
        assert keys[0].tier == "pro"
        assert keys[0].redeemed_by is None  # not tied to any account yet

    def test_idempotent_replay_of_same_finished_notification_does_not_double_issue(self, client):
        c, session_factory = client
        order_id = _seed_pending_payment(session_factory)

        first = _post_webhook(c, {"order_id": order_id, "payment_id": "p1", "payment_status": "finished"})
        second = _post_webhook(c, {"order_id": order_id, "payment_id": "p1", "payment_status": "finished"})
        assert first.status_code == 200
        assert second.status_code == 200
        assert second.json()["status"] == "already_processed"

        async def fetch_keys():
            async with session_factory() as db:
                return (await db.execute(select(LicenseKey))).scalars().all()

        keys = _run(fetch_keys())
        assert len(keys) == 1


class TestWebhookNonFinishedStatuses:
    @pytest.mark.parametrize("status", ["failed", "expired", "refunded"])
    def test_terminal_failure_statuses_generate_no_key(self, client, status):
        c, session_factory = client
        order_id = _seed_pending_payment(session_factory)

        resp = _post_webhook(c, {"order_id": order_id, "payment_id": "p1", "payment_status": status})
        assert resp.status_code == 200

        async def fetch():
            async with session_factory() as db:
                pending = (await db.execute(
                    select(PendingPayment).where(PendingPayment.order_id == order_id)
                )).scalar_one()
                keys = (await db.execute(select(LicenseKey))).scalars().all()
                return pending, keys

        pending, keys = _run(fetch())
        assert pending.status == status
        assert pending.license_key_hash is None
        assert keys == []

    def test_partially_paid_generates_no_key_and_records_status(self, client):
        c, session_factory = client
        order_id = _seed_pending_payment(session_factory)

        resp = _post_webhook(c, {"order_id": order_id, "payment_id": "p1", "payment_status": "partially_paid"})
        assert resp.status_code == 200

        async def fetch():
            async with session_factory() as db:
                pending = (await db.execute(
                    select(PendingPayment).where(PendingPayment.order_id == order_id)
                )).scalar_one()
                keys = (await db.execute(select(LicenseKey))).scalars().all()
                return pending, keys

        pending, keys = _run(fetch())
        assert pending.status == "partially_paid"
        assert pending.license_key_hash is None
        assert keys == []

    def test_unknown_order_id_is_ignored_not_errored(self, client):
        c, _ = client
        resp = _post_webhook(c, {"order_id": "reconpro|does-not-exist|pro",
                                  "payment_id": "p1", "payment_status": "finished"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"


class TestGeneratedKeyIsRedeemable:
    def test_raw_key_delivered_to_outbox_actually_verifies_against_stored_hash(self, client, monkeypatch, tmp_path):
        import web.services.email_delivery as email_delivery
        monkeypatch.setattr(email_delivery, "OUTBOX_DIR", tmp_path)

        c, session_factory = client
        order_id = _seed_pending_payment(session_factory, email="realbuyer@example.com")
        resp = _post_webhook(c, {"order_id": order_id, "payment_id": "p1", "payment_status": "finished"})
        assert resp.status_code == 200

        files = list(tmp_path.glob("*.txt"))
        assert len(files) == 1
        content = files[0].read_text()
        assert "realbuyer@example.com" in content

        raw_key = [line.split("=", 1)[1] for line in content.splitlines() if line.startswith("license_key=")][0]

        async def fetch_hash():
            async with session_factory() as db:
                pending = (await db.execute(
                    select(PendingPayment).where(PendingPayment.order_id == order_id)
                )).scalar_one()
                return pending.license_key_hash

        stored_hash = _run(fetch_hash())
        assert verify_key_hash(raw_key, stored_hash)
