"""
Tests for web/routers/bug_bounty.py's submission-time guards, added because
h1_submit/bc_submit had none: HACKERONE_API_TOKEN/BUGCROWD_API_TOKEN are a
single instance-wide credential (os.environ), so any PRO/ENTERPRISE user
could fire an unlimited number of real submissions under the platform's own
shared HackerOne/Bugcrowd identity, with no record of which OPTISEC account
triggered which report and no per-user cap.

Fixes covered:
  - BugBountySubmission audit row written on every submit call (success,
    demo, or error), keyed to user_id (web/models.py).
  - Per-user submission quota (_enforce_submission_quota), enforced via
    BugBountySubmission row counts rather than the in-memory per-IP
    rate_limiter() -- see RATE_LIMIT_BUG_BOUNTY_SUBMIT.
  - bc_submit no longer silently drops a caller-supplied vrt_id in favor of
    the router's hardcoded default.
  - Empty program/title fields are rejected with 400 before ever reaching
    the external API.
  - Preview/confirm gate (_require_confirmation): /submit refuses to call
    submit_report/bc_submit_report at all unless the caller first hit
    /submit/preview for this *exact* report content and echoed back
    'confirmed': true plus the resulting confirm_token. Missing, stale, or
    content-mismatched tokens are rejected with 400 -- proving a real
    HackerOne/Bugcrowd submission cannot happen without an explicit,
    per-report human confirmation step.

Same TestClient + dependency-override approach as
tests/test_csrf_protection.py, adapted for bug_bounty.router's own local
`_user` dependency (not web.app's `web_user`). The lazy `from
modules.bug_bounty.hackerone import submit_report` / `... bugcrowd import
bc_submit_report` inside each endpoint re-binds from the module's current
attribute on every call, so monkeypatching submit_report/bc_submit_report
directly on those modules intercepts it without touching httpx.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User, BugBountySubmission
import web.app as app_module
import web.routers.bug_bounty as bb_module
import modules.bug_bounty.hackerone as hackerone
import modules.bug_bounty.bugcrowd as bugcrowd


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def env():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with TestSessionLocal() as session:
            user = User(
                username="researcher", email="researcher@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused-1",
                subscription_tier="pro",
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return user.id

    user_id = _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            result = await session.execute(select(User).where(User.id == user_id))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[bb_module._user] = _user_override
    test_client = TestClient(app_module.app)
    yield test_client, TestSessionLocal, user_id
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def _submit_payload(**overrides):
    payload = {
        "program_handle": "shopify", "program_code": "shopify",
        "title": "Reflected XSS in search", "severity": "high",
        "description": "desc", "impact": "impact", "steps": "1,2,3",
    }
    payload.update(overrides)
    return payload


def _preview_and_confirm(client, platform, payload):
    """Hits /submit/preview for `platform` with `payload`, then returns a
    submit-ready copy carrying 'confirmed': True plus the confirm_token that
    call returned -- exercises the real preview-then-confirm flow instead of
    forging a token by hand."""
    resp = client.post(f"/bug-bounty/api/{platform}/submit/preview", json=payload)
    assert resp.status_code == 200, resp.text
    confirmed = dict(payload)
    confirmed["confirmed"] = True
    confirmed["confirm_token"] = resp.json()["confirm_token"]
    return confirmed


# ─── Audit trail ────────────────────────────────────────────────────────────

def test_hackerone_submit_writes_audit_row(env, monkeypatch):
    client, SessionLocal, user_id = env

    async def fake_submit_report(**kwargs):
        return {"status": "submitted", "report_id": "R1", "url": "https://hackerone.com/reports/R1"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    payload = _preview_and_confirm(client, "hackerone", _submit_payload())
    resp = client.post("/bug-bounty/api/hackerone/submit", json=payload)
    assert resp.status_code == 200

    async def _fetch():
        async with SessionLocal() as session:
            rows = (await session.execute(select(BugBountySubmission))).scalars().all()
            return rows

    rows = _run(_fetch())
    assert len(rows) == 1
    assert rows[0].user_id == user_id
    assert rows[0].platform == "hackerone"
    assert rows[0].status == "submitted"
    assert rows[0].external_ref == "R1"


def test_bugcrowd_submit_writes_audit_row_even_on_demo_status(env, monkeypatch):
    client, SessionLocal, user_id = env

    async def fake_bc_submit(**kwargs):
        return {"status": "demo", "message": "Set BUGCROWD_API_TOKEN to submit real reports"}

    monkeypatch.setattr(bugcrowd, "bc_submit_report", fake_bc_submit)

    payload = _preview_and_confirm(client, "bugcrowd", _submit_payload())
    resp = client.post("/bug-bounty/api/bugcrowd/submit", json=payload)
    assert resp.status_code == 200

    async def _fetch():
        async with SessionLocal() as session:
            rows = (await session.execute(select(BugBountySubmission))).scalars().all()
            return rows

    rows = _run(_fetch())
    assert len(rows) == 1
    assert rows[0].user_id == user_id
    assert rows[0].platform == "bugcrowd"
    assert rows[0].status == "demo"


# ─── Per-user submission quota ──────────────────────────────────────────────

def test_submission_quota_blocks_after_limit_reached(env, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_BUG_BOUNTY_SUBMIT", "2")
    client, SessionLocal, user_id = env

    async def fake_submit_report(**kwargs):
        return {"status": "submitted", "report_id": "R"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    confirmed = _preview_and_confirm(client, "hackerone", _submit_payload())
    r1 = client.post("/bug-bounty/api/hackerone/submit", json=confirmed)
    r2 = client.post("/bug-bounty/api/hackerone/submit", json=confirmed)
    r3 = client.post("/bug-bounty/api/hackerone/submit", json=confirmed)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    # web/app.py's on_http_exception handler reshapes HTTPException(detail=...)
    # into {"error": ...}, not FastAPI's default {"detail": ...}.
    assert "abuse" in r3.json()["error"] or "limit" in r3.json()["error"].lower()


def test_submission_quota_is_shared_across_platforms_per_user(env, monkeypatch):
    """The quota exists to protect the shared platform-wide credential, not
    a single platform's credential -- it must count HackerOne and Bugcrowd
    submissions from the same user together."""
    monkeypatch.setenv("RATE_LIMIT_BUG_BOUNTY_SUBMIT", "1")
    client, SessionLocal, user_id = env

    async def fake_submit_report(**kwargs):
        return {"status": "submitted"}

    async def fake_bc_submit(**kwargs):
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)
    monkeypatch.setattr(bugcrowd, "bc_submit_report", fake_bc_submit)

    r1 = client.post("/bug-bounty/api/hackerone/submit", json=_preview_and_confirm(client, "hackerone", _submit_payload()))
    r2 = client.post("/bug-bounty/api/bugcrowd/submit", json=_preview_and_confirm(client, "bugcrowd", _submit_payload()))

    assert r1.status_code == 200
    assert r2.status_code == 429


def test_submission_quota_does_not_count_another_users_submissions(env, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_BUG_BOUNTY_SUBMIT", "1")
    client, SessionLocal, user_id = env

    async def fake_submit_report(**kwargs):
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    async def _seed_other_user_submission():
        async with SessionLocal() as session:
            session.add(BugBountySubmission(
                user_id=user_id + 999, platform="hackerone", program="x",
                title="x", severity="low", status="submitted",
            ))
            await session.commit()

    _run(_seed_other_user_submission())

    resp = client.post("/bug-bounty/api/hackerone/submit", json=_preview_and_confirm(client, "hackerone", _submit_payload()))
    assert resp.status_code == 200  # this user's own quota is still fresh


# ─── vrt_id passthrough (Bugcrowd) ──────────────────────────────────────────

def test_bugcrowd_submit_forwards_caller_supplied_vrt_id(env, monkeypatch):
    client, SessionLocal, user_id = env
    captured = {}

    async def fake_bc_submit(**kwargs):
        captured.update(kwargs)
        return {"status": "submitted", "id": "S1"}

    monkeypatch.setattr(bugcrowd, "bc_submit_report", fake_bc_submit)

    payload = _preview_and_confirm(client, "bugcrowd", _submit_payload(vrt_id="cross_site_scripting"))
    resp = client.post("/bug-bounty/api/bugcrowd/submit", json=payload)
    assert resp.status_code == 200
    assert captured["vrt_id"] == "cross_site_scripting"


def test_bugcrowd_submit_falls_back_to_default_vrt_id_when_omitted(env, monkeypatch):
    client, SessionLocal, user_id = env
    captured = {}

    async def fake_bc_submit(**kwargs):
        captured.update(kwargs)
        return {"status": "submitted", "id": "S1"}

    monkeypatch.setattr(bugcrowd, "bc_submit_report", fake_bc_submit)

    payload = _preview_and_confirm(client, "bugcrowd", _submit_payload())
    resp = client.post("/bug-bounty/api/bugcrowd/submit", json=payload)
    assert resp.status_code == 200
    assert captured["vrt_id"] == "server_security_misconfiguration"


# ─── Input validation ───────────────────────────────────────────────────────

def test_hackerone_submit_rejects_empty_title(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_submit_report(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    resp = client.post("/bug-bounty/api/hackerone/submit", json=_submit_payload(title=""))
    assert resp.status_code == 400
    assert not called  # rejected before ever calling out to the external module


def test_bugcrowd_submit_rejects_missing_program_code(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_bc_submit(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(bugcrowd, "bc_submit_report", fake_bc_submit)

    resp = client.post("/bug-bounty/api/bugcrowd/submit", json=_submit_payload(program_code=""))
    assert resp.status_code == 400
    assert not called


# ─── Preview / confirm gate — submission impossible without confirmation ───

def test_hackerone_submit_rejected_without_any_confirmation_fields(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_submit_report(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    resp = client.post("/bug-bounty/api/hackerone/submit", json=_submit_payload())
    assert resp.status_code == 400
    assert not called  # no real HackerOne call happens without confirmation


def test_hackerone_submit_rejected_with_confirmed_true_but_no_token(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_submit_report(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    resp = client.post(
        "/bug-bounty/api/hackerone/submit",
        json=_submit_payload(confirmed=True),
    )
    assert resp.status_code == 400
    assert not called  # setting confirmed=true alone is not enough


def test_hackerone_submit_rejected_when_content_edited_after_preview(env, monkeypatch):
    """A confirm_token is bound to the exact previewed content -- changing
    so much as the title afterward must invalidate it and block submission,
    otherwise a preview of one report could rubber-stamp a different one."""
    client, SessionLocal, user_id = env
    called = []

    async def fake_submit_report(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    confirmed = _preview_and_confirm(client, "hackerone", _submit_payload())
    confirmed["title"] = "A completely different report title"

    resp = client.post("/bug-bounty/api/hackerone/submit", json=confirmed)
    assert resp.status_code == 400
    assert not called


def test_hackerone_submit_rejected_with_another_users_confirm_token(env, monkeypatch):
    """A confirm_token is bound to the confirming user_id too, so it can't
    be replayed by a different account."""
    client, SessionLocal, user_id = env
    called = []

    async def fake_submit_report(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    payload = _submit_payload()
    canonical = bb_module._canonical_report(
        "hackerone", user_id + 999, program_handle=payload["program_handle"],
        title=payload["title"], severity=payload["severity"],
        description=payload["description"], impact=payload["impact"], steps=payload["steps"],
    )
    forged = dict(payload)
    forged["confirmed"] = True
    forged["confirm_token"] = bb_module._make_confirm_token(canonical)

    resp = client.post("/bug-bounty/api/hackerone/submit", json=forged)
    assert resp.status_code == 400
    assert not called


def test_hackerone_submit_rejected_with_expired_confirm_token(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_submit_report(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    confirmed = _preview_and_confirm(client, "hackerone", _submit_payload())

    # Jump the clock past the token's TTL before submitting.
    real_time = bb_module.time.time
    monkeypatch.setattr(
        bb_module.time, "time",
        lambda: real_time() + bb_module.CONFIRM_TOKEN_TTL_SECONDS + 30,
    )

    resp = client.post("/bug-bounty/api/hackerone/submit", json=confirmed)
    assert resp.status_code == 400
    assert not called


def test_hackerone_submit_preview_never_calls_submit_report(env, monkeypatch):
    """Hitting /submit/preview must only render a draft -- it must never
    itself trigger the real HackerOne API call."""
    client, SessionLocal, user_id = env
    called = []

    async def fake_submit_report(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    resp = client.post("/bug-bounty/api/hackerone/submit/preview", json=_submit_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert "confirm_token" in body and body["confirm_token"]
    assert "**Impact**" in body["body_preview"]
    assert not called


def test_hackerone_submit_succeeds_with_valid_preview_confirmation(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_submit_report(**kwargs):
        called.append(1)
        return {"status": "submitted", "report_id": "R9"}

    monkeypatch.setattr(hackerone, "submit_report", fake_submit_report)

    confirmed = _preview_and_confirm(client, "hackerone", _submit_payload())
    resp = client.post("/bug-bounty/api/hackerone/submit", json=confirmed)
    assert resp.status_code == 200
    assert called == [1]


def test_bugcrowd_submit_rejected_without_confirmation(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_bc_submit(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(bugcrowd, "bc_submit_report", fake_bc_submit)

    resp = client.post("/bug-bounty/api/bugcrowd/submit", json=_submit_payload())
    assert resp.status_code == 400
    assert not called


def test_bugcrowd_submit_rejected_when_vrt_id_edited_after_preview(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_bc_submit(**kwargs):
        called.append(1)
        return {"status": "submitted"}

    monkeypatch.setattr(bugcrowd, "bc_submit_report", fake_bc_submit)

    confirmed = _preview_and_confirm(client, "bugcrowd", _submit_payload())
    confirmed["vrt_id"] = "sql_injection"

    resp = client.post("/bug-bounty/api/bugcrowd/submit", json=confirmed)
    assert resp.status_code == 400
    assert not called


def test_bugcrowd_submit_succeeds_with_valid_preview_confirmation(env, monkeypatch):
    client, SessionLocal, user_id = env
    called = []

    async def fake_bc_submit(**kwargs):
        called.append(1)
        return {"status": "submitted", "id": "S9"}

    monkeypatch.setattr(bugcrowd, "bc_submit_report", fake_bc_submit)

    confirmed = _preview_and_confirm(client, "bugcrowd", _submit_payload())
    resp = client.post("/bug-bounty/api/bugcrowd/submit", json=confirmed)
    assert resp.status_code == 200
    assert called == [1]
