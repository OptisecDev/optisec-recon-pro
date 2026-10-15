"""
Server-side coverage for the scan-authorization UI (step 4):

  * GET /api/scan-authorization -- the no-network preview the scan page uses
    to lock modules before the user hits Start.
  * /targets -- per-target authorization badge, Verify button, and the
    domain-verification card (escaping included).
  * /scan -- the hooks the page script relies on are present.

Browser behaviour (locking checkboxes, rendering a 403) is covered for real
in tests/test_scan_authz_playwright.py.
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import modules.scan_scope as scan_scope_module
import web.app as app_module
import web.domain_verification as dv
import web.rate_limit as rate_limit
from web.auth import create_access_token, generate_csrf_token
from web.database import Base, get_db
from web.models import DomainVerification, Target, User
from web.scan_authz import ACTIVE_CHECKS, PASSIVE_CHECKS, SCAN_STEP_ORDER


CSRF_SECRET = "scan-authz-test-csrf-secret"

def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    rate_limit._buckets.clear()
    monkeypatch.delenv("SCAN_AUTHZ_ENFORCE", raising=False)

    async def no_network(*a, **k):
        raise AssertionError("the preview/UI must never run a DNS/HTTP ownership check")
    monkeypatch.setattr(dv, "check_dns_txt", no_network)
    monkeypatch.setattr(dv, "check_http_file", no_network)
    # network_scope_for() resolves the scope's hosts; keep that offline.
    monkeypatch.setattr(scan_scope_module, "_resolve", lambda host: {"93.184.216.34"})
    yield
    rate_limit._buckets.clear()


@pytest.fixture
def env():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    sf = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())

    async def override_get_db():
        async with sf() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    # POST /api/scan, /api/scan/ports and /api/osint require X-CSRF-Token
    # for cookie auth; every session cookie set below carries CSRF_SECRET.
    client = TestClient(app_module.app, headers={"X-CSRF-Token": generate_csrf_token(CSRF_SECRET)})
    yield client, sf
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _seed(sf, username="alice", role="analyst", verifications=(), targets=()):
    """verifications: (domain, method, status, last_checked_at, last_error)"""
    async def go():
        async with sf() as db:
            u = User(
                username=username, email=f"{username}@example.com", password_hash="x",
                role=role, subscription_tier="enterprise", is_active=True,
            )
            db.add(u)
            await db.flush()
            for i, (domain, method, status, checked, err) in enumerate(verifications):
                db.add(DomainVerification(
                    user_id=u.id, domain=domain, method=method, token=f"{username}-{i}",
                    status=status, last_checked_at=checked, last_error=err,
                    verified_at=checked if status == "verified" else None,
                ))
            ids = {}
            for url in targets:
                t = Target(user_id=u.id, url=url, name="")
                db.add(t)
                await db.flush()
                ids[url] = t.id
            await db.commit()
            return u.id, ids
    uid, ids = _run(go())
    return {"access_token": create_access_token(uid, role), "csrf_secret": CSRF_SECRET}, ids


NOW = datetime.utcnow()
VERIFIED = ("example.com", "dns_txt", "verified", NOW, None)


# ── GET /api/scan-authorization ──────────────────────────────────────────────

def test_preview_unverified(env):
    c, sf = env
    cookies, _ = _seed(sf)
    r = c.get("/api/scan-authorization", params={"target": "https://unverified.test/x"}, cookies=cookies)
    assert r.status_code == 200
    body = r.json()
    assert body["host"] == "unverified.test"
    assert body["basis"] == "passive_only"
    assert set(body["allowed"]) == PASSIVE_CHECKS
    assert set(body["denied"]) == ACTIVE_CHECKS
    assert set(body["passive"]) == PASSIVE_CHECKS
    assert set(body["active"]) == ACTIVE_CHECKS
    assert body["allowed"] == [c for c in SCAN_STEP_ORDER if c in PASSIVE_CHECKS]


def test_preview_verified_subdomain(env):
    c, sf = env
    cookies, _ = _seed(sf, verifications=[VERIFIED])
    body = c.get("/api/scan-authorization", params={"target": "shop.example.com"}, cookies=cookies).json()
    assert body["basis"] == "verified:dns_txt:example.com"
    assert body["allowed"] == list(SCAN_STEP_ORDER)
    assert body["denied"] == []


def test_preview_stale_verification_does_not_trigger_network(env):
    """The autouse fixture fails the test if a re-check runs."""
    c, sf = env
    stale = ("example.com", "dns_txt", "verified", NOW - timedelta(days=60), None)
    cookies, _ = _seed(sf, verifications=[stale])
    body = c.get("/api/scan-authorization", params={"target": "example.com"}, cookies=cookies).json()
    assert body["basis"] == "verified:dns_txt:example.com"


@pytest.mark.parametrize("status", ["pending", "failed", "revoked"])
def test_preview_ignores_unverified_records(env, status):
    c, sf = env
    cookies, _ = _seed(sf, verifications=[("example.com", "dns_txt", status, NOW, None)])
    body = c.get("/api/scan-authorization", params={"target": "example.com"}, cookies=cookies).json()
    assert body["basis"] == "passive_only"


def test_preview_other_users_verification_ignored(env):
    c, sf = env
    _seed(sf, "owner", verifications=[VERIFIED])
    cookies, _ = _seed(sf, "other")
    body = c.get("/api/scan-authorization", params={"target": "example.com"}, cookies=cookies).json()
    assert body["basis"] == "passive_only"


def test_preview_training_target(env):
    c, sf = env
    cookies, _ = _seed(sf)
    body = c.get("/api/scan-authorization", params={"target": "scanme.nmap.org"}, cookies=cookies).json()
    assert body["basis"] == "training:scanme.nmap.org"
    assert {"nmap", "ports"} <= set(body["allowed"])
    assert "xss" in body["denied"]


def test_preview_log_only_mode_allows_everything(env, monkeypatch):
    monkeypatch.setenv("SCAN_AUTHZ_ENFORCE", "false")
    c, sf = env
    cookies, _ = _seed(sf)
    body = c.get("/api/scan-authorization", params={"target": "unverified.test"}, cookies=cookies).json()
    assert body["basis"] == "unenforced:passive_only"
    assert body["denied"] == []


def test_preview_requires_target_and_auth(env):
    c, sf = env
    cookies, _ = _seed(sf)
    assert c.get("/api/scan-authorization", params={"target": "  "}, cookies=cookies).status_code == 400
    assert c.get("/api/scan-authorization", params={"target": "example.com"}).status_code == 401


def test_preview_agrees_with_real_gate(env, monkeypatch):
    """What the preview allows for a fresh record is exactly what POST
    /api/scan accepts -- the page must never offer a module the gate refuses."""
    c, sf = env
    cookies, _ = _seed(sf, verifications=[("app.example.org", "http_file", "verified", NOW, None)])

    async def fake_task(*a, **k):
        return None
    monkeypatch.setattr(app_module, "_run_scan_task", fake_task)
    for target in ["app.example.org", "www.app.example.org", "scanme.nmap.org", "unverified.test"]:
        preview = c.get("/api/scan-authorization", params={"target": target}, cookies=cookies).json()
        ok = c.post("/api/scan", json={"target": target, "scan_types": preview["allowed"]}, cookies=cookies)
        assert ok.status_code == 200, (target, ok.text)
        if preview["denied"]:
            refused = c.post("/api/scan", json={"target": target, "scan_types": preview["denied"][:1]}, cookies=cookies)
            assert refused.status_code == 403, target


# ── /targets ─────────────────────────────────────────────────────────────────

def _row(html, target_id):
    start = html.index(f'id="target-row-{target_id}"')
    return html[start:html.index("</tr>", start)]


def test_targets_page_badges_and_verify_button(env):
    c, sf = env
    cookies, ids = _seed(
        sf, verifications=[VERIFIED],
        targets=["https://shop.example.com", "http://scanme.nmap.org", "https://other.test", "http://93.184.216.34/"],
    )
    html = c.get("/targets", cookies=cookies).text

    verified = _row(html, ids["https://shop.example.com"])
    assert "✓ Verified" in verified and "verifyTarget" not in verified

    training = _row(html, ids["http://scanme.nmap.org"])
    assert "Training" in training and "verifyTarget" not in training

    passive = _row(html, ids["https://other.test"])
    assert "Passive only" in passive
    assert "data-onclick=\"verifyTarget\" data-onclick-args='[\"other.test\"]'" in passive

    ip = _row(html, ids["http://93.184.216.34/"])
    assert "Passive only" in ip and "verifyTarget" not in ip


def test_targets_page_lists_verifications_escaped(env):
    c, sf = env
    cookies, _ = _seed(sf, verifications=[
        VERIFIED,
        ("pending.test", "http_file", "failed", NOW, "<script>alert(1)</script>"),
    ])
    html = c.get("/targets", cookies=cookies).text
    assert 'id="verify-card"' in html
    assert 'id="verify-domain"' in html
    assert "example.com" in html and "pending.test" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'data-onclick="checkVerification"' in html


def test_targets_page_viewer_gets_no_verification_controls(env):
    c, sf = env
    cookies, _ = _seed(sf, "victor", role="viewer", verifications=[VERIFIED], targets=["https://other.test"])
    html = c.get("/targets", cookies=cookies).text
    assert 'id="verify-domain"' not in html
    assert 'data-onclick="verifyTarget"' not in html
    assert 'data-onclick="checkVerification"' not in html
    assert "Passive only" in html


def test_targets_page_log_only_badge(env, monkeypatch):
    monkeypatch.setenv("SCAN_AUTHZ_ENFORCE", "false")
    c, sf = env
    cookies, ids = _seed(sf, targets=["https://other.test"])
    assert "Not enforced" in _row(c.get("/targets", cookies=cookies).text, ids["https://other.test"])


# ── /scan ────────────────────────────────────────────────────────────────────

def test_scan_page_has_authorization_hooks(env):
    c, sf = env
    cookies, _ = _seed(sf)
    html = c.get("/scan", cookies=cookies).text
    assert 'id="authz-status"' in html
    assert 'data-oninput="scheduleAuthzCheck"' in html
    assert "/api/scan-authorization?target=" in html
    assert "denied_checks" in html  # 403 rendering path in startScan
