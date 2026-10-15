"""
CSRF protection on the cookie-authenticated scan endpoints: POST /api/scan,
/api/scan/ports and /api/osint (web/app.py _require_csrf_for_cookie_auth).

These routes launch outbound scans on the caller's behalf but accepted a
bare cookie-authenticated POST, so any page the victim visited could start
scans from their account. They now require the same double-submit
X-CSRF-Token as DELETE /targets/{id} and /api/domains/*; the token reaches
the browser through base.html's csrf-token meta tag. X-API-Key and Bearer
clients are exempt, as in web/routers/domain_verification.py, since a
cross-site page can't make the browser attach either header.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import web.app as app_module
import web.domain_verification as dv
import web.rate_limit as rate_limit
from web.auth import create_access_token, generate_csrf_token
from web.database import Base, get_db
from web.models import User
from web.shared_templates import csrf_token_for

CSRF_SECRET = "scan-csrf-test-secret"

ROUTES = [
    ("/api/scan", {"target": "scanme.nmap.org", "scan_types": ["dns"]}),
    ("/api/scan/ports", {"target": "scanme.nmap.org"}),
    ("/api/osint", {"domain": "example.com"}),
]


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def env(monkeypatch):
    rate_limit._buckets.clear()
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    sf = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with sf() as db:
            u = User(
                username="alice", email="alice@example.com", password_hash="x",
                role="analyst", subscription_tier="enterprise", is_active=True,
            )
            db.add(u)
            await db.commit()
            return u.id
    uid = _run(setup())

    async def override_get_db():
        async with sf() as session:
            yield session

    # Nothing may actually run: record what would have.
    ran = []

    async def fake_task(*a, **k):
        ran.append("scan")
    monkeypatch.setattr(app_module, "_run_scan_task", fake_task)
    monkeypatch.setattr(app_module, "nmap_scan", lambda t: ran.append("nmap") or {})

    async def fake_auth(*a, **k):
        ran.append("osint")
        from web.scan_authz import AuthzDecision
        return AuthzDecision(allowed=set(), denied={"subdomain"}, reason="x")
    monkeypatch.setattr(app_module, "check_scan_authorization", fake_auth)

    async def no_dns(host):
        return ["93.184.216.34"]

    async def empty(domain):
        return {}
    monkeypatch.setattr(dv, "_resolve_addresses", no_dns)
    monkeypatch.setattr(app_module, "find_emails", empty)
    monkeypatch.setattr(app_module, "find_social_profiles", empty)
    monkeypatch.setattr(app_module, "dns_lookup", lambda d: {})
    monkeypatch.setattr(app_module, "whois_lookup", lambda d: {})
    monkeypatch.setattr(app_module, "enumerate_subdomains", lambda d, passive=False: {"subdomains": [], "unconfirmed": []})

    app_module.app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app_module.app), uid, ran
    app_module.app.dependency_overrides.pop(get_db, None)
    rate_limit._buckets.clear()
    _run(engine.dispose())


def _cookies(uid):
    return {"access_token": create_access_token(uid, "analyst"), "csrf_secret": CSRF_SECRET}


@pytest.mark.parametrize("path,body", ROUTES)
def test_post_without_csrf_token_is_rejected(env, path, body):
    c, uid, ran = env
    r = c.post(path, json=body, cookies=_cookies(uid))
    assert r.status_code == 403
    assert "CSRF" in r.text
    assert ran == []


@pytest.mark.parametrize("path,body", ROUTES)
def test_post_with_wrong_csrf_token_is_rejected(env, path, body):
    c, uid, ran = env
    r = c.post(path, json=body, cookies=_cookies(uid), headers={"X-CSRF-Token": "0" * 64})
    assert r.status_code == 403
    assert ran == []


@pytest.mark.parametrize("path,body", ROUTES)
def test_token_for_another_session_is_rejected(env, path, body):
    c, uid, ran = env
    r = c.post(
        path, json=body, cookies=_cookies(uid),
        headers={"X-CSRF-Token": generate_csrf_token("someone-elses-secret")},
    )
    assert r.status_code == 403
    assert ran == []


@pytest.mark.parametrize("path,body", ROUTES)
def test_post_with_valid_csrf_token_passes_the_check(env, path, body):
    c, uid, ran = env
    r = c.post(path, json=body, cookies=_cookies(uid), headers={"X-CSRF-Token": generate_csrf_token(CSRF_SECRET)})
    assert "CSRF" not in r.text
    assert ran  # reached the route body


@pytest.mark.parametrize("path,body", ROUTES)
def test_bearer_clients_are_exempt(env, path, body):
    c, uid, ran = env
    token = create_access_token(uid, "analyst")
    r = c.post(path, json=body, headers={"Authorization": f"Bearer {token}"})
    assert "CSRF" not in r.text
    assert ran


def test_pages_expose_the_session_token_in_a_meta_tag(env):
    c, uid, _ = env
    r = c.get("/scan", cookies=_cookies(uid))
    assert r.status_code == 200
    assert f'<meta name="csrf-token" content="{generate_csrf_token(CSRF_SECRET)}">' in r.text


def test_csrf_token_for_without_cookie_is_empty():
    class Req:
        cookies = {}
    assert csrf_token_for(Req()) == ""
    assert csrf_token_for(None) == ""


def test_frontend_sends_the_token_on_scan_requests():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    main_js = open(os.path.join(root, "web", "static", "js", "main.js"), encoding="utf-8").read()
    scan_html = open(os.path.join(root, "web", "templates", "scan.html"), encoding="utf-8").read()
    assert "'X-CSRF-Token': csrfToken()" in main_js.split("async get(")[0]  # API.post
    assert "'X-CSRF-Token': csrfToken()" in scan_html
