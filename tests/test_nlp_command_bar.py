"""
Tests for the top-of-page NLP command bar (web/templates/base.html's
`.nlp-bar` input + Go button -> web/static/js/main.js runNLPCommand() ->
POST /api/nlp -> web/app.py nlp_parse()).

A support ticket reported the bar appearing to freeze silently in Firefox
(no network request, an unhandled "TypeError: NetworkError" in the
console). Live investigation (curl + a full authenticated Playwright
click-through in Chromium) could not reproduce a code defect: the fetch
URL is a literal '/api/nlp' string and the endpoint responds correctly.
The most likely explanation was a stale cached web/static/js/main.js from
before 8b2d453 (content-hash cache-busting), which the user should clear
by hard-refreshing. Regardless of that root cause, two real gaps existed
and are fixed alongside these tests:

  1. runNLPCommand() had no try/catch around its fetch -- any genuine
     network failure became a silent unhandled promise rejection with no
     user feedback and no way to retry (the Go button stayed disabled
     forever in appearance, though it was never actually touched).
  2. nlp_parse() called `await request.json()` unguarded -- a malformed
     JSON body was an unhandled exception -> opaque 500, instead of an
     explicit 400.

Same TestClient + in-memory-sqlite + dependency-override approach as
tests/test_csrf_protection.py. /api/nlp does not check CSRF (it's a
read-only parse, not a state-changing action), so no CSRF cookie/token
dance is needed here.
"""

import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
from web.models import User
import web.app as app_module

FAKE_SESSION_COOKIE = "fixture-session-value"


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client():
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
                username="analyst", email="analyst@example.com", password_hash="x",
                role="analyst", is_active=True, api_key_hash="unused",
            )
            session.add(user)
            await session.commit()

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    async def _user_override():
        async with TestSessionLocal() as session:
            from sqlalchemy import select
            result = await session.execute(select(User).where(User.username == "analyst"))
            return result.scalar_one()

    app_module.app.dependency_overrides[get_db] = _get_db_override
    app_module.app.dependency_overrides[app_module.web_user] = _user_override
    test_client = TestClient(app_module.app)
    test_client.cookies.set("access_token", FAKE_SESSION_COOKIE)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


# ─── Happy path ─────────────────────────────────────────────────────────────

def test_arabic_scan_command_parses_action_and_target(client):
    resp = client.post("/api/nlp", json={"text": "افحص ثغرات example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "example.com"
    assert data["action"] not in ("unknown", "error")


def test_english_scan_command_parses_action_and_target(client):
    resp = client.post("/api/nlp", json={"text": "Scan example.com for XSS"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "example.com"
    assert data["action"] not in ("unknown", "error")


# ─── Invalid input -> explicit response, never a silent 500 ────────────────

def test_empty_text_returns_200_with_unknown_action_not_a_crash(client):
    resp = client.post("/api/nlp", json={"text": ""})
    assert resp.status_code == 200
    assert resp.json()["action"] == "unknown"


def test_missing_text_field_returns_200_with_unknown_action(client):
    resp = client.post("/api/nlp", json={})
    assert resp.status_code == 200
    assert resp.json()["action"] == "unknown"


def test_gibberish_text_returns_200_with_unknown_action(client):
    resp = client.post("/api/nlp", json={"text": "asdkjhaskjdh 1234 !!!"})
    assert resp.status_code == 200
    assert resp.json()["action"] == "unknown"


def test_malformed_json_body_returns_explicit_400_not_silent_500(client):
    resp = client.post(
        "/api/nlp",
        content=b"{not valid json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_non_object_json_body_returns_explicit_400(client):
    resp = client.post("/api/nlp", json=["afhas", "example.com"])
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_non_string_text_field_returns_explicit_400(client):
    resp = client.post("/api/nlp", json={"text": 12345})
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_unauthenticated_request_is_rejected_not_silently_ignored():
    # No dependency override, no cookie -- a real "not logged in" request
    # must fail loudly (401/redirect), not appear to succeed with no data.
    plain_client = TestClient(app_module.app)
    resp = plain_client.post("/api/nlp", json={"text": "scan example.com"})
    assert resp.status_code in (401, 403, 307, 302)


# ─── Frontend wiring stays consistent with the backend route ───────────────

def test_frontend_fetch_url_matches_registered_backend_route():
    """Guards against exactly the reported failure mode: the JS building a
    URL (empty, mistyped, or pointing at a path the backend never
    registers) that silently diverges from the real /api/nlp route."""
    main_js = open(
        os.path.join(os.path.dirname(__file__), "..", "web", "static", "js", "main.js"),
        encoding="utf-8",
    ).read()
    assert "API.post('/api/nlp'" in main_js or 'API.post("/api/nlp"' in main_js

    registered_paths = {getattr(r, "path", None) for r in app_module.app.routes}
    assert "/api/nlp" in registered_paths


def test_go_button_and_input_share_the_nlp_bar_and_button_has_stable_id():
    """The Go button needs a stable id so runNLPCommand() can find it to
    toggle its loading state -- this pins that id against accidental
    rename drift between base.html and main.js."""
    base_html = open(
        os.path.join(os.path.dirname(__file__), "..", "web", "templates", "base.html"),
        encoding="utf-8",
    ).read()
    assert re.search(r'id="nlp-go-btn"[^>]*data-onclick="runNLPCommand"', base_html) \
        or re.search(r'data-onclick="runNLPCommand"[^>]*id="nlp-go-btn"', base_html) \
        or ('id="nlp-go-btn"' in base_html and 'data-onclick="runNLPCommand"' in base_html)

    main_js = open(
        os.path.join(os.path.dirname(__file__), "..", "web", "static", "js", "main.js"),
        encoding="utf-8",
    ).read()
    assert "getElementById('nlp-go-btn')" in main_js
