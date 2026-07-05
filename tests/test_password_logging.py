"""
Regression tests for the fix in commit ff5b820 ("security: stop logging
plaintext admin/demo passwords, use env var + secure file fallback").

Before that commit, _ensure_first_admin() and _ensure_demo_account()
(web/app.py) ran on every server startup and, the first time they seeded
their respective account, printed the plaintext password straight to
stdout/logs -- readable forever after by anyone with log access (e.g. via
Render's log viewer). The fix replaced those prints with a password-free
log line plus, when no FIRST_ADMIN_PASSWORD/DEMO_INITIAL_PASSWORD env var
is set, a one-time write to a chmod-600 file outside any logs/ directory
(_write_initial_credentials_file).

These tests drive the real seeding functions against an isolated in-memory
DB (same fixture pattern as tests/test_api_key_hash.py) and assert the
plaintext password never appears in the log output, regardless of whether
the password came from an env var or was auto-generated.
"""

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base
import web.app as app_module


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def db(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())
    monkeypatch.setattr(app_module, "SessionLocal", TestSessionLocal)
    yield TestSessionLocal
    _run(engine.dispose())


def _clear_password_env(monkeypatch):
    monkeypatch.delenv("FIRST_ADMIN_USER", raising=False)
    monkeypatch.delenv("FIRST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("FIRST_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("DEMO_INITIAL_PASSWORD", raising=False)


def test_ensure_first_admin_never_logs_env_supplied_password(db, monkeypatch, caplog):
    _clear_password_env(monkeypatch)
    secret = "sUp3r-Secret-Env-Password!"
    monkeypatch.setenv("FIRST_ADMIN_PASSWORD", secret)

    with caplog.at_level(logging.DEBUG, logger="web.app"):
        _run(app_module._ensure_first_admin())

    assert secret not in caplog.text


def test_ensure_first_admin_never_logs_auto_generated_password(db, monkeypatch, caplog):
    _clear_password_env(monkeypatch)
    captured = {}

    def _fake_write_creds(role, username, password):
        # Stand in for the real file write so the test never touches /tmp;
        # captures the password out-of-band to prove it left the function
        # via this channel and not via logger output.
        captured["role"] = role
        captured["username"] = username
        captured["password"] = password

    monkeypatch.setattr(app_module, "_write_initial_credentials_file", _fake_write_creds)

    with caplog.at_level(logging.DEBUG, logger="web.app"):
        _run(app_module._ensure_first_admin())

    assert captured["role"] == "admin"
    assert captured["password"]  # a password was in fact generated
    assert captured["password"] not in caplog.text


def test_ensure_demo_account_never_logs_env_supplied_password(db, monkeypatch, caplog):
    _clear_password_env(monkeypatch)
    secret = "D3mo-Env-Password!"
    monkeypatch.setenv("DEMO_INITIAL_PASSWORD", secret)

    with caplog.at_level(logging.DEBUG, logger="web.app"):
        _run(app_module._ensure_demo_account())

    assert secret not in caplog.text


def test_ensure_demo_account_never_logs_auto_generated_password(db, monkeypatch, caplog):
    _clear_password_env(monkeypatch)
    captured = {}

    def _fake_write_creds(role, username, password):
        captured["role"] = role
        captured["username"] = username
        captured["password"] = password

    monkeypatch.setattr(app_module, "_write_initial_credentials_file", _fake_write_creds)

    with caplog.at_level(logging.DEBUG, logger="web.app"):
        _run(app_module._ensure_demo_account())

    assert captured["role"] == "demo"
    assert captured["password"]
    assert captured["password"] not in caplog.text


def test_ensure_first_admin_is_a_noop_on_second_call(db, monkeypatch, caplog):
    # Startup runs this on every restart; it must only seed once per DB,
    # not just log-safely every time.
    _clear_password_env(monkeypatch)
    monkeypatch.setenv("FIRST_ADMIN_PASSWORD", "first-call-password")
    _run(app_module._ensure_first_admin())

    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="web.app"):
        _run(app_module._ensure_first_admin())

    assert "Initial admin account created" not in caplog.text
