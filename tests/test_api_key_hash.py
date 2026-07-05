"""
Tests for the User.api_key encryption-at-rest fix (web/models.py,
web/auth.py, web/app.py).

Previously users.api_key stored the raw, bearer-usable API key in
plaintext and was looked up by direct equality. Since nothing in the
codebase ever needs the plaintext key back after it's shown once at
generation/regeneration time (see web/app.py register/regenerate routes),
this moves to a hash-and-reissue model: only a SHA-256 hash
(web/auth.py hash_api_key) is persisted, in users.api_key_hash.

Same isolated in-memory SQLite fixture pattern as tests/test_cve_pipeline.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base
from web.models import User
from web.auth import generate_api_key, hash_api_key, get_current_user


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def db():
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
    yield TestSessionLocal
    _run(engine.dispose())


class _FakeRequest:
    """Duck-types just the pieces of fastapi.Request get_current_user reads."""

    def __init__(self, headers=None):
        self.headers = headers or {}
        self.cookies = {}


def test_user_model_no_longer_accepts_plaintext_api_key_column():
    with pytest.raises(TypeError):
        User(username="x", email="x@example.com", password_hash="h", api_key="plaintext")


def test_hash_api_key_is_deterministic_sha256():
    import hashlib

    key = "a" * 64
    assert hash_api_key(key) == hashlib.sha256(key.encode("utf-8")).hexdigest()


def test_hash_api_key_differs_for_different_keys():
    assert hash_api_key(generate_api_key()) != hash_api_key(generate_api_key())


def test_get_current_user_authenticates_via_hashed_lookup(db):
    async def scenario():
        plaintext_key = generate_api_key()
        async with db() as session:
            user = User(
                username="analyst1", email="analyst1@example.com",
                password_hash="h", role="analyst", is_active=True,
                api_key_hash=hash_api_key(plaintext_key),
            )
            session.add(user)
            await session.commit()

            request = _FakeRequest(headers={"X-API-Key": plaintext_key})
            authenticated = await get_current_user(request, session)
            assert authenticated.username == "analyst1"

    _run(scenario())


def test_get_current_user_rejects_wrong_api_key(db):
    async def scenario():
        async with db() as session:
            user = User(
                username="analyst1", email="analyst1@example.com",
                password_hash="h", role="analyst", is_active=True,
                api_key_hash=hash_api_key(generate_api_key()),
            )
            session.add(user)
            await session.commit()

            request = _FakeRequest(headers={"X-API-Key": "not-the-real-key"})
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(request, session)
            assert exc_info.value.status_code == 401

    _run(scenario())


def test_get_current_user_rejects_plaintext_of_a_stale_pre_migration_key(db):
    # Simulates presenting a key that was only ever hashed (i.e. the exact
    # plaintext-equality lookup the old code used is gone) -- storing the
    # raw string in api_key_hash rather than its digest must not authenticate.
    async def scenario():
        async with db() as session:
            raw = generate_api_key()
            user = User(
                username="analyst1", email="analyst1@example.com",
                password_hash="h", role="analyst", is_active=True,
                api_key_hash=raw,  # wrong on purpose: not hashed
            )
            session.add(user)
            await session.commit()

            request = _FakeRequest(headers={"X-API-Key": raw})
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(request, session)
            assert exc_info.value.status_code == 401

    _run(scenario())
