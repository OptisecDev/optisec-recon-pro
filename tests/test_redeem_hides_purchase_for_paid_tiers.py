"""
PRIORITY 3 item 7 of the live-walkthrough audit (BATCH 2):

web/templates/redeem.html always rendered the "Buy PRO — $399" purchase
block, even for a user already on PRO or ENTERPRISE — an Enterprise account
landing on /redeem (e.g. from an old bookmark or a stray upsell link) saw a
paid-upgrade pitch for a plan they already have, which reads as either a
bug or a dark pattern. web/routers/license_routes.py::redeem_page passes
`user` into the template; the fix gates the purchase block on
`user.subscription_tier` and shows a bilingual "already on this plan"
notice instead — see web/templates/redeem.html's
`{% if user and user.subscription_tier in ('pro', 'enterprise') %}`.

Same TestClient + dependency-override + cookie-auth pattern as
tests/test_cve_pipeline.py's TestCveDraftEndpointCreditsValidation.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
from web.database import Base, get_db
from web.models import User
from web.auth import create_access_token, hash_password


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client():
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
    c = TestClient(app_module.app)
    yield c, session_factory
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _token_for_tier(session_factory, tier: str) -> str:
    async def go():
        async with session_factory() as db_:
            user = User(
                username=f"{tier}_user", email=f"{tier}_user@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role="analyst", subscription_tier=tier, is_active=True,
            )
            db_.add(user)
            await db_.commit()
            await db_.refresh(user)
            return user.id
    user_id = _run(go())
    return create_access_token(user_id, "analyst")


def test_free_tier_user_still_sees_the_purchase_block(client):
    c, session_factory = client
    token = _token_for_tier(session_factory, "free")
    resp = c.get("/redeem", cookies={"access_token": token})
    assert resp.status_code == 200
    assert "Buy PRO" in resp.text
    assert "$399" in resp.text


def test_pro_tier_user_does_not_see_the_purchase_block(client):
    c, session_factory = client
    token = _token_for_tier(session_factory, "pro")
    resp = c.get("/redeem", cookies={"access_token": token})
    assert resp.status_code == 200
    # The visible pricing pitch/purchase form must be gone. ("$399" alone
    # isn't checked — it also appears inert inside the always-present
    # <script> block's dormant button-reset text, which never renders.)
    assert "Buy PRO" not in resp.text
    assert 'id="buy-pro-form"' not in resp.text
    assert "You are on the PRO plan" in resp.text  # the "already on this plan" notice
    assert any("؀" <= ch <= "ۿ" for ch in resp.text)


def test_enterprise_tier_user_sees_bilingual_already_on_plan_notice(client):
    c, session_factory = client
    token = _token_for_tier(session_factory, "enterprise")
    resp = c.get("/redeem", cookies={"access_token": token})
    assert resp.status_code == 200
    assert "Buy PRO" not in resp.text
    assert 'id="buy-pro-form"' not in resp.text
    assert "You are on the ENTERPRISE plan" in resp.text
    assert any("؀" <= ch <= "ۿ" for ch in resp.text)


def test_enterprise_tier_user_does_not_see_refund_note_without_a_purchase_offer(client):
    c, session_factory = client
    token = _token_for_tier(session_factory, "enterprise")
    resp = c.get("/redeem", cookies={"access_token": token})
    assert "Full refund" not in resp.text
