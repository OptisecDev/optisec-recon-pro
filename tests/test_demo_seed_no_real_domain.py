"""
Demo seed data in web/app.py must not use the real third-party domain
tesla.com; example.com is reserved for this (RFC 2606).

_ensure_demo_account() stores _DEMO_TARGETS / _DEMO_FINDINGS as Target, Scan
and Finding rows for the demo account, so whatever is in the seed block is
shown to every demo user. The block is read as text (no import, no DB) and
the content is reduced to a bool before asserting so a failure never dumps
the source into the test output.
"""

import os

APP_PY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "app.py"
)
SEED_START = "_DEMO_TARGETS = ["
SEED_END = "async def _ensure_demo_account"
REAL_DOMAIN = "tesla.com"


def _seed_block():
    with open(APP_PY, encoding="utf-8") as f:
        text = f.read()
    start = text.find(SEED_START)
    end = text.find(SEED_END, start)
    assert start != -1, "demo seed marker _DEMO_TARGETS not found in web/app.py"
    assert end != -1, "_ensure_demo_account not found after the demo seed block"
    return text[start:end]


def test_demo_seed_block_is_found():
    block = _seed_block()
    has_findings = "_DEMO_FINDINGS = [" in block
    assert has_findings, "demo seed block no longer contains _DEMO_FINDINGS"


def test_demo_seed_does_not_use_real_domain():
    text = _seed_block()
    has_real = REAL_DOMAIN in text
    assert not has_real, "demo seed data still contains the real domain tesla.com"
