"""
Real-browser (headless Chromium via Playwright) regression test for the
!important-vs-JS-display-toggle bug (see inline-extracted.css's header
comment, README's CSP section, and tests/test_js_display_toggle_regression.py
for the static version of this guard).

test_js_display_toggle_regression.py proves the fix by text/regex analysis
of the templates, CSS, and JS, without ever loading a real cascade -- that's
exactly the blind spot that let the original bug ship (the pre-existing
jsdom-based tests never loaded any CSS, so `.style.display` looked like it
"worked" even though a real browser's cascade would have overridden it).
This test closes that blind spot: it boots the actual app against a
throwaway local SQLite DB, drives real Chromium against it, and asserts on
getComputedStyle() -- the same signal a human clicking through the site
would see -- after each tab click.

Covers Red Team (the page the bug was first diagnosed on) plus two of the
other most heavily affected pages from the platform-wide inventory:
Threat Feed (6 tabs, its own showTab + tab-btn active-state sync + a
JS-set border-color) and OSINT (9 tabs via a differently-named switchTab(),
the class-selector show/hide variant rather than per-id).

Skips (does not fail) if Chromium isn't installed for Playwright, per the
task instructions -- explicit skip, not a silent swap to jsdom.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover
    sync_playwright = None
    _PLAYWRIGHT_IMPORT_ERROR = exc


def _chromium_available():
    if sync_playwright is None:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            browser.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _chromium_available(),
    reason="Playwright/Chromium not available in this environment -- "
           "install with `python -m playwright install chromium`. "
           "Not substituted with a jsdom/no-CSS test; see module docstring.",
)


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    """Boots the real app (uvicorn subprocess) against a fresh, throwaway
    local SQLite DB -- explicitly NOT the Neon DATABASE_URL from .env,
    which a previous run pointed straight at and hung for ~22 minutes
    inside this sandbox's restricted network egress. Overriding
    DATABASE_URL in this subprocess's environment is sufficient:
    web/database.py's load_dotenv() call never overrides an
    already-set env var."""
    data_dir = tmp_path_factory.mktemp("playwright_live_server")
    db_path = data_dir / "test.db"
    port = _free_port()

    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    env["GROQ_ENV"] = "testing"  # opt into the insecure-but-fine-for-tests default JWT secret
    env.pop("GROQ_API_KEY", None)  # AI features degrade gracefully; keep this offline
    env.setdefault("PYTHONUNBUFFERED", "1")

    log_path = data_dir / "uvicorn.log"
    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "web.app:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT, env=env, stdout=log_file, stderr=subprocess.STDOUT,
    )

    base_url = f"http://127.0.0.1:{port}"
    ready = False
    for _ in range(60):
        if proc.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                ready = True
                break
        except OSError:
            time.sleep(0.5)

    if not ready:
        proc.terminate()
        log_file.close()
        log_contents = open(log_path).read()[-4000:]
        pytest.fail(f"Live server did not become ready in time. Log tail:\n{log_contents}")

    # One more beat for the startup event (init_db + demo account seeding)
    # to finish past the initial socket bind.
    for _ in range(20):
        try:
            import urllib.request
            urllib.request.urlopen(f"{base_url}/login", timeout=1)
            break
        except Exception:
            time.sleep(0.5)

    # Red Team and Threat Feed (unlike OSINT) are enterprise-gated features
    # (require_feature_or_402() in web/routers/ai_security.py and
    # threat_feed.py) -- the seeded demo account is free-tier, so it would
    # get a 402 Upgrade Required page instead of the page under test. This
    # is a throwaway DB file this fixture created, so upgrading the one
    # seeded account directly is simpler and faster than driving the
    # redeem-a-license UI just to unlock a test page.
    import sqlite3
    for _ in range(20):
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            conn.execute("UPDATE users SET subscription_tier = 'enterprise' WHERE username = 'demo'")
            conn.commit()
            conn.close()
            break
        except sqlite3.OperationalError:
            time.sleep(0.5)

    yield base_url

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    log_file.close()

    # _ensure_demo_account() writes a one-time creds file to /tmp -- clean
    # it up, it's not ours to leave lying around.
    for fname in os.listdir("/tmp"):
        if re.match(r"optisec_initial_creds_(demo|admin)_\d+\.txt$", fname):
            try:
                os.remove(os.path.join("/tmp", fname))
            except OSError:
                pass


@pytest.fixture(scope="module")
def browser_context(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(base_url=live_server)
        page = context.new_page()
        # /demo is a one-click login the app itself provides for exactly
        # this kind of no-manual-credentials smoke test; _ensure_demo_account()
        # (web/app.py startup) seeds the account this hits.
        resp = page.goto("/demo")
        assert resp.ok, f"/demo login failed: {resp.status}"
        yield context
        browser.close()


def _visible_tab_ids(page, ids):
    """{id: display != 'none'} for every id in ids, via a real computed
    style -- this is exactly the check that would have caught the original
    bug (element.style.display alone, or a static text/regex check, both
    miss an !important class silently winning the cascade)."""
    return {
        el_id: page.evaluate(
            "id => { const el = document.getElementById(id); "
            "return el && getComputedStyle(el).display !== 'none'; }",
            el_id,
        )
        for el_id in ids
    }


def test_red_team_tabs_respond_to_clicks(browser_context):
    page = browser_context.new_page()
    page.goto("/ai-security/red-team")

    tab_ids = ["tab-engagements", "tab-new", "tab-library"]
    buttons = [
        ("🎯 Engagements", "tab-engagements"),
        ("➕ New Engagement", "tab-new"),
        ("📚 Technique Library", "tab-library"),
    ]

    # Initial state: exactly the first tab visible.
    visibility = _visible_tab_ids(page, tab_ids)
    assert visibility == {"tab-engagements": True, "tab-new": False, "tab-library": False}, (
        f"Initial Red Team tab state wrong: {visibility}"
    )

    for label, expected_visible_id in buttons:
        page.get_by_role("button", name=label, exact=True).click()
        visibility = _visible_tab_ids(page, tab_ids)
        assert visibility[expected_visible_id] is True, (
            f"Clicking {label!r} should show #{expected_visible_id}, got {visibility}"
        )
        for other_id in tab_ids:
            if other_id != expected_visible_id:
                assert visibility[other_id] is False, (
                    f"Clicking {label!r}: #{other_id} should be hidden, got {visibility}"
                )
        # The active (green/primary) button should track the selected tab.
        active_classes = page.eval_on_selector(
            f'button:has-text("{label}")', "el => el.className"
        )
        assert "btn-primary" in active_classes, (
            f"Active tab button {label!r} should carry btn-primary, got {active_classes!r}"
        )

    page.close()


def test_threat_feed_tabs_respond_to_clicks(browser_context):
    page = browser_context.new_page()
    page.goto("/threat-feed")

    tab_ids = ["tab-feed", "tab-map", "tab-campaigns", "tab-sources", "tab-submit", "tab-sharing"]
    visibility = _visible_tab_ids(page, tab_ids)
    assert visibility["tab-feed"] is True
    assert all(v is False for k, v in visibility.items() if k != "tab-feed"), visibility

    buttons = page.locator(".tab-btn")
    count = buttons.count()
    assert count == len(tab_ids), f"Expected {len(tab_ids)} .tab-btn buttons, found {count}"

    for i, expected_id in enumerate(tab_ids):
        buttons.nth(i).click()
        visibility = _visible_tab_ids(page, tab_ids)
        assert visibility[expected_id] is True, f"Tab {i} ({expected_id}) click: {visibility}"
        assert sum(1 for v in visibility.values() if v) == 1, (
            f"Exactly one tab should be visible after clicking tab {i}, got {visibility}"
        )
        active_class = buttons.nth(i).get_attribute("class")
        assert "active" in active_class, f"Clicked .tab-btn[{i}] should carry .active, got {active_class!r}"

    page.close()


def test_osint_tabs_respond_to_clicks(browser_context):
    page = browser_context.new_page()
    page.goto("/osint")

    tab_ids = [
        "tab-phone", "tab-username", "tab-device", "tab-plate",
        "tab-ip", "tab-cell", "tab-phonesoc", "tab-domain",
    ]
    visibility = _visible_tab_ids(page, tab_ids)
    assert visibility["tab-phone"] is True
    assert all(v is False for k, v in visibility.items() if k != "tab-phone"), visibility

    # switchTab() is a differently-named function using a class-selector
    # (.osint-tab) hide-all-then-show-one pattern, rather than red_team's
    # per-id forEach -- deliberately exercising the other code shape.
    for btn_id, expected_id in zip(
        [f"tab-btn-{t.replace('tab-', '')}" for t in tab_ids], tab_ids
    ):
        page.locator(f"#{btn_id}").click()
        visibility = _visible_tab_ids(page, tab_ids)
        assert visibility[expected_id] is True, f"#{btn_id} click: {visibility}"
        assert sum(1 for v in visibility.values() if v) == 1, (
            f"Exactly one OSINT tab should be visible after clicking {btn_id}, got {visibility}"
        )

    page.close()
