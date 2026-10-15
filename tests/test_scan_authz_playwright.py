"""
Real-browser (headless Chromium via Playwright) check that the scan page
works with scan authorization enforced, and that the Targets page's
verification UI is wired up -- under the app's real CSP.

Reuses the live-server + /demo-login fixtures from
tests/test_platform_tabs_playwright.py (throwaway SQLite DB, uvicorn
subprocess). The demo account is an analyst with no verified domains. No
scan ever actually runs here: the authorized-path assertions stop at the
UI state, and the one Start click is a request the server refuses (403),
so no scanner touches the network.

Skips (does not fail) when Chromium isn't installed, same as that module.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.test_platform_tabs_playwright import (  # noqa: F401 -- fixtures
    _chromium_available, browser_context, live_server,
)

pytestmark = pytest.mark.skipif(
    not _chromium_available(),
    reason="Playwright/Chromium not available in this environment -- "
           "install with `python -m playwright install chromium`.",
)

UNVERIFIED = "unverified-target.invalid"


@pytest.fixture
def page(browser_context):
    p = browser_context.new_page()
    csp_errors = []
    p.on("console", lambda m: csp_errors.append(m.text) if "Content Security Policy" in m.text else None)
    p.csp_errors = csp_errors
    yield p
    p.close()


def _box(page, value):
    return page.locator(f'.scan-type[value="{value}"]')


def _wait_banner(page, text):
    page.wait_for_function(
        "t => { const el = document.getElementById('authz-status');"
        " return el && getComputedStyle(el).display !== 'none' && el.textContent.includes(t); }",
        arg=text, timeout=10_000,
    )


def test_scan_page_locks_active_modules_for_unverified_target(page):
    page.goto("/scan")
    page.fill("#scan-target", UNVERIFIED)
    _wait_banner(page, "Passive modules only")

    for active in ["subdomain", "nmap", "ports", "xss", "sqli", "ssrf", "lfi", "redirect"]:
        assert _box(page, active).is_disabled(), active
        assert not _box(page, active).is_checked(), active
    for passive in ["dns", "whois", "ssl", "headers", "osint"]:
        assert _box(page, passive).is_enabled(), passive
        assert _box(page, passive).is_checked(), passive

    locked_label = page.locator('.checkbox-item:has(.scan-type[value="xss"])')
    assert "is-locked" in locked_label.get_attribute("class")
    assert page.locator("#authz-status a[href='/targets']").count() == 1

    # "Select All" must not re-check locked modules.
    page.click("text=Select All")
    assert not _box(page, "xss").is_checked()
    assert page.csp_errors == []


def test_scan_page_training_target_and_unlock_on_clear(page):
    page.goto("/scan")
    page.fill("#scan-target", UNVERIFIED)
    _wait_banner(page, "Passive modules only")

    page.fill("#scan-target", "scanme.nmap.org")
    _wait_banner(page, "training target")
    assert _box(page, "nmap").is_enabled() and _box(page, "ports").is_enabled()
    assert _box(page, "xss").is_disabled() and _box(page, "subdomain").is_disabled()

    # Clearing the target unlocks everything and restores the original ticks.
    page.fill("#scan-target", "")
    page.wait_for_function("() => !document.querySelector('.scan-type[value=\"xss\"]').disabled", timeout=10_000)
    assert _box(page, "xss").is_checked()
    assert page.csp_errors == []


def test_scan_page_renders_server_refusal_inline(page):
    """Even if a locked module is forced on client-side, the server refuses
    and the page shows why, instead of opening /ws/scan/undefined."""
    page.goto("/scan")
    page.fill("#scan-target", UNVERIFIED)
    _wait_banner(page, "Passive modules only")
    page.evaluate(
        "() => { const cb = document.querySelector('.scan-type[value=\"xss\"]');"
        " cb.disabled = false; cb.checked = true; }"
    )

    ws_urls = []
    page.on("websocket", lambda ws: ws_urls.append(ws.url))
    with page.expect_response(lambda r: r.url.endswith("/api/scan") and r.request.method == "POST") as resp_info:
        page.click("#scan-btn")
    assert resp_info.value.status == 403

    page.wait_for_selector("#scan-status .alert-error", timeout=10_000)
    status = page.inner_text("#scan-status")
    assert "Refused modules: xss" in status
    assert page.locator("#scan-status a[href='/targets']").count() == 1
    assert page.is_enabled("#scan-btn")
    assert "Start Scan" in page.inner_text("#scan-btn")
    assert ws_urls == []
    page.wait_for_function("() => document.querySelector('.scan-type[value=\"xss\"]').disabled", timeout=10_000)
    assert page.csp_errors == []


def test_targets_page_verification_instructions(page):
    page.goto("/targets")
    page.fill("#verify-domain", "example.com")
    with page.expect_response(lambda r: r.url.endswith("/api/domains/verify")) as resp_info:
        page.click("text=Get verification instructions")
    assert resp_info.value.status in (200, 201), resp_info.value.text()

    page.wait_for_selector("#verify-instructions:not(.is-hidden)", timeout=10_000)
    text = page.inner_text("#verify-instructions")
    assert "_optisec-verify.example.com" in text
    assert "optisec-verify=" in text
    assert "Status: pending" in text
    assert page.locator('#verify-instructions [data-onclick="checkVerification"]').count() == 1
    assert page.csp_errors == []
