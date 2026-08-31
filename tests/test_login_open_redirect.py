"""
Regression test for web/app.py's `next` param handling on /login.

Found during a standardized SAST/DAST audit (OWASP ZAP baseline flagged
/login?next=... as a "User Controllable HTML Element Attribute" hotspot):
`next` was passed straight from Form(...) into RedirectResponse(next or
"/") with no validation, so /login?next=https://evil.com (or any of the
REDIRECT_PAYLOADS the project's own modules/vuln/open_redirect.py tests
OTHER sites for) let an attacker send a victim to the real login page,
have them authenticate normally, and get redirected off-site afterward
-- a classic post-login phishing open redirect (CWE-601).

web.app._safe_next_path() now allows only a same-origin relative path.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import web.app as app_module
from modules.vuln.open_redirect import REDIRECT_PAYLOADS


@pytest.mark.parametrize("payload", REDIRECT_PAYLOADS)
def test_rejects_every_known_open_redirect_payload(payload):
    assert app_module._safe_next_path(payload) == "/"


@pytest.mark.parametrize("payload", [
    "",
    None,
    "https:evil.com",
    "javascript:alert(1)",
    "/%5C/evil.com",
    "/\\/evil.com",
])
def test_rejects_additional_bypass_attempts(payload):
    assert app_module._safe_next_path(payload) == "/"


@pytest.mark.parametrize("path", [
    "/",
    "/redeem",
    "/dashboard?tab=scans",
    "/reports/42",
])
def test_allows_same_origin_relative_paths(path):
    assert app_module._safe_next_path(path) == path
