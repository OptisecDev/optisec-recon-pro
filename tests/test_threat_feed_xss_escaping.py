"""
Regression test for the stored-XSS fix in web/templates/threat_feed.html.

data.iocs (from GET /api/feed, which merges submit_ioc()-submitted values
into the shared feed -- see tests/test_threat_feed_submit_ioc_controls.py)
was interpolated directly into innerHTML via unescaped JS template
literals in refreshFeed()/loadLocalIocs()/shareIoc()/loadShareHistory(),
with no escHtml() helper defined anywhere in the file (unlike
web/templates/behavioral.html and bug_bounty.html, which already use one).
A `value` like `<img src=x onerror=alert(document.cookie)>` submitted by
any threat_feed-entitled account would execute in every other viewer's
browser on page load/refresh.

There's no JS test runner in this repo, so this is a static-source
regression guard rather than a real DOM execution test: it asserts the
specific interpolations that read attacker-reachable feed fields
(ioc.value, ioc.malware, ioc.type, ioc.tlp, ioc.source, s.ioc_value, ...)
are wrapped in escHtml(...), and that the helper itself is defined and
escapes the five HTML-significant characters.
"""

import os
import re

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "threat_feed.html",
)


def _read_template() -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        return f.read()


def test_eschtml_helper_is_defined():
    src = _read_template()
    assert "function escHtml(" in src


def test_eschtml_escapes_html_significant_characters():
    src = _read_template()
    match = re.search(r"function escHtml\(s\)\s*\{(.*?)\}", src, re.DOTALL)
    assert match, "escHtml() body not found"
    body = match.group(1)
    for char in ("&", "<", ">", '"', "'"):
        assert char in body, f"escHtml() does not appear to handle {char!r}"


def test_refresh_feed_wraps_ioc_fields_in_eschtml():
    src = _read_template()
    fn = src.split("async function refreshFeed()")[1].split("async function")[0]
    for field in ("ioc.type", "ioc.value", "ioc.malware", "ioc.source", "ioc.tlp"):
        assert re.search(rf"escHtml\([^)]*{re.escape(field)}", fn), \
            f"{field} is not passed through escHtml() in refreshFeed()"


def test_load_local_iocs_wraps_ioc_fields_in_eschtml():
    src = _read_template()
    fn = src.split("async function loadLocalIocs()")[1].split("async function")[0]
    for field in ("ioc.type", "ioc.value", "ioc.source_module", "ioc.severity"):
        assert re.search(rf"escHtml\([^)]*{re.escape(field)}", fn), \
            f"{field} is not passed through escHtml() in loadLocalIocs()"


def test_load_share_history_wraps_fields_in_eschtml():
    src = _read_template()
    fn = src.split("async function loadShareHistory()")[1].split("function ")[0]
    for field in ("s.ioc_type", "s.ioc_value", "s.status"):
        assert re.search(rf"escHtml\([^)]*{re.escape(field)}", fn), \
            f"{field} is not passed through escHtml() in loadShareHistory()"
