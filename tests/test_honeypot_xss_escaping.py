"""
Regression test for the stored-XSS fix in web/templates/honeypot.html.

eventRowHtml() interpolated e.payload -- the raw data a real attacker sent
to one of the honeypot's live SSH/FTP/HTTP-admin TCP listeners
(modules/honeypot/listeners.py), captured verbatim into HoneypotEvent --
directly into innerHTML via an unescaped JS template literal, in both the
cell text and a `title="..."` attribute (an easier breakout point). No
platform account is required to exploit this: any internet host
connecting to the honeypot's real ports (e.g. an FTP USER command like
`<img src=x onerror=alert(document.cookie)>`) could get that payload
persisted and later executed in the browser of any staff member who opens
the /honeypot dashboard.

Static-source regression guard, same shape as
tests/test_threat_feed_xss_escaping.py / test_attack_navigator_xss_escaping.py
-- there's no JS test runner in this repo.
"""

import os
import re

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "honeypot.html",
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


def test_event_row_html_wraps_attacker_reachable_fields_in_eschtml():
    src = _read_template()
    fn = src.split("function eventRowHtml(e)")[1].split("function ")[0]
    for field in ("e.service_ar", "e.source_ip", "e.country", "e.risk_level", "e.payload"):
        assert re.search(rf"escHtml\([^)]*{re.escape(field)}", fn), \
            f"{field} is not passed through escHtml() in eventRowHtml()"


def test_payload_is_escaped_in_both_the_title_attribute_and_cell_text():
    """The title="..." attribute is the easier breakout point (a payload
    containing a bare double-quote can close the attribute early) -- make
    sure both occurrences of e.payload are covered, not just the visible
    cell text."""
    src = _read_template()
    fn = src.split("function eventRowHtml(e)")[1].split("function ")[0]
    payload_line = next(line for line in fn.splitlines() if "e.payload" in line)
    assert payload_line.count("escHtml(") == 2, (
        f"expected both the title attribute and cell text to use escHtml(), got: {payload_line!r}"
    )
