"""
Regression test for the stored-XSS fix in web/templates/attack_navigator.html.

loadDetections() interpolated d.technique_id/d.technique_name/d.source
(all attacker-reachable via POST /api/add-detection -- technique_id and
source directly, technique_name derived from an unvalidated technique_id
via _find_technique()'s echo-back fallback, see
tests/test_idor_attack_navigator.py) straight into innerHTML via
unescaped JS template literals, with no escHtml() helper defined anywhere
in the file. A `source` like `<img src=x onerror=alert(document.cookie)>`
submitted by any attack_navigator-entitled account executed in every
other viewer's browser on loading the Detections tab.

Static-source regression guard, same shape as
tests/test_threat_feed_xss_escaping.py -- there's no JS test runner in
this repo.
"""

import os
import re

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "attack_navigator.html",
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


def test_load_detections_wraps_fields_in_eschtml():
    src = _read_template()
    fn = src.split("async function loadDetections()")[1].split("async function")[0]
    for field in ("d.technique_id", "d.technique_name", "d.source"):
        assert re.search(rf"escHtml\([^)]*{re.escape(field)}", fn), \
            f"{field} is not passed through escHtml() in loadDetections()"


def test_run_detect_iocs_wraps_technique_fields_in_eschtml():
    src = _read_template()
    # technique_hits' ids are drawn from the fixed server-side mapping
    # (not directly attacker-controlled) but are escaped anyway for
    # defense in depth, matching the add-detection path.
    idx = src.find("data.technique_hits.map(h =>")
    assert idx != -1, "technique_hits render call not found"
    snippet = src[idx:idx + 400]
    for field in ("h.technique_id", "h.technique_name"):
        assert re.search(rf"escHtml\([^)]*{re.escape(field)}", snippet), \
            f"{field} is not passed through escHtml()"
