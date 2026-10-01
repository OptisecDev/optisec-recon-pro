"""
Tests for a further fix to draftFromFinding() in web/templates/cve_pipeline.html.

tests/test_cve_pipeline_ui_fixes.py already covers `d.error || d.detail`
reading the real backend message for ordinary HTTPException failures
(402/404/422/400 — on_http_exception in web/app.py renders those as
{"error": exc.detail} for /api/ routes). This file covers what was still
missing:

1. The reason shown to the user now includes the HTTP status code (e.g.
   "... (402)", "Finding 42 not found (404)"), per the ask to distinguish
   "PRO required (402)" from "Finding not found (404)" from "Server error
   (500)" instead of one generic "Failed to generate draft." for all of
   them.

2. A true unhandled 500 (or any non-JSON error body) used to leave the
   user with nothing: `const d = await r.json()` had no try/catch, so a
   non-JSON body threw and the rejection was silently swallowed — no
   fallback text, no error shown at all. Same for a network failure
   (fetch() itself rejecting). Both are now caught and shown as an honest
   message instead of failing silently.

No JS test runner in this repo (see test_cve_pipeline_ui_fixes.py's own
note) — same static-source regression-guard shape.
"""

import os
import re

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "cve_pipeline.html",
)


def _draft_from_finding_source() -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        html = f.read()
    match = re.search(r"async function draftFromFinding\(\).*?\n}", html, re.DOTALL)
    assert match, "draftFromFinding() not found in template"
    return match.group(0)


def test_error_branch_still_prefers_error_then_detail():
    # Guard against regressing the existing fix from test_cve_pipeline_ui_fixes.py.
    assert "d.error || d.detail" in _draft_from_finding_source()


def test_error_branch_includes_the_http_status_code():
    fn = _draft_from_finding_source()
    else_branch = fn.split("} else {")[1]
    assert "r.status" in else_branch, \
        "the shown reason should include the HTTP status code (e.g. '(402)', '(404)', '(500)')"


def test_fetch_call_is_wrapped_in_try_catch():
    """A network failure (fetch() rejecting) must not be a silent no-op."""
    fn = _draft_from_finding_source()
    assert "try {" in fn and "catch" in fn, \
        "fetch()/r.json() must be guarded so a network failure or a non-JSON body doesn't fail silently"
    # The fetch call itself must be inside a try block, not bare.
    fetch_idx = fn.index("fetch('/api/cve/draft'")
    try_idx = fn.rindex("try {", 0, fetch_idx)
    catch_idx = fn.index("catch", fetch_idx)
    assert try_idx < fetch_idx < catch_idx


def test_json_parse_is_guarded_against_non_json_error_bodies():
    """A true unhandled 500 (plain-text body) must not throw past r.json()
    uncaught -- it should fall through to the generic 'Server error (N)'
    message instead of leaving the result div unchanged with no feedback."""
    fn = _draft_from_finding_source()
    json_idx = fn.index("await r.json()")
    # There must be a try/catch wrapping this specific call.
    try_idx = fn.rindex("try", 0, json_idx)
    catch_idx = fn.index("catch", json_idx)
    assert try_idx < json_idx < catch_idx


def test_fallback_message_names_server_error_with_status():
    fn = _draft_from_finding_source()
    assert re.search(r"Server error \(\$\{r\.status\}\)", fn), \
        "a response with neither d.error nor d.detail should fall back to 'Server error (<status>)'"
