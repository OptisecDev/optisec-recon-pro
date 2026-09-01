"""
Regression guards for the style-src unsafe-inline removal: 1470 static
style="" attributes (1021 unique values) were mechanically extracted into
web/static/css/inline-extracted.css as ie<hash> classes with !important on
every declaration (to preserve inline style's override precedence), and the
96 dynamic ones were renamed to data-dyn-style="..." for
main.js's optisecApplyDynStyles() to apply via element.style.setProperty().

These are static/textual checks -- the actual "does this still render
correctly" question was verified separately with a headless-Chromium pass
against the real CSP header (zero violations across all 32 templates, and
an end-to-end mocked-fetch run of firewall.html's inspectRequest()); no
browser automation was available in this test environment to make that a
permanent CI check, so these tests instead guard the invariants a future
edit could silently break: no static style="" creeping back in, every
extracted class actually enforces precedence, the stylesheet is actually
served and linked, and the JS mechanism a data-dyn-style relies on exists.
"""

import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_FILES = glob.glob(os.path.join(REPO_ROOT, "web/templates/*.html"))
MAIN_JS = os.path.join(REPO_ROOT, "web/static/js/main.js")
EXTRACTED_CSS = os.path.join(REPO_ROOT, "web/static/css/inline-extracted.css")

STATIC_STYLE_RE = re.compile(r'style="([^"]*)"')


def _is_dynamic(value: str) -> bool:
    return "{{" in value or "${" in value or "{%" in value


def _strip_js_line_comments(src: str) -> str:
    """Drops '// ...' line comments before pattern-matching code, so this
    module's own explanatory comments (which reference style="", cssText,
    setAttribute('style', ...) etc. as examples) don't trip the checks
    below. Line-based and doesn't handle // inside a string literal, but
    main.js has none of those on commented lines."""
    return "\n".join(
        line for line in src.split("\n")
        if not line.strip().startswith("//")
    )


def test_no_static_style_attributes_remain():
    """Any style="..." attribute left in templates/main.js must be dynamic
    (data-driven, renamed to data-dyn-style elsewhere) -- a plain static
    style="" attribute would reintroduce the exact thing style-src's
    unsafe-inline removal was for."""
    offenders = []
    for path in TEMPLATE_FILES + [MAIN_JS]:
        src = open(path).read()
        if path == MAIN_JS:
            src = _strip_js_line_comments(src)
        for m in STATIC_STYLE_RE.finditer(src):
            if not _is_dynamic(m.group(1)):
                offenders.append(f"{path}: style=\"{m.group(1)[:60]}\"")
    assert not offenders, f"Found static style=\"\" attribute(s):\n" + "\n".join(offenders)


def test_no_style_cssText_or_setAttribute_style_assignments():
    """element.style.cssText = ... and setAttribute('style', ...) both
    reduce to the restricted style attribute under CSP, unlike individual
    element.style.setProperty()/element.style.xxx = ... assignments. A
    reintroduced cssText assignment would silently violate the CSP in a
    real browser without failing any Python-side test, so it's guarded
    here as a static pattern instead."""
    offenders = []
    pattern = re.compile(r"\.style\.cssText\s*=|setAttribute\(\s*['\"]style['\"]")
    for path in TEMPLATE_FILES + [MAIN_JS]:
        src = open(path).read()
        if path == MAIN_JS:
            src = _strip_js_line_comments(src)
        for m in pattern.finditer(src):
            line_no = src.count("\n", 0, m.start()) + 1
            offenders.append(f"{path}:{line_no}")
    assert not offenders, f"Found style.cssText/setAttribute('style',...) usage:\n" + "\n".join(offenders)


def test_inline_extracted_css_exists_and_uses_important_on_every_declaration():
    assert os.path.exists(EXTRACTED_CSS), "web/static/css/inline-extracted.css is missing"
    css = open(EXTRACTED_CSS).read()
    rules = re.findall(r"\.ie[0-9a-f]{8}\s*\{([^}]*)\}", css)
    assert len(rules) > 500, f"Expected 500+ extracted classes, found {len(rules)}"
    for body in rules:
        decls = [d.strip() for d in body.split(";") if d.strip()]
        for d in decls:
            assert d.endswith("!important"), f"Declaration missing !important: {d!r}"


def test_base_html_links_inline_extracted_stylesheet():
    base = open(os.path.join(REPO_ROOT, "web/templates/base.html")).read()
    assert '/static/css/inline-extracted.css' in base


def test_standalone_pages_link_inline_extracted_stylesheet():
    # login.html, register.html, landing.html don't extend base.html, so
    # each needs its own <link> to the extracted stylesheet.
    for name in ("login.html", "register.html", "landing.html"):
        html = open(os.path.join(REPO_ROOT, "web/templates", name)).read()
        assert '/static/css/inline-extracted.css' in html, f"{name} missing the stylesheet link"


def test_main_js_defines_the_dyn_style_and_args_helpers():
    js = open(MAIN_JS).read()
    assert "window.optisecApplyDynStyles" in js
    assert "el.style.setProperty(prop, val)" in js
    assert "window.optisecArgs" in js


def test_no_single_quoted_inline_event_handlers_remain():
    """The addEventListener refactor's original grep only searched for
    double-quoted on*="..." attributes and missed one single-quoted
    onclick='...' in threat_feed.html (found and fixed during the style
    pass). Guard against that class of miss recurring."""
    pattern = re.compile(r"\bon(?:click|change|keydown|keyup|submit|input|error)='[^']*'")
    offenders = []
    for path in TEMPLATE_FILES + [MAIN_JS]:
        src = open(path).read()
        if pattern.search(src):
            offenders.append(path)
    assert not offenders, f"Single-quoted inline event handler(s) found in: {offenders}"
