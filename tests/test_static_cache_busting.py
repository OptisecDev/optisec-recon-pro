"""Guards the cache-busting fix in web/shared_templates.py (follow-up to
commit ac9a488, which coupled style.css / inline-extracted.css / main.js
together -- see that commit's message). Without a version query string,
a browser (or an intermediate cache) can keep serving one of those files
stale after a deploy while the HTML markup and the other assets move on,
reproducing the exact "JS-toggled elements frozen by !important" bug
ac9a488 fixed, just for a different subset of users.

Two things are tested:
1. No template hardcodes an unversioned /static/*.css or /static/*.js
   reference -- every local stylesheet/script must go through the
   static_v() Jinja global.
2. static_v()'s underlying hash actually changes when a file's content
   changes, so the version query string is not a static no-op.
"""

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.shared_templates import BASE_DIR, _compute_static_versions

TEMPLATES_DIR = BASE_DIR / "templates"

# Matches a literal, unversioned local static CSS/JS reference such as
# href="/static/css/style.css" or src="/static/js/main.js". Anything routed
# through {{ static_v('css/style.css') }} renders as
# href="{{ static_v('css/style.css') }}" in the template source (Jinja
# expressions are still raw text at this point, not yet evaluated), so it
# never matches this pattern.
UNVERSIONED_STATIC_RE = re.compile(r'(?:href|src)="/static/[^"]*\.(?:css|js)"')


def test_no_unversioned_static_css_js_links_in_templates():
    offenders = {}
    for template_path in TEMPLATES_DIR.glob("*.html"):
        matches = UNVERSIONED_STATIC_RE.findall(template_path.read_text())
        if matches:
            offenders[template_path.name] = matches
    assert not offenders, (
        f"Templates reference local CSS/JS without static_v(): {offenders}"
    )


def test_static_v_hash_changes_when_file_content_changes(tmp_path):
    css_dir = tmp_path / "css"
    css_dir.mkdir()
    target = css_dir / "style.css"

    target.write_text("body { color: red; }")
    versions_before = _compute_static_versions(tmp_path)

    target.write_text("body { color: blue; }")
    versions_after = _compute_static_versions(tmp_path)

    assert versions_before["css/style.css"] != versions_after["css/style.css"]


def test_static_v_hash_stable_for_unchanged_content(tmp_path):
    css_dir = tmp_path / "css"
    css_dir.mkdir()
    (css_dir / "style.css").write_text("body { color: red; }")

    first = _compute_static_versions(tmp_path)
    second = _compute_static_versions(tmp_path)

    assert first == second
