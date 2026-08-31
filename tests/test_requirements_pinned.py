"""
Regression test: requirements.txt entries were declared with an open-ended
lower bound (e.g. "flask>=3.0.0") rather than an exact pin. An unbounded
lower bound lets a future `pip install -r requirements.txt` silently pull
in a newer major version of any dependency and break the app without
warning. Every real PyPI dependency must be pinned to an exact version
with "==" (the git+ theHarvester line is exempt -- it is already pinned to
a fixed tag via @4.11.1, just not through PyPI's == syntax).
"""

import os
import re

REQUIREMENTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "requirements.txt"
)

PIN_RE = re.compile(r"^[A-Za-z0-9_.\-]+(\[[A-Za-z0-9_,.\-]+\])?==[^\s<>=!~]+$")


def _requirement_lines():
    with open(REQUIREMENTS_PATH) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("git+"):
                continue
            yield stripped


def test_requirements_file_is_not_empty():
    lines = list(_requirement_lines())
    assert len(lines) > 30


def test_all_pypi_requirements_are_pinned_with_exact_version():
    unpinned = [line for line in _requirement_lines() if not PIN_RE.match(line)]
    assert unpinned == [], (
        f"requirements.txt has unpinned entries (must use ==): {unpinned}"
    )


def test_no_open_ended_version_specifiers_remain():
    with open(REQUIREMENTS_PATH) as f:
        content = f.read()
    for op in (">=", "<=", "~="):
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("git+"):
                continue
            assert op not in stripped, f"found {op!r} in requirement line: {stripped!r}"
