"""Shared Jinja2Templates instance with license globals — import from here, not directly."""
import hashlib
from pathlib import Path
from fastapi.templating import Jinja2Templates
from web.license import get_license, user_has_feature, user_tier, user_tier_label, user_tier_color

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"


def _compute_static_versions(static_dir: Path = STATIC_DIR) -> dict[str, str]:
    """Content-hash every local CSS/JS file once at startup, keyed by its
    path relative to web/static/ (e.g. "css/style.css"). Used by static_v()
    below to cache-bust asset URLs so a deploy that changes style.css /
    inline-extracted.css / main.js together (see commit ac9a488) can't leave
    a browser serving a stale file paired with fresh markup."""
    versions = {}
    for path in static_dir.rglob("*"):
        if path.suffix not in (".css", ".js"):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:10]
        versions[path.relative_to(static_dir).as_posix()] = digest
    return versions


STATIC_VERSIONS = _compute_static_versions()


def static_v(path: str) -> str:
    """Return "/static/<path>?v=<content-hash>" for a local CSS/JS file.
    Raises KeyError for an unknown path rather than silently serving an
    unversioned URL -- see STATIC_VERSIONS."""
    return f"/static/{path}?v={STATIC_VERSIONS[path]}"


def register_template_globals(instance: Jinja2Templates) -> None:
    """Register every Jinja global shared across the project's Jinja2Templates
    instances. Call this on each instance (see web/app.py) instead of setting
    env.globals[...] by hand, so a global added here never has to be added
    separately per instance again."""
    instance.env.globals["get_license"] = get_license
    instance.env.globals["user_has_feature"] = user_has_feature
    instance.env.globals["user_tier"] = user_tier
    instance.env.globals["user_tier_label"] = user_tier_label
    instance.env.globals["user_tier_color"] = user_tier_color
    instance.env.globals["static_v"] = static_v


templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
register_template_globals(templates)
