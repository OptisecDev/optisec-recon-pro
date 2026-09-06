"""Shared Jinja2Templates instance with license globals — import from here, not directly."""
from pathlib import Path
from fastapi.templating import Jinja2Templates
from web.license import get_license, user_has_feature, user_tier, user_tier_label, user_tier_color

BASE_DIR = Path(__file__).parent


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


templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
register_template_globals(templates)
