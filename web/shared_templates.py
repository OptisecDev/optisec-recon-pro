"""Shared Jinja2Templates instance with license global — import from here, not directly."""
from pathlib import Path
from fastapi.templating import Jinja2Templates
from web.license import get_license

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals["get_license"] = get_license
