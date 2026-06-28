import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent
load_dotenv(BASE_DIR / ".env")
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"

REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# AI
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = "llama-3.3-70b-versatile"

# Database — defaults to SQLite; set DATABASE_URL for PostgreSQL
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{DATA_DIR}/optisec.db",
)

# Auth
JWT_SECRET = os.environ.get("JWT_SECRET", "optisec-enterprise-key-change-in-production")
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))

# First-run admin credentials (used only when DB is empty)
FIRST_ADMIN_USER = os.environ.get("FIRST_ADMIN_USER", "admin")
FIRST_ADMIN_EMAIL = os.environ.get("FIRST_ADMIN_EMAIL", "admin@optisec.local")
FIRST_ADMIN_PASSWORD = os.environ.get("FIRST_ADMIN_PASSWORD", "admin123")

# App
APP_NAME = "OPTISEC v4.0 SINGULARITY"
APP_VERSION = "4.0.0-singularity"
ACCENT_COLOR = "#00ff88"

# Scanning
DEFAULT_TIMEOUT = 10
MAX_THREADS = 50
NMAP_DEFAULT_FLAGS = "-sV -sC --open"
WORDLIST_PATH = DATA_DIR / "wordlists" / "subdomains.txt"
TARGETS_FILE = DATA_DIR / "targets.json"
