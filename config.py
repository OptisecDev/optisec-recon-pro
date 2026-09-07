import os
import logging
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
GROQ_MODEL = "openai/gpt-oss-120b"
GROQ_CONCURRENCY_LIMIT = int(os.environ.get("GROQ_CONCURRENCY_LIMIT", "20"))
GROQ_TPM_LIMIT = int(os.environ.get("GROQ_TPM_LIMIT", "8000"))
GROQ_TPD_LIMIT = int(os.environ.get("GROQ_TPD_LIMIT", "200000"))

# Analytics — GA4 measurement ID for the public /landing and /redeem
# purchase-path pages only. Empty by default: templates render no tracking
# snippet at all until this is set.
GA_MEASUREMENT_ID = os.environ.get("GA_MEASUREMENT_ID", "")

# Threat Intelligence
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
URLHAUS_API_KEY = os.environ.get("URLHAUS_API_KEY", "")

# Threat Sharing — opt-in outbound IOC sharing (modules/threat_intel/threat_sharing.py).
# Disabled by default: no IOC ever leaves this deployment unless an operator
# explicitly sets this to true AND then explicitly triggers each share.
ENABLE_THREAT_SHARING = os.environ.get("ENABLE_THREAT_SHARING", "false").strip().lower() == "true"

# Database — defaults to SQLite; set DATABASE_URL for PostgreSQL
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{DATA_DIR}/optisec.db",
)

# Auth
# GROQ_ENV is this project's general app-environment flag -- not
# Groq-API-specific despite the name.
_DEV_TESTING_ENV_VALUES = {"development", "dev", "test", "testing"}
_INSECURE_DEV_JWT_SECRET = "optisec-INSECURE-dev-default-key-do-not-use-in-production"


def _resolve_is_production() -> bool:
    return os.environ.get("GROQ_ENV") == "production" or bool(os.environ.get("RENDER"))


# Shared with the session cookie's Secure flag (web/app.py) so a plain HTTP
# local dev server keeps working -- Secure cookies are dropped by browsers
# on a non-HTTPS connection.
IS_PRODUCTION = _resolve_is_production()


def _resolve_jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    if secret:
        return secret

    is_production = os.environ.get("GROQ_ENV") == "production" or bool(os.environ.get("RENDER"))
    is_dev_or_testing = os.environ.get("GROQ_ENV") in _DEV_TESTING_ENV_VALUES

    if is_dev_or_testing:
        logging.getLogger("optisec").warning(
            "JWT_SECRET is not set — using an INSECURE default signing key because "
            "GROQ_ENV=%r explicitly opts into dev/testing mode. Never do this in "
            "production.", os.environ.get("GROQ_ENV"),
        )
        return _INSECURE_DEV_JWT_SECRET

    reason = (
        "production mode (GROQ_ENV=production or RENDER is set)" if is_production
        else "GROQ_ENV is not explicitly set to development/dev/test/testing"
    )
    raise RuntimeError(
        f"JWT_SECRET environment variable is not set, and {reason}. Refusing to "
        "start: set JWT_SECRET to a long random string, or set "
        "GROQ_ENV=development (or dev/test/testing) to explicitly opt into an "
        "insecure default for local development only."
    )


JWT_SECRET = _resolve_jwt_secret()
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))

# First-run admin credentials (used only when DB is empty)
FIRST_ADMIN_USER = os.environ.get("FIRST_ADMIN_USER", "admin")
FIRST_ADMIN_EMAIL = os.environ.get("FIRST_ADMIN_EMAIL", "admin@optisec.local")

# App
APP_NAME = "OPTISEC v4.0 SINGULARITY"
APP_VERSION = "4.0.0-singularity"
ACCENT_COLOR = "#00ff88"

# Scanning
# 5s per request is still generous for a live target that's actually up; a
# hung/filtered request no longer eats a full 10s before the (now-concurrent)
# scanners can move on, halving the worst-case per-request wait.
DEFAULT_TIMEOUT = 5
MAX_THREADS = 50
# Concurrency for the vuln scanners (xss/sqli/ssrf/lfi/open_redirect), which
# test one target's params/forms in parallel. Kept well below MAX_THREADS
# (used for lightweight DNS-only subdomain probing) since these are full
# HTTP requests against a single live target — too high a value risks
# looking like a request flood / tripping the target's own rate limiting.
#
# Lowered from 8 to 4 after the 2026-09-07 04:41 OOM on Render's free tier
# (512MB hard cap, 2 uvicorn workers per README's start command). Measured
# locally against the same `--workers 2` command: each worker's baseline
# import/startup footprint alone is ~155-160MB RSS (~310-320MB idle for both
# workers, before a single request), leaving a thin ~190-200MB shared budget
# for everything else. Each concurrent scanner thread fully buffers+decodes
# one HTTP response body (`requests`' `r.text`, not streamed) — measured
# transient cost is roughly 3x the target page's size per in-flight thread
# (e.g. a ~3MB page cost ~9-10MB/thread at the moment of decode). Since scan
# targets are arbitrary/unpredictable (this is a recon tool, not a fixed
# internal API), a single scan hitting a large page at concurrency=8 could
# transiently add 60-150MB+ on top of the ~310MB baseline. concurrency=4
# halves that worst case while keeping most of the parallel speedup, and
# keeps combined usage under 512MB with the requested 30%+ safety margin for
# page sizes up to a few MB. Does not address the ~300MB fixed two-worker
# baseline itself (would need --workers 1 or a paid plan — out of scope here,
# both deliberately deferred).
VULN_SCAN_CONCURRENCY = int(os.environ.get("VULN_SCAN_CONCURRENCY", "4"))
NMAP_DEFAULT_FLAGS = "-sV -sC --open"
WORDLIST_PATH = DATA_DIR / "wordlists" / "subdomains.txt"
TARGETS_FILE = DATA_DIR / "targets.json"
