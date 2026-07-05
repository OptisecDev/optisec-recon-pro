import os
import re
import time
import secrets
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import bcrypt
from jose import JWTError, jwt
from fastapi import HTTPException, Request, WebSocket
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config import JWT_SECRET as SECRET_KEY  # config resolves/validates JWT_SECRET at startup

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "30"))

# ─── Trusted proxy IP resolution ───────────────────────────────────────────────
# Set TRUSTED_PROXY_IPS (comma-separated) when deploying behind a reverse
# proxy such as Nginx, so X-Forwarded-For / X-Real-IP are only honored when
# they come from that proxy. Left empty, no client-supplied IP header is
# ever trusted, preventing IP spoofing for rate limiting / auth logging.
_TRUSTED_PROXY_IPS = {
    ip.strip() for ip in os.environ.get("TRUSTED_PROXY_IPS", "").split(",") if ip.strip()
}


def get_client_ip(request: Request) -> str:
    """Return the real client IP, honoring X-Forwarded-For/X-Real-IP only
    when the immediate connecting peer is a trusted reverse proxy."""
    direct_ip = request.client.host if request.client else "unknown"
    if direct_ip in _TRUSTED_PROXY_IPS:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
    return direct_ip

# ─── Auth event logger ─────────────────────────────────────────────────────────
_log_dir = Path(__file__).parent.parent / "logs"
_log_dir.mkdir(exist_ok=True)

_auth_logger = logging.getLogger("optisec.auth")
if not _auth_logger.handlers:
    _handler = logging.FileHandler(_log_dir / "auth.log")
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _auth_logger.addHandler(_handler)
    _auth_logger.setLevel(logging.INFO)


def log_auth_event(event: str, username: str, ip: str, success: bool, detail: str = "") -> None:
    status = "SUCCESS" if success else "FAILURE"
    msg = f"{status} | {event} | user={username!r} | ip={ip}"
    if detail:
        msg += f" | {detail}"
    _auth_logger.info(msg)


# ─── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 900  # 15 minutes in seconds

_login_attempts: dict = defaultdict(list)  # ip -> [monotonic timestamp, ...]


def check_rate_limit(ip: str) -> tuple:
    """Returns (allowed: bool, seconds_remaining: int)."""
    now = time.monotonic()
    timestamps = [t for t in _login_attempts[ip] if now - t < RATE_LIMIT_WINDOW]
    _login_attempts[ip] = timestamps
    if len(timestamps) >= RATE_LIMIT_MAX:
        oldest = min(timestamps)
        remaining = int(RATE_LIMIT_WINDOW - (now - oldest))
        return False, max(remaining, 0)
    return True, 0


def record_failed_attempt(ip: str) -> None:
    _login_attempts[ip].append(time.monotonic())


def clear_attempts(ip: str) -> None:
    _login_attempts.pop(ip, None)


# ─── Password utilities ────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


_SPECIAL_CHARS = set('!@#$%^&*(),.?":{}|<>[]_-+=~`/\\;\'')


def validate_password_strength(password: str) -> list:
    """Returns list of human-readable error strings. Empty list = strong enough."""
    errors = []
    if len(password) < 8:
        errors.append("minimum 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("at least one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("at least one digit (0-9)")
    if not any(c in _SPECIAL_CHARS for c in password):
        errors.append("at least one special character (!@#$%^&*…)")
    return errors


# ─── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(user_id: int, role: str, expires_minutes: int = None) -> str:
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes or ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def generate_api_key() -> str:
    return secrets.token_hex(32)


def hash_api_key(api_key: str) -> str:
    """SHA-256 hex digest used for API key storage/lookup.

    generate_api_key() already produces 256 bits of secrets.token_hex
    randomness, so there's no offline brute-force risk that would call for
    a slow/salted hash (unlike passwords) -- a fast deterministic hash is
    what lets get_current_user do an indexed equality lookup below, and
    the plaintext key is never stored, only shown once at issue time.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


async def get_current_user(request: Request, db: AsyncSession):
    from web.models import User

    # API key header takes priority
    api_key = request.headers.get("X-API-Key")
    if api_key:
        result = await db.execute(
            select(User).where(User.api_key_hash == hash_api_key(api_key), User.is_active == True)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return user

    # Bearer token or cookie
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_ws_user(websocket: WebSocket, db: AsyncSession):
    """Authenticate a WebSocket handshake.

    Browsers cannot attach custom headers to a WebSocket handshake, so a
    `?token=` query param is accepted in addition to the same
    Authorization/cookie sources `get_current_user` reads (WebSocket and
    Request both expose `.headers`/`.cookies`, so same-origin page loads
    that already carry the `access_token` cookie work with no frontend
    changes). Raises HTTPException(401) on any failure — callers must
    catch this and close the socket themselves, since a WebSocket has not
    been accepted yet and cannot be answered like a normal HTTP request.
    """
    from web.models import User

    token = websocket.query_params.get("token")
    if not token:
        return await get_current_user(websocket, db)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_roles(*roles: str):
    def check(user) -> None:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
    return check


require_admin = require_roles("admin")
require_analyst_or_admin = require_roles("admin", "analyst")
