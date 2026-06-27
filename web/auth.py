import os
import secrets
from datetime import datetime, timedelta

import bcrypt
from jose import JWTError, jwt
from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

SECRET_KEY = os.environ.get("JWT_SECRET", "optisec-enterprise-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(user_id: int, role: str, expires_hours: int = None) -> str:
    expire = datetime.utcnow() + timedelta(hours=expires_hours or ACCESS_TOKEN_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def generate_api_key() -> str:
    return secrets.token_hex(32)


async def get_current_user(request: Request, db: AsyncSession):
    from web.models import User

    # API key header takes priority
    api_key = request.headers.get("X-API-Key")
    if api_key:
        result = await db.execute(
            select(User).where(User.api_key == api_key, User.is_active == True)
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


def require_roles(*roles: str):
    def check(user) -> None:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
    return check


require_admin = require_roles("admin")
require_analyst_or_admin = require_roles("admin", "analyst")
