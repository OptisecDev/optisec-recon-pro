"""Rotate the password hash for a single existing user (e.g. admin, demo).

Standalone script — does not import web.app, does not touch any other
column. Uses the exact same hashing (web.auth.hash_password, bcrypt) and
strength policy (web.auth.validate_password_strength) as registration and
the initial admin/demo seeder, and the same DB session factory
(web.database.SessionLocal, async) the rest of the app uses.

The new password is read only from ROTATE_NEW_PASSWORD — it is never
logged, printed, or echoed back, including in error messages.

Usage:
    ROTATE_USERNAME=admin ROTATE_NEW_PASSWORD='...' python scripts/rotate_admin_password.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from web.auth import hash_password, validate_password_strength  # noqa: E402
from web.database import SessionLocal  # noqa: E402
from web.models import User  # noqa: E402


async def rotate_password(username: str, new_password: str) -> None:
    async with SessionLocal() as db:
        user = (await db.execute(
            select(User).where(User.username == username)
        )).scalar_one_or_none()

        if user is None:
            print(f"[OPTISEC] Error: no user found with username: {username}", file=sys.stderr)
            sys.exit(1)

        user.password_hash = hash_password(new_password)
        await db.commit()

    print(f"[OPTISEC] Password rotated for user: {username}")


def main() -> None:
    username = os.environ.get("ROTATE_USERNAME")
    new_password = os.environ.get("ROTATE_NEW_PASSWORD")

    if not username:
        print("[OPTISEC] Error: ROTATE_USERNAME environment variable is not set", file=sys.stderr)
        sys.exit(1)
    if not new_password:
        print("[OPTISEC] Error: ROTATE_NEW_PASSWORD environment variable is not set", file=sys.stderr)
        sys.exit(1)

    errors = validate_password_strength(new_password)
    if errors:
        print(
            "[OPTISEC] Error: new password does not meet strength requirements: "
            + ", ".join(errors),
            file=sys.stderr,
        )
        sys.exit(1)

    asyncio.run(rotate_password(username, new_password))


if __name__ == "__main__":
    main()
