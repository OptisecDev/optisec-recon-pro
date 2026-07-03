# Security Notes

## Initial admin / demo passwords

On first startup (when the `users` table is empty), OPTISEC creates one
`admin` account and one `demo` account. Their initial passwords are sourced
in this order:

1. `FIRST_ADMIN_PASSWORD` / `DEMO_INITIAL_PASSWORD` environment variables, if set.
2. Otherwise, a random strong password (`secrets.token_urlsafe`) is generated
   and written **once** to a local file — `/tmp/optisec_initial_creds_<role>_<timestamp>.txt`,
   created with `chmod 600`. It is **never** printed to stdout or the
   application logs.

Neither password is ever logged in plaintext, regardless of which path is used.

### Setting the initial admin password on Render

1. Open the Render dashboard → your web service → **Environment**.
2. Add `FIRST_ADMIN_PASSWORD` with a strong value before the first deploy
   that creates the `users` table (it only applies while the table is empty).
3. Optionally set `DEMO_INITIAL_PASSWORD` the same way. The public "Try Demo"
   button on the login page (`GET /demo`) creates a session directly and does
   not check this password — it only matters if someone logs in through the
   normal form with `demo` / this password.
4. If you don't set `FIRST_ADMIN_PASSWORD`, SSH/exec into the running
   instance immediately after the first boot and read
   `/tmp/optisec_initial_creds_admin_*.txt`, then **delete the file** — it is
   not cleaned up automatically and must not be left on the server.

## Rotating the admin password (it was previously exposed in logs)

Earlier versions of this app printed the initial admin/demo passwords in
plaintext to stdout/logs on first startup. If your deployment ever ran that
code, treat those credentials as compromised and rotate them:

1. Pick a new strong password.
2. There is currently no in-app "change password" UI/endpoint, so update the
   hash directly against the database used by your deployment:

   ```bash
   python - <<'EOF'
   import asyncio
   from sqlalchemy import select
   from web.database import SessionLocal
   from web.models import User
   from web.auth import hash_password

   NEW_PASSWORD = "REPLACE-WITH-A-NEW-STRONG-PASSWORD"

   async def main():
       async with SessionLocal() as db:
           user = (await db.execute(
               select(User).where(User.username == "admin")
           )).scalar_one()
           user.password_hash = hash_password(NEW_PASSWORD)
           await db.commit()
           print("Password rotated for:", user.username)

   asyncio.run(main())
   EOF
   ```

3. Run this against the same `DATABASE_URL` your deployment uses (set it in
   the shell environment first if it isn't already, e.g. on a Render shell).
4. Invalidate any existing sessions for that account by rotating `JWT_SECRET`
   (this logs out **all** users, admin and non-admin) if you suspect the
   session token itself — not just the password — may have been exposed.
5. Also rotate the account's API key (`api_key` column) the same way if it
   was ever logged or shared alongside the password.
6. Check historical log storage (platform log retention, any log
   aggregation/export you have configured) and purge or restrict access to
   any retained logs that contain the old plaintext password.
