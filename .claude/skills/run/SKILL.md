---
description: Launch OPTISEC v4.0 SINGULARITY web dashboard and verify it's running
---

# Run OPTISEC Web Dashboard

FastAPI app served via uvicorn on port 8000. Uses a local SQLite DB and a Python venv.

## Prerequisites

```bash
# venv must exist (created on first run automatically)
[ -d venv ] || python3 -m venv venv && venv/bin/pip install -q -r requirements.txt
```

## Start

```bash
pkill -f "uvicorn web.app:app" 2>/dev/null; sleep 1
source venv/bin/activate
source .env   # loads GROQ_API_KEY, OTX_API_KEY, etc.
uvicorn web.app:app --host 0.0.0.0 --port 8000 > /tmp/optisec.log 2>&1 &
echo $! > /tmp/optisec.pid

# Wait for ready
timeout 30 bash -c 'until curl -sf http://localhost:8000/login > /dev/null; do sleep 1; done'
echo "Server up"
```

Or via the project script:

```bash
bash start.sh web
```

## Verify

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/login
# → 200
```

## Auth (get a logged-in session)

The first-run admin is auto-created. Password is printed to stdout on first startup.
If the DB already exists, use whatever password was set (or reset it):

```bash
# Reset admin password in the DB
source venv/bin/activate && python3 -c "
import asyncio
from web.database import SessionLocal
from web.models import User
from web.auth import hash_password
from sqlalchemy import select

async def reset():
    async with SessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == 'admin'))).scalar_one_or_none()
        if u:
            u.password_hash = hash_password('Optisec123!')
            await db.commit()
            print('Password is now: Optisec123!')
asyncio.run(reset())
"
```

Then log in via web form and capture the session cookie:

```bash
curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST http://localhost:8000/login \
  -d "username=admin&password=Optisec123!&next=/" \
  -D /tmp/login_headers.txt -o /dev/null
grep "set-cookie" /tmp/login_headers.txt   # should show access_token
```

Or via JSON API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Optisec123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
```

## Drive with Playwright (screenshot a page)

Playwright is installed in the venv:

```python
source venv/bin/activate && python3 - << 'PYEOF'
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--no-sandbox','--disable-gpu'])
    page = browser.new_page(viewport={'width': 1400, 'height': 900})

    # Login
    page.goto('http://localhost:8000/login')
    page.fill('input[name="username"]', 'admin')
    page.fill('input[name="password"]', 'Optisec123!')
    page.click('button[type="submit"]')
    page.wait_for_url('http://localhost:8000/', timeout=5000)

    # Navigate to any page (increase timeout for OTX/slow pages)
    page.goto('http://localhost:8000/threat-feed', timeout=60000, wait_until='networkidle')
    page.screenshot(path='/tmp/optisec_screenshot.png', full_page=False)
    browser.close()
PYEOF
```

## Stop

```bash
kill $(cat /tmp/optisec.pid) 2>/dev/null
# or
pkill -f "uvicorn web.app:app"
```

## Key routes

| Route | Description |
|---|---|
| `/` | Dashboard (scan counts, recent scans) |
| `/scan` | Run a new scan |
| `/targets` | Manage targets |
| `/threat-feed` | AlienVault OTX live IOC feed (15s first load, cached 5min) |
| `/osint` | OSINT tools |
| `/admin` | User management, auth log |
| `/threat-feed/api/otx/test` | Test OTX API connectivity |

## Gotchas

- **`/threat-feed` first load is slow (~15s)** — AlienVault OTX API latency. Subsequent loads serve from a 5-minute in-process cache.
- **OTX_API_KEY must be in `.env`** — without it the page falls back to simulated data.
- **SQLite DB is at `data/optisec.db`** — safe to delete to reset all state (admin re-created on next startup).
- **`--reload` flag causes cache loss** — don't use `--reload` in production; it respawns workers and clears the OTX in-memory cache.
- **Port 8000** — check with `lsof -i :8000` before starting; always `pkill` the old process first.
