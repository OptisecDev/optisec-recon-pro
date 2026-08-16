"""Live breach lookups against the HaveIBeenPwned (HIBP) v3 API.

Only breach metadata (name, title, dates, description) is ever returned —
this module never touches HIBP's pastes/stealer-log endpoints or any
endpoint that could expose leaked credentials.
"""
import asyncio
import logging

import httpx

from app.core.config import HIBP_API_KEY

logger = logging.getLogger("app.services.external.hibp")

_BREACHED_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
_USER_AGENT = "OPTISEC-Recon/1.0"
_TIMEOUT = 10.0


async def check_hibp(email: str) -> dict:
    """Query HIBP for breaches tied to `email`.

    Returns {"breaches": [...], "message": str | None}. A 404 (no breaches
    found) is not an error — it comes back as an empty list with an
    explanatory message. Any other non-2xx response raises
    httpx.HTTPStatusError so the caller can fall back to mock data.
    """
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": _USER_AGENT,
    }
    url = _BREACHED_ACCOUNT_URL.format(email=email)

    async with httpx.AsyncClient(timeout=_TIMEOUT, verify=True) as client:
        response = await client.get(url, headers=headers, params={"truncateResponse": "false"})

        if response.status_code == 429:
            logger.warning("HIBP rate limit hit for lookup; retrying in 1s")
            await asyncio.sleep(1)
            response = await client.get(
                url, headers=headers, params={"truncateResponse": "false"}
            )

        if response.status_code == 404:
            return {"breaches": [], "message": "لم يتم العثور على تسريبات لهذا البريد."}

        response.raise_for_status()
        return {"breaches": response.json(), "message": None}
