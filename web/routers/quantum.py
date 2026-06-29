"""Quantum-Safe Encryption router."""

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/quantum", tags=["quantum"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


@router.get("", response_class=HTMLResponse)
async def quantum_home(request: Request, user: User = Depends(_user)):
    from modules.quantum.encryption import get_algorithms, get_hybrid_schemes, list_keys
    return templates.TemplateResponse(request, "quantum.html", {
        "app_name": APP_NAME, "user": user, "active": "quantum",
        "algorithms": get_algorithms(),
        "hybrid_schemes": get_hybrid_schemes(),
        "keys": list_keys(),
    })


@router.get("/api/algorithms")
async def list_algorithms(user: User = Depends(_user)):
    from modules.quantum.encryption import get_algorithms, get_hybrid_schemes
    return {"algorithms": get_algorithms(), "hybrid_schemes": get_hybrid_schemes()}


@router.post("/api/keypair")
async def generate_keypair(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.quantum.encryption import generate_keypair
    result = generate_keypair(algorithm=data.get("algorithm", "kyber768"))
    # Never expose private key via API
    result.pop("private_key", None)
    return result


@router.post("/api/encapsulate")
async def encapsulate(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.quantum.encryption import encapsulate as _enc
    return await _enc(
        public_key_b64=data.get("public_key", ""),
        algorithm=data.get("algorithm", "kyber768"),
    ) if False else _enc(
        public_key_b64=data.get("public_key", ""),
        algorithm=data.get("algorithm", "kyber768"),
    )


@router.post("/api/encrypt")
async def encrypt_data(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.quantum.encryption import encrypt_data as _enc
    try:
        return _enc(
            data=data.get("data", ""),
            shared_secret_b64=data.get("shared_secret", ""),
        )
    except ImportError:
        return {"error": "Install cryptography package: pip install cryptography"}


@router.post("/api/assess")
async def assess_algorithm(request: Request, user: User = Depends(_user)):
    data = await request.json()
    from modules.quantum.encryption import assess_crypto_strength
    return assess_crypto_strength(data.get("algorithm", ""))


@router.get("/api/keys")
async def list_keys_api(user: User = Depends(_user)):
    from modules.quantum.encryption import list_keys
    return {"keys": list_keys()}
