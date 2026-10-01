"""Quantum-Safe Encryption router."""

import functools

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from web.license import require_feature_or_402
from web.shared_templates import templates
from config import APP_NAME

router = APIRouter(prefix="/quantum", tags=["quantum"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _pqc_safe(fn):
    """Turn modules.quantum.encryption.PQCUnavailableError into an explicit
    HTTP 503 instead of letting a real-PQC endpoint 500 or (worse) fall
    through to fabricated data -- there is no fallback path left to fall
    through to."""
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        from modules.quantum.encryption import PQCUnavailableError
        try:
            return await fn(*args, **kwargs)
        except PQCUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return wrapper


@router.get("", response_class=HTMLResponse)
async def quantum_home(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    from modules.quantum.encryption import get_algorithms, get_hybrid_schemes, list_keys
    return templates.TemplateResponse(request, "quantum.html", {
        "app_name": APP_NAME, "user": user, "active": "quantum",
        "algorithms": get_algorithms(),
        "hybrid_schemes": get_hybrid_schemes(),
        "keys": list_keys(user_id=user.id, is_admin=user.role == "admin"),
    })


@router.get("/api/algorithms")
async def list_algorithms(user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    from modules.quantum.encryption import get_algorithms, get_hybrid_schemes
    return {"algorithms": get_algorithms(), "hybrid_schemes": get_hybrid_schemes()}


@router.post("/api/keypair")
@_pqc_safe
async def generate_keypair(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import generate_keypair
    result = generate_keypair(algorithm=data.get("algorithm", "kyber768"), user_id=user.id)
    # Never expose private key via API
    result.pop("private_key", None)
    return result


@router.post("/api/encapsulate")
@_pqc_safe
async def encapsulate(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import encapsulate as _enc
    return _enc(
        public_key_b64=data.get("public_key", ""),
        algorithm=data.get("algorithm", "kyber768"),
    )


@router.post("/api/decapsulate")
@_pqc_safe
async def decapsulate(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import decapsulate as _dec
    return _dec(
        private_key_b64=data.get("private_key", ""),
        ciphertext_b64=data.get("ciphertext", ""),
        algorithm=data.get("algorithm", "kyber768"),
    )


@router.post("/api/sign")
@_pqc_safe
async def sign_message(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import sign as _sign
    return _sign(
        private_key_b64=data.get("private_key", ""),
        message=data.get("message", ""),
        algorithm=data.get("algorithm", "dilithium3"),
    )


@router.post("/api/verify")
@_pqc_safe
async def verify_signature(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import verify as _verify
    return _verify(
        public_key_b64=data.get("public_key", ""),
        message=data.get("message", ""),
        signature_b64=data.get("signature", ""),
        algorithm=data.get("algorithm", "dilithium3"),
    )


@router.post("/api/encrypt")
async def encrypt_data(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import encrypt_data as _enc
    try:
        return _enc(
            data=data.get("data", ""),
            shared_secret_b64=data.get("shared_secret", ""),
        )
    except ImportError:
        return {"error": "Install cryptography package: pip install cryptography"}


@router.post("/api/decrypt")
async def decrypt_data(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import decrypt_data as _dec
    return _dec(
        ciphertext_b64=data.get("ciphertext", ""),
        nonce_b64=data.get("nonce", ""),
        shared_secret_b64=data.get("shared_secret", ""),
    )


@router.post("/api/assess")
async def assess_algorithm(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import assess_crypto_strength
    return assess_crypto_strength(data.get("algorithm", ""))


@router.get("/api/keys")
async def list_keys_api(user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    from modules.quantum.encryption import list_keys
    return {"keys": list_keys(user_id=user.id, is_admin=user.role == "admin")}


# --------------------------------------------------------------------------
# Hybrid schemes (real PQC + classical combination)
# --------------------------------------------------------------------------

@router.post("/api/hybrid/keypair")
@_pqc_safe
async def generate_hybrid_keypair(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import generate_hybrid_keypair as _gen
    result = _gen(scheme=data.get("scheme", "kyber768_x25519"), user_id=user.id)
    result.pop("pqc_private_key", None)
    result.pop("classical_private_key", None)
    return result


# --------------------------------------------------------------------------
# Server-side round-trip demos -- prove KEM/sign/encrypt/hybrid round trips
# actually succeed without ever putting a private key on the wire (the
# generate_keypair endpoint above never returns one). Powers the "Proof"
# tab in the UI.
# --------------------------------------------------------------------------

@router.post("/api/demo/kem")
@_pqc_safe
async def demo_kem(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import demo_kem_roundtrip
    return demo_kem_roundtrip(algorithm=data.get("algorithm", "kyber768"))


@router.post("/api/demo/sign")
@_pqc_safe
async def demo_sign(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import demo_sign_roundtrip
    return demo_sign_roundtrip(
        algorithm=data.get("algorithm", "dilithium3"),
        message=data.get("message", "OPTISEC quantum-safe test"),
    )


@router.post("/api/demo/encrypt")
@_pqc_safe
async def demo_encrypt(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import demo_encrypt_roundtrip
    return demo_encrypt_roundtrip(
        algorithm=data.get("algorithm", "kyber768"),
        message=data.get("message", "OPTISEC quantum-safe secret"),
    )


@router.post("/api/demo/hybrid")
@_pqc_safe
async def demo_hybrid(request: Request, user: User = Depends(_user)):
    require_feature_or_402("quantum", user)
    data = await request.json()
    from modules.quantum.encryption import demo_hybrid_roundtrip
    return demo_hybrid_roundtrip(
        scheme=data.get("scheme", "kyber768_x25519"),
        message=data.get("message", "OPTISEC hybrid quantum-safe test"),
    )
