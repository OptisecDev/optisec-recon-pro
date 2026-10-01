"""Quantum-Safe Encryption — real NIST PQC (FIPS 203/204/205) via liboqs.

Every operation below calls the liboqs native library through liboqs-python.
There is no simulated/mock code path: if liboqs cannot be loaded,
PQCUnavailableError is raised rather than returning fabricated key material
or a fabricated "success". See _require_oqs().
"""

import ctypes.util
import hashlib
import json
import os
import re
import secrets
from base64 import b64decode, b64encode
from datetime import datetime
from pathlib import Path
from typing import Optional

KEYS_DIR = Path("data/quantum_keys")

# NIST PQC Standard algorithms (FIPS 203/204/205)
PQC_ALGORITHMS = {
    "kyber768": {
        "name": "ML-KEM-768 (CRYSTALS-Kyber)",
        "type": "key_encapsulation",
        "standard": "FIPS 203",
        "security_level": 3,
        "public_key_size": 1184,
        "private_key_size": 2400,
        "ciphertext_size": 1088,
        "shared_secret_size": 32,
        "quantum_resistant": True,
        "nist_status": "standardized",
    },
    "kyber1024": {
        "name": "ML-KEM-1024 (CRYSTALS-Kyber)",
        "type": "key_encapsulation",
        "standard": "FIPS 203",
        "security_level": 5,
        "public_key_size": 1568,
        "private_key_size": 3168,
        "ciphertext_size": 1568,
        "shared_secret_size": 32,
        "quantum_resistant": True,
        "nist_status": "standardized",
    },
    "dilithium3": {
        "name": "ML-DSA-65 (CRYSTALS-Dilithium)",
        "type": "digital_signature",
        "standard": "FIPS 204",
        "security_level": 3,
        "public_key_size": 1952,
        "private_key_size": 4000,
        "signature_size": 3293,
        "quantum_resistant": True,
        "nist_status": "standardized",
    },
    "sphincs_sha2": {
        "name": "SLH-DSA-SHA2-128s (SPHINCS+)",
        "type": "digital_signature",
        "standard": "FIPS 205",
        "security_level": 1,
        "public_key_size": 32,
        "private_key_size": 64,
        "signature_size": 7856,
        "quantum_resistant": True,
        "nist_status": "standardized",
    },
    "falcon512": {
        "name": "FN-DSA-512 (Falcon)",
        "type": "digital_signature",
        "standard": "FIPS draft",
        "security_level": 1,
        "public_key_size": 897,
        "private_key_size": 1281,
        "signature_size": 666,
        "quantum_resistant": True,
        "nist_status": "standardized",
    },
}

# liboqs' algorithm identifiers (current, FIPS-final names) for each entry
# above. liboqs dropped the old round-3 "Kyber768"/"Dilithium3"/
# "SPHINCS+-SHA2-128s-simple" identifiers once ML-KEM/ML-DSA/SLH-DSA were
# finalized -- using those old strings against a current liboqs build
# raises, so this mapping must track liboqs' actual enabled-mechanism names.
_OQS_ALG_NAMES = {
    "kyber768": "ML-KEM-768",
    "kyber1024": "ML-KEM-1024",
    "dilithium3": "ML-DSA-65",
    "sphincs_sha2": "SLH_DSA_PURE_SHA2_128S",
    "falcon512": "Falcon-512",
}

HYBRID_SCHEMES = {
    "kyber768_x25519": {
        "name": "Kyber-768 + X25519 Hybrid",
        "kem": "kyber768",
        "classical": "X25519",
        "description": "Combines PQC KEM with classical ECDH for defense-in-depth",
    },
    "dilithium3_ed25519": {
        "name": "Dilithium-3 + Ed25519 Hybrid",
        "sig": "dilithium3",
        "classical": "Ed25519",
        "description": "PQC signature combined with classical EdDSA",
    },
}


class PQCUnavailableError(Exception):
    """Raised when liboqs is not loaded and a real PQC operation cannot proceed.

    Deliberately never caught internally and turned into a fake success --
    callers (web/routers/quantum.py) are expected to surface this as an
    explicit error (HTTP 503) rather than silently falling back to mock
    key material.
    """


_oqs_module = None
_oqs_unavailable_reason: Optional[str] = None


def _liboqs_discoverable() -> bool:
    """Check whether liboqs' shared library can be found WITHOUT importing
    the oqs module.

    liboqs-python's module-level `_load_liboqs()` runs at `import oqs` time
    and, if it can't find the library, automatically git-clones and compiles
    the *entire* liboqs suite from source as a fallback -- a multi-minute,
    network-dependent build with no business running inside a live request.
    Checking discoverability ourselves first means a genuinely-missing
    liboqs fails immediately (PQCUnavailableError) instead of silently
    kicking off that build.
    """
    if ctypes.util.find_library("oqs"):
        return True
    install_path = os.environ.get("OQS_INSTALL_PATH")
    if install_path:
        for sub in ("lib", "lib64"):
            lib_dir = Path(install_path) / sub
            if lib_dir.is_dir() and any(lib_dir.glob("liboqs.so*")):
                return True
    return False


def _require_oqs():
    """Return the loaded `oqs` module, or raise PQCUnavailableError."""
    global _oqs_module, _oqs_unavailable_reason
    if _oqs_module is not None:
        return _oqs_module
    if _oqs_unavailable_reason is not None:
        raise PQCUnavailableError(_oqs_unavailable_reason)

    if not _liboqs_discoverable():
        _oqs_unavailable_reason = (
            "Real PQC unavailable — liboqs not loaded. The liboqs native "
            "library was not found on this system."
        )
        raise PQCUnavailableError(_oqs_unavailable_reason)

    try:
        import oqs
    except Exception as exc:  # pragma: no cover - defensive; liboqs is discoverable here
        _oqs_unavailable_reason = f"Real PQC unavailable — liboqs not loaded ({exc})"
        raise PQCUnavailableError(_oqs_unavailable_reason) from exc

    _oqs_module = oqs
    return oqs


def _oqs_name(algorithm: str) -> str:
    return _OQS_ALG_NAMES.get(algorithm, algorithm)


def _is_kem(algorithm: str) -> bool:
    info = PQC_ALGORITHMS.get(algorithm)
    return bool(info) and info["type"] == "key_encapsulation"


# --------------------------------------------------------------------------
# Key generation
# --------------------------------------------------------------------------

def generate_keypair(algorithm: str = "kyber768", user_id: Optional[int] = None) -> dict:
    """Generate a real PQC keypair via liboqs. Raises PQCUnavailableError if
    liboqs isn't loaded -- never returns simulated key material."""
    if algorithm not in PQC_ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {algorithm}. Available: {list(PQC_ALGORITHMS.keys())}")

    oqs = _require_oqs()
    info = PQC_ALGORITHMS[algorithm]
    name = _oqs_name(algorithm)

    obj = oqs.KeyEncapsulation(name) if info["type"] == "key_encapsulation" else oqs.Signature(name)
    try:
        pub = obj.generate_keypair()
        priv = obj.export_secret_key()
    finally:
        obj.free()

    return _format_keypair(algorithm, info, pub, priv, user_id)


def _format_keypair(algorithm: str, info: dict, pub: bytes, priv: bytes,
                     user_id: Optional[int] = None) -> dict:
    key_id = f"pqc-{algorithm}-{secrets.token_hex(6)}"
    now = datetime.utcnow().isoformat()
    result = {
        "key_id": key_id,
        "algorithm": algorithm,
        "algorithm_name": info["name"],
        "type": info["type"],
        "standard": info["standard"],
        "security_level": info["security_level"],
        "public_key": b64encode(pub).decode(),
        "private_key": b64encode(priv).decode(),
        "created_at": now,
        "mode": "liboqs",
        "user_id": user_id,
    }
    _save_key(key_id, result)
    return result


# --------------------------------------------------------------------------
# KEM: encapsulate / decapsulate
# --------------------------------------------------------------------------

def encapsulate(public_key_b64: str, algorithm: str = "kyber768") -> dict:
    """Encapsulate against `public_key_b64` — generate shared secret + ciphertext."""
    oqs = _require_oqs()
    pub_bytes = b64decode(public_key_b64)
    with oqs.KeyEncapsulation(_oqs_name(algorithm)) as kem:
        ciphertext, shared_secret = kem.encap_secret(pub_bytes)
    return {
        "ciphertext": b64encode(ciphertext).decode(),
        "shared_secret": b64encode(shared_secret).decode(),
        "algorithm": algorithm,
        "mode": "liboqs",
    }


def decapsulate(private_key_b64: str, ciphertext_b64: str, algorithm: str = "kyber768") -> dict:
    """Decapsulate `ciphertext_b64` with `private_key_b64` to recover the shared secret."""
    oqs = _require_oqs()
    priv_bytes = b64decode(private_key_b64)
    ct_bytes = b64decode(ciphertext_b64)
    with oqs.KeyEncapsulation(_oqs_name(algorithm), secret_key=priv_bytes) as kem:
        shared_secret = kem.decap_secret(ct_bytes)
    return {
        "shared_secret": b64encode(shared_secret).decode(),
        "algorithm": algorithm,
        "mode": "liboqs",
    }


# --------------------------------------------------------------------------
# Signatures: sign / verify
# --------------------------------------------------------------------------

def sign(private_key_b64: str, message: str, algorithm: str = "dilithium3") -> dict:
    """Sign `message` with `private_key_b64` under a PQC signature algorithm."""
    oqs = _require_oqs()
    priv_bytes = b64decode(private_key_b64)
    with oqs.Signature(_oqs_name(algorithm), secret_key=priv_bytes) as signer:
        signature = signer.sign(message.encode())
    return {
        "signature": b64encode(signature).decode(),
        "algorithm": algorithm,
        "mode": "liboqs",
    }


def verify(public_key_b64: str, message: str, signature_b64: str,
           algorithm: str = "dilithium3") -> dict:
    """Verify `signature_b64` over `message` against `public_key_b64`."""
    oqs = _require_oqs()
    pub_bytes = b64decode(public_key_b64)
    sig_bytes = b64decode(signature_b64)
    with oqs.Signature(_oqs_name(algorithm)) as verifier:
        try:
            valid = verifier.verify(message.encode(), sig_bytes, pub_bytes)
        except Exception:
            valid = False
    return {
        "valid": bool(valid),
        "algorithm": algorithm,
        "mode": "liboqs",
    }


# --------------------------------------------------------------------------
# AES-256-GCM symmetric layer, keyed by a real KEM-derived shared secret
# --------------------------------------------------------------------------

def encrypt_data(data: str, shared_secret_b64: str) -> dict:
    """AES-256-GCM encrypt using a PQC KEM-derived shared secret as the key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = b64decode(shared_secret_b64)[:32]
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return {
        "ciphertext": b64encode(ciphertext).decode(),
        "nonce": b64encode(nonce).decode(),
        "cipher": "AES-256-GCM",
    }


def decrypt_data(ciphertext_b64: str, nonce_b64: str, shared_secret_b64: str) -> dict:
    """AES-256-GCM decrypt using a PQC KEM-derived shared secret as the key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = b64decode(shared_secret_b64)[:32]
    nonce = b64decode(nonce_b64)
    ct = b64decode(ciphertext_b64)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
        return {"plaintext": plaintext.decode(), "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}


# --------------------------------------------------------------------------
# Hybrid schemes: real PQC + classical combination (Kyber+X25519, Dilithium+Ed25519)
# --------------------------------------------------------------------------

def _combine_secrets(*secrets_: bytes) -> bytes:
    """Bind multiple independently-derived shared secrets into one key.

    Concatenate-then-hash combiner: the combined key is only as strong as
    its strongest input is broken, so an attacker must break BOTH the PQC
    and classical half to recover it -- the point of a hybrid scheme.
    """
    return hashlib.sha256(b"".join(secrets_)).digest()


def generate_hybrid_keypair(scheme: str, user_id: Optional[int] = None) -> dict:
    if scheme not in HYBRID_SCHEMES:
        raise ValueError(f"Unknown hybrid scheme: {scheme}. Available: {list(HYBRID_SCHEMES.keys())}")
    info = HYBRID_SCHEMES[scheme]

    if "kem" in info:
        oqs = _require_oqs()
        pqc_algo = info["kem"]
        with oqs.KeyEncapsulation(_oqs_name(pqc_algo)) as kem:
            pqc_pub = kem.generate_keypair()
            pqc_priv = kem.export_secret_key()

        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization
        classical_priv_obj = x25519.X25519PrivateKey.generate()
        classical_priv = classical_priv_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        classical_pub = classical_priv_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    else:
        oqs = _require_oqs()
        pqc_algo = info["sig"]
        with oqs.Signature(_oqs_name(pqc_algo)) as sig:
            pqc_pub = sig.generate_keypair()
            pqc_priv = sig.export_secret_key()

        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        classical_priv_obj = ed25519.Ed25519PrivateKey.generate()
        classical_priv = classical_priv_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        classical_pub = classical_priv_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    key_id = f"hybrid-{scheme}-{secrets.token_hex(6)}"
    pqc_info = PQC_ALGORITHMS[pqc_algo]
    result = {
        "key_id": key_id,
        "scheme": scheme,
        "scheme_name": info["name"],
        "pqc_algorithm": pqc_algo,
        "classical_algorithm": info["classical"],
        "pqc_public_key": b64encode(pqc_pub).decode(),
        "pqc_private_key": b64encode(pqc_priv).decode(),
        "classical_public_key": b64encode(classical_pub).decode(),
        "classical_private_key": b64encode(classical_priv).decode(),
        "created_at": datetime.utcnow().isoformat(),
        "mode": "liboqs+cryptography",
        "user_id": user_id,
        # Fields shared with generate_keypair()'s output shape so a hybrid
        # key renders correctly in the same Key Store list as a plain PQC
        # key (web/templates/quantum.html's #tab-keys loop) instead of
        # hitting missing-attribute template errors.
        "algorithm_name": f"{info['name']} (hybrid)",
        "standard": f"{pqc_info['standard']} + classical",
        "security_level": pqc_info["security_level"],
        "public_key": b64encode(pqc_pub).decode(),
    }
    _save_key(key_id, result, extra_private_fields=("pqc_private_key", "classical_private_key"))
    return result


def hybrid_encapsulate(pqc_public_key_b64: str, classical_public_key_b64: str,
                        scheme: str = "kyber768_x25519") -> dict:
    """Hybrid KEM encapsulation: real ML-KEM + real X25519 ECDH, combined."""
    info = HYBRID_SCHEMES[scheme]
    oqs = _require_oqs()

    pqc_pub = b64decode(pqc_public_key_b64)
    with oqs.KeyEncapsulation(_oqs_name(info["kem"])) as kem:
        pqc_ct, pqc_ss = kem.encap_secret(pqc_pub)

    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    peer_classical_pub = x25519.X25519PublicKey.from_public_bytes(b64decode(classical_public_key_b64))
    classical_ss = ephemeral.exchange(peer_classical_pub)

    shared_secret = _combine_secrets(pqc_ss, classical_ss)
    return {
        "pqc_ciphertext": b64encode(pqc_ct).decode(),
        "ephemeral_classical_public_key": b64encode(ephemeral_pub).decode(),
        "shared_secret": b64encode(shared_secret).decode(),
        "scheme": scheme,
        "hybrid": True,
        "mode": "liboqs+cryptography",
    }


def hybrid_decapsulate(pqc_private_key_b64: str, classical_private_key_b64: str,
                        pqc_ciphertext_b64: str, ephemeral_classical_public_key_b64: str,
                        scheme: str = "kyber768_x25519") -> dict:
    """Hybrid KEM decapsulation: recover the same combined secret the sender derived."""
    info = HYBRID_SCHEMES[scheme]
    oqs = _require_oqs()

    pqc_priv = b64decode(pqc_private_key_b64)
    pqc_ct = b64decode(pqc_ciphertext_b64)
    with oqs.KeyEncapsulation(_oqs_name(info["kem"]), secret_key=pqc_priv) as kem:
        pqc_ss = kem.decap_secret(pqc_ct)

    from cryptography.hazmat.primitives.asymmetric import x25519
    own_classical = x25519.X25519PrivateKey.from_private_bytes(b64decode(classical_private_key_b64))
    peer_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(
        b64decode(ephemeral_classical_public_key_b64)
    )
    classical_ss = own_classical.exchange(peer_ephemeral_pub)

    shared_secret = _combine_secrets(pqc_ss, classical_ss)
    return {
        "shared_secret": b64encode(shared_secret).decode(),
        "scheme": scheme,
        "hybrid": True,
        "mode": "liboqs+cryptography",
    }


def hybrid_sign(pqc_private_key_b64: str, classical_private_key_b64: str, message: str,
                 scheme: str = "dilithium3_ed25519") -> dict:
    """Hybrid signature: real ML-DSA-65 signature + real Ed25519 signature."""
    info = HYBRID_SCHEMES[scheme]
    oqs = _require_oqs()

    pqc_priv = b64decode(pqc_private_key_b64)
    with oqs.Signature(_oqs_name(info["sig"]), secret_key=pqc_priv) as signer:
        pqc_sig = signer.sign(message.encode())

    from cryptography.hazmat.primitives.asymmetric import ed25519
    classical_key = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(classical_private_key_b64))
    classical_sig = classical_key.sign(message.encode())

    return {
        "pqc_signature": b64encode(pqc_sig).decode(),
        "classical_signature": b64encode(classical_sig).decode(),
        "scheme": scheme,
        "hybrid": True,
        "mode": "liboqs+cryptography",
    }


def hybrid_verify(pqc_public_key_b64: str, classical_public_key_b64: str, message: str,
                   pqc_signature_b64: str, classical_signature_b64: str,
                   scheme: str = "dilithium3_ed25519") -> dict:
    """Hybrid verification: BOTH the PQC and classical signature must be valid."""
    info = HYBRID_SCHEMES[scheme]
    oqs = _require_oqs()

    pqc_pub = b64decode(pqc_public_key_b64)
    pqc_sig = b64decode(pqc_signature_b64)
    with oqs.Signature(_oqs_name(info["sig"])) as verifier:
        try:
            pqc_valid = verifier.verify(message.encode(), pqc_sig, pqc_pub)
        except Exception:
            pqc_valid = False

    from cryptography.hazmat.primitives.asymmetric import ed25519
    classical_pub = ed25519.Ed25519PublicKey.from_public_bytes(b64decode(classical_public_key_b64))
    try:
        classical_pub.verify(b64decode(classical_signature_b64), message.encode())
        classical_valid = True
    except Exception:
        classical_valid = False

    return {
        "valid": bool(pqc_valid and classical_valid),
        "pqc_valid": bool(pqc_valid),
        "classical_valid": bool(classical_valid),
        "scheme": scheme,
    }


# --------------------------------------------------------------------------
# Server-side round-trip demos — prove KEM/sign/encrypt/hybrid actually work
# without ever putting a private key on the wire (generate_keypair's HTTP
# response never includes private_key; see web/routers/quantum.py).
# --------------------------------------------------------------------------

def demo_kem_roundtrip(algorithm: str = "kyber768") -> dict:
    kp = generate_keypair(algorithm)
    enc = encapsulate(kp["public_key"], algorithm)
    dec = decapsulate(kp["private_key"], enc["ciphertext"], algorithm)
    match = enc["shared_secret"] == dec["shared_secret"]
    return {
        "algorithm": algorithm,
        "public_key": kp["public_key"],
        "ciphertext": enc["ciphertext"],
        "match": match,
        "mode": "liboqs",
    }


def demo_sign_roundtrip(algorithm: str = "dilithium3", message: str = "OPTISEC quantum-safe test") -> dict:
    kp = generate_keypair(algorithm)
    s = sign(kp["private_key"], message, algorithm)
    correct = verify(kp["public_key"], message, s["signature"], algorithm)
    tampered = verify(kp["public_key"], message + " tampered", s["signature"], algorithm)
    return {
        "algorithm": algorithm,
        "public_key": kp["public_key"],
        "signature": s["signature"],
        "verified_correct_message": correct["valid"],
        "verified_tampered_message": tampered["valid"],
        "success": correct["valid"] and not tampered["valid"],
        "mode": "liboqs",
    }


def demo_encrypt_roundtrip(algorithm: str = "kyber768", message: str = "OPTISEC quantum-safe secret") -> dict:
    kp = generate_keypair(algorithm)
    enc_kem = encapsulate(kp["public_key"], algorithm)
    dec_kem = decapsulate(kp["private_key"], enc_kem["ciphertext"], algorithm)

    enc_data = encrypt_data(message, dec_kem["shared_secret"])
    dec_data = decrypt_data(enc_data["ciphertext"], enc_data["nonce"], enc_kem["shared_secret"])

    wrong_secret = b64encode(secrets.token_bytes(32)).decode()
    wrong_attempt = decrypt_data(enc_data["ciphertext"], enc_data["nonce"], wrong_secret)

    return {
        "algorithm": algorithm,
        "ciphertext": enc_data["ciphertext"],
        "recovered_plaintext": dec_data.get("plaintext"),
        "round_trip_success": dec_data.get("success") and dec_data.get("plaintext") == message,
        "wrong_key_rejected": not wrong_attempt.get("success", False),
        "mode": "liboqs",
    }


def demo_hybrid_roundtrip(scheme: str = "kyber768_x25519",
                           message: str = "OPTISEC hybrid quantum-safe test") -> dict:
    if scheme not in HYBRID_SCHEMES:
        raise ValueError(f"Unknown hybrid scheme: {scheme}")
    kp = generate_hybrid_keypair(scheme)

    if "kem" in HYBRID_SCHEMES[scheme]:
        enc = hybrid_encapsulate(kp["pqc_public_key"], kp["classical_public_key"], scheme)
        dec = hybrid_decapsulate(
            kp["pqc_private_key"], kp["classical_private_key"],
            enc["pqc_ciphertext"], enc["ephemeral_classical_public_key"], scheme,
        )
        match = enc["shared_secret"] == dec["shared_secret"]
        return {
            "scheme": scheme,
            "pqc_ciphertext": enc["pqc_ciphertext"],
            "match": match,
            "hybrid": True,
            "mode": "liboqs+cryptography",
        }

    s = hybrid_sign(kp["pqc_private_key"], kp["classical_private_key"], message, scheme)
    v = hybrid_verify(
        kp["pqc_public_key"], kp["classical_public_key"], message,
        s["pqc_signature"], s["classical_signature"], scheme,
    )
    tampered = hybrid_verify(
        kp["pqc_public_key"], kp["classical_public_key"], message + " tampered",
        s["pqc_signature"], s["classical_signature"], scheme,
    )
    return {
        "scheme": scheme,
        "pqc_valid": v["pqc_valid"],
        "classical_valid": v["classical_valid"],
        "valid": v["valid"],
        "tampered_rejected": not tampered["valid"],
        "hybrid": True,
        "mode": "liboqs+cryptography",
    }


# --------------------------------------------------------------------------
# Crypto Assessment — computed from the algorithm's actual family/key-length,
# not a fixed lookup table. Uses published quantum-attack-cost formulas
# (Shor's algorithm qubit estimates, Grover's quadratic speedup) so inputs
# outside any hardcoded list still get a genuine, distinct answer.
# --------------------------------------------------------------------------

_FAMILY_PATTERNS = [
    ("des", re.compile(r"\b3?des\b", re.I)),
    ("rsa", re.compile(r"\brsa\b", re.I)),
    ("eddsa", re.compile(r"\b(ed25519|ed448|eddsa)\b", re.I)),
    ("ecc", re.compile(r"\b(ecdsa|ecdh|ecc|nistp|secp|p-?256|p-?384|p-?521)\b", re.I)),
    ("chacha20", re.compile(r"\bchacha20\b", re.I)),
    ("aes", re.compile(r"\baes\b", re.I)),
    ("sha3", re.compile(r"\bsha-?3\b", re.I)),
    ("sha2", re.compile(r"\bsha-?(1|2|224|256|384|512)\b", re.I)),
]

# NIST PQC security categories -> approximate AES-equivalent classical
# security bits (Category 1 ~ AES-128, 3 ~ AES-192, 5 ~ AES-256).
_PQC_LEVEL_TO_BITS = {1: 128, 2: 128, 3: 192, 4: 192, 5: 256}

_DEFAULT_BITS = {"rsa": 2048, "ecc": 256, "eddsa": 256, "aes": 256,
                  "chacha20": 256, "sha2": 256, "sha3": 256, "des": 112}


def _detect_family_and_bits(algorithm_in_use: str) -> tuple:
    family = None
    for fam, pattern in _FAMILY_PATTERNS:
        if pattern.search(algorithm_in_use):
            family = fam
            break
    if family is None:
        return None, None

    match = re.search(r"(\d{2,4})", algorithm_in_use)
    if match:
        bits = int(match.group(1))
    elif family == "eddsa" and "448" in algorithm_in_use:
        bits = 448
    else:
        bits = _DEFAULT_BITS[family]
    return family, bits


def assess_crypto_strength(algorithm_in_use: str) -> dict:
    """Rate an algorithm against quantum threats, computed from its actual
    family and key/digest length rather than a fixed per-string lookup."""
    normalized = algorithm_in_use.lower().strip()

    # Already a PQC algorithm we know about -> genuinely quantum-resistant,
    # security bits derived from its NIST category (PQC_ALGORITHMS metadata).
    pqc_key = normalized.replace(" ", "").replace("-", "")
    for key, info in PQC_ALGORITHMS.items():
        if key == normalized or key.replace("_", "") == pqc_key or info["name"].lower() == normalized:
            bits = _PQC_LEVEL_TO_BITS.get(info["security_level"], 128)
            return {
                "algorithm": algorithm_in_use,
                "quantum_broken": False,
                "risk": "low",
                "recommendation": "Already quantum-resistant",
                "standard": info["standard"],
                "estimated_classical_security_bits": bits,
            }

    family, bits = _detect_family_and_bits(normalized)

    if family is None:
        return {"algorithm": algorithm_in_use, "quantum_broken": "unknown", "risk": "unknown",
                "recommendation": "Analyze this algorithm manually"}

    if family == "des":
        return {
            "algorithm": algorithm_in_use,
            "quantum_broken": True,
            "risk": "critical",
            "recommendation": "Migrate to ML-KEM-768 or ML-DSA-65 (also classically weak at this key size)",
            "key_bits": bits,
        }

    if family == "rsa":
        # Beauregard (2003): ~2n+3 logical qubits to factor an n-bit modulus via Shor's algorithm.
        logical_qubits = 2 * bits + 3
        return {
            "algorithm": algorithm_in_use,
            "quantum_broken": True,
            "risk": "critical",
            "recommendation": "Migrate to ML-KEM-768 or ML-DSA-65",
            "key_bits": bits,
            "shor_estimated_logical_qubits": logical_qubits,
            "grover_attack_time": "N/A (Shor's algorithm applies, not Grover's)",
            "shor_attack_time": "instant on a sufficiently large fault-tolerant quantum computer",
        }

    if family in ("ecc", "eddsa"):
        # Roetteler et al. (2017): ~6n logical qubits for Shor's algorithm over an n-bit elliptic curve.
        logical_qubits = 6 * bits
        return {
            "algorithm": algorithm_in_use,
            "quantum_broken": True,
            "risk": "critical",
            "recommendation": "Migrate to ML-KEM-768 or ML-DSA-65",
            "key_bits": bits,
            "shor_estimated_logical_qubits": logical_qubits,
            "grover_attack_time": "N/A (Shor's algorithm applies, not Grover's)",
            "shor_attack_time": "instant on a sufficiently large fault-tolerant quantum computer",
        }

    # Symmetric ciphers and hashes: Grover's algorithm gives a quadratic
    # speedup, halving the effective brute-force security margin.
    effective_bits = bits // 2
    risk = "low" if effective_bits >= 128 else "medium"
    recommendation = (
        "Acceptable for post-quantum era"
        if effective_bits >= 128
        else f"Consider a larger key (effective quantum security only ~{effective_bits}-bit)"
    )
    return {
        "algorithm": algorithm_in_use,
        "quantum_broken": False,
        "risk": risk,
        "recommendation": recommendation,
        "key_bits": bits,
        "grover_effective_security_bits": effective_bits,
        "grover_attack_time": f"~2^{effective_bits} quantum operations",
        "shor_attack_time": "N/A (Grover's algorithm applies, not Shor's)",
    }


# --------------------------------------------------------------------------
# Key store (metadata only — private key material is never persisted)
# --------------------------------------------------------------------------

def _save_key(key_id: str, data: dict, extra_private_fields: tuple = ()) -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_file = KEYS_DIR / f"{key_id}.json"
    omit = {"private_key", *extra_private_fields}
    safe = {k: v for k, v in data.items() if k not in omit}
    key_file.write_text(json.dumps(safe, indent=2))


def list_keys(user_id: Optional[int] = None, is_admin: bool = False) -> list:
    """Keys owned by `user_id` (admin sees every account's -- same
    admin-sees-all convention as modules/ai_advanced/{zero_day,red_team}.py
    and modules/darkweb/intelligence.py). private_key is never persisted
    (_save_key strips it), so this is metadata-only either way; still,
    which algorithm/how many keys another tenant generated and when is
    account activity that shouldn't be visible cross-tenant. Passing
    user_id=None and is_admin=False (the defaults) returns everything, for
    any other internal caller; web/routers/quantum.py always passes
    explicit values."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    keys = []
    for f in KEYS_DIR.glob("*.json"):
        try:
            keys.append(json.loads(f.read_text()))
        except Exception:
            pass
    if not (is_admin or user_id is None):
        keys = [k for k in keys if k.get("user_id") == user_id]
    return sorted(keys, key=lambda x: x.get("created_at", ""), reverse=True)


def get_algorithms() -> dict:
    return PQC_ALGORITHMS


def get_hybrid_schemes() -> dict:
    return HYBRID_SCHEMES
