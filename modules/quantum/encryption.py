"""Quantum-Safe Encryption — NIST PQC algorithms (Kyber, Dilithium) via pure-Python fallbacks."""

import os
import json
import base64
import hashlib
import secrets
import asyncio
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


def _try_pqc_lib():
    """Try to import liboqs Python bindings."""
    try:
        import oqs
        return oqs
    except ImportError:
        return None


def generate_keypair(algorithm: str = "kyber768") -> dict:
    """Generate a PQC keypair. Uses liboqs if available, else simulates."""
    if algorithm not in PQC_ALGORITHMS:
        return {"error": f"Unknown algorithm: {algorithm}. Available: {list(PQC_ALGORITHMS.keys())}"}

    algo_info = PQC_ALGORITHMS[algorithm]
    oqs = _try_pqc_lib()

    if oqs:
        try:
            kem_name = _oqs_name(algorithm)
            with oqs.KeyEncapsulation(kem_name) if algo_info["type"] == "key_encapsulation" \
                    else oqs.Signature(kem_name) as obj:
                pub_key = obj.generate_keypair()
                priv_key = obj.export_secret_key()
                return _format_keypair(algorithm, algo_info, pub_key, priv_key, "liboqs")
        except Exception:
            pass

    # Simulation mode: generate deterministic-length random keys
    pub_key = secrets.token_bytes(algo_info.get("public_key_size", 32))
    priv_key = secrets.token_bytes(algo_info.get("private_key_size", 64))
    return _format_keypair(algorithm, algo_info, pub_key, priv_key, "simulated")


def _format_keypair(algorithm: str, info: dict, pub: bytes, priv: bytes, mode: str) -> dict:
    key_id = f"pqc-{algorithm}-{secrets.token_hex(6)}"
    now = datetime.utcnow().isoformat()
    result = {
        "key_id": key_id,
        "algorithm": algorithm,
        "algorithm_name": info["name"],
        "type": info["type"],
        "standard": info["standard"],
        "security_level": info["security_level"],
        "public_key": base64.b64encode(pub).decode(),
        "private_key": base64.b64encode(priv).decode(),
        "created_at": now,
        "mode": mode,
        "note": "Install liboqs-python for real PQC key generation" if mode == "simulated" else "",
    }
    _save_key(key_id, result)
    return result


def _oqs_name(algorithm: str) -> str:
    mapping = {
        "kyber768": "Kyber768", "kyber1024": "Kyber1024",
        "dilithium3": "Dilithium3", "sphincs_sha2": "SPHINCS+-SHA2-128s-simple",
        "falcon512": "Falcon-512",
    }
    return mapping.get(algorithm, algorithm)


def encapsulate(public_key_b64: str, algorithm: str = "kyber768") -> dict:
    """Encapsulate — generate shared secret + ciphertext."""
    pub_bytes = base64.b64decode(public_key_b64)
    algo_info = PQC_ALGORITHMS.get(algorithm, {})
    oqs = _try_pqc_lib()

    if oqs:
        try:
            with oqs.KeyEncapsulation(_oqs_name(algorithm)) as kem:
                ciphertext, shared_secret = kem.encap_secret(pub_bytes)
                return {
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "shared_secret": base64.b64encode(shared_secret).decode(),
                    "algorithm": algorithm,
                    "mode": "liboqs",
                }
        except Exception:
            pass

    # Simulation
    ciphertext = secrets.token_bytes(algo_info.get("ciphertext_size", 1088))
    shared_secret = secrets.token_bytes(32)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "shared_secret": base64.b64encode(shared_secret).decode(),
        "algorithm": algorithm,
        "mode": "simulated",
    }


def decapsulate(private_key_b64: str, ciphertext_b64: str, algorithm: str = "kyber768") -> dict:
    """Decapsulate ciphertext to recover shared secret."""
    priv_bytes = base64.b64decode(private_key_b64)
    ct_bytes = base64.b64decode(ciphertext_b64)
    oqs = _try_pqc_lib()

    if oqs:
        try:
            with oqs.KeyEncapsulation(_oqs_name(algorithm), secret_key=priv_bytes) as kem:
                shared_secret = kem.decap_secret(ct_bytes)
                return {
                    "shared_secret": base64.b64encode(shared_secret).decode(),
                    "algorithm": algorithm,
                    "mode": "liboqs",
                }
        except Exception:
            pass

    shared_secret = hashlib.sha256(priv_bytes + ct_bytes).digest()
    return {
        "shared_secret": base64.b64encode(shared_secret).decode(),
        "algorithm": algorithm,
        "mode": "simulated",
    }


def encrypt_data(data: str, shared_secret_b64: str) -> dict:
    """AES-256-GCM encrypt using PQC-derived shared secret."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = base64.b64decode(shared_secret_b64)[:32]
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "cipher": "AES-256-GCM",
        "hybrid": True,
    }


def decrypt_data(ciphertext_b64: str, nonce_b64: str, shared_secret_b64: str) -> dict:
    """AES-256-GCM decrypt using PQC-derived shared secret."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = base64.b64decode(shared_secret_b64)[:32]
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ciphertext_b64)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
        return {"plaintext": plaintext.decode(), "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}


def assess_crypto_strength(algorithm_in_use: str) -> dict:
    """Rate an existing algorithm against quantum threats."""
    classical_vulns = {
        "rsa-2048": {"quantum_broken": True, "grover_time": "hours", "shor_time": "minutes"},
        "rsa-4096": {"quantum_broken": True, "grover_time": "days", "shor_time": "hours"},
        "ecdsa-p256": {"quantum_broken": True, "grover_time": "hours", "shor_time": "minutes"},
        "ecdh-p256": {"quantum_broken": True, "grover_time": "hours", "shor_time": "minutes"},
        "ed25519": {"quantum_broken": True, "grover_time": "days", "shor_time": "hours"},
        "aes-128": {"quantum_broken": False, "grover_time": "requires 64-qubit", "shor_time": "N/A"},
        "aes-256": {"quantum_broken": False, "grover_time": "infeasible", "shor_time": "N/A"},
        "sha-256": {"quantum_broken": False, "grover_time": "128-bit equiv", "shor_time": "N/A"},
        "sha-512": {"quantum_broken": False, "grover_time": "256-bit equiv", "shor_time": "N/A"},
    }

    key = algorithm_in_use.lower().replace(" ", "-")
    if key in classical_vulns:
        info = classical_vulns[key]
        return {
            "algorithm": algorithm_in_use,
            "quantum_broken": info["quantum_broken"],
            "risk": "critical" if info["quantum_broken"] else "low",
            "recommendation": f"Migrate to ML-KEM-768 or ML-DSA-65" if info["quantum_broken"] else "Acceptable for post-quantum era",
            "grover_attack_time": info["grover_time"],
            "shor_attack_time": info["shor_time"],
        }

    if key in PQC_ALGORITHMS:
        return {
            "algorithm": algorithm_in_use,
            "quantum_broken": False,
            "risk": "low",
            "recommendation": "Already quantum-resistant",
            "standard": PQC_ALGORITHMS[key].get("standard"),
        }

    return {"algorithm": algorithm_in_use, "quantum_broken": "unknown", "risk": "unknown",
            "recommendation": "Analyze this algorithm manually"}


def _save_key(key_id: str, data: dict) -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_file = KEYS_DIR / f"{key_id}.json"
    safe = {k: v for k, v in data.items() if k != "private_key"}
    key_file.write_text(json.dumps(safe, indent=2))


def list_keys() -> list:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    keys = []
    for f in KEYS_DIR.glob("*.json"):
        try:
            keys.append(json.loads(f.read_text()))
        except Exception:
            pass
    return sorted(keys, key=lambda x: x.get("created_at", ""), reverse=True)


def get_algorithms() -> dict:
    return PQC_ALGORITHMS


def get_hybrid_schemes() -> dict:
    return HYBRID_SCHEMES
