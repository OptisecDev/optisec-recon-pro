"""OPTISEC Recon Pro - License Key Utilities"""
import hashlib
import hmac
import secrets
import string

ALPHABET = string.ascii_uppercase + string.digits
GROUP_LEN = 4
GROUPS = 4


def generate_license_key() -> str:
    groups = ["".join(secrets.choice(ALPHABET) for _ in range(GROUP_LEN)) for _ in range(GROUPS)]
    return f"OPTISEC-RECON-{'-'.join(groups)}"


def hash_license_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def verify_key_hash(raw_key: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_license_key(raw_key), stored_hash)
