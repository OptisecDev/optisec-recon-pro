"""
Tests for the JWT_SECRET strength policy in config._resolve_jwt_secret():
a set secret shorter than 32 bytes (UTF-8) or containing a PEM header is
rejected at startup (mitigates PYSEC-2025-183, short HMAC keys), and the
error message never echoes the secret value.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import config


def _clear_env(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("GROQ_ENV", raising=False)
    monkeypatch.delenv("RENDER", raising=False)


def test_short_secret_is_rejected_without_leaking_value(monkeypatch):
    _clear_env(monkeypatch)
    short = "short-secret-xyz"
    monkeypatch.setenv("JWT_SECRET", short)
    with pytest.raises(RuntimeError, match="32 bytes") as exc:
        config._resolve_jwt_secret()
    assert short not in str(exc.value)


def test_31_byte_secret_is_rejected(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("JWT_SECRET", "a" * 31)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        config._resolve_jwt_secret()


def test_length_is_measured_in_utf8_bytes(monkeypatch):
    _clear_env(monkeypatch)
    # 16 characters but 32 UTF-8 bytes -> accepted.
    secret = "é" * 16
    monkeypatch.setenv("JWT_SECRET", secret)
    assert config._resolve_jwt_secret() == secret


def test_pem_secret_is_rejected_without_leaking_value(monkeypatch):
    _clear_env(monkeypatch)
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7pemtestbody\n"
        "-----END PRIVATE KEY-----"
    )
    monkeypatch.setenv("JWT_SECRET", pem)
    with pytest.raises(RuntimeError, match="PEM") as exc:
        config._resolve_jwt_secret()
    assert "MIIEvQ" not in str(exc.value)


@pytest.mark.parametrize("length", [32, 64])
def test_secret_of_32_bytes_or_more_is_accepted(monkeypatch, length):
    _clear_env(monkeypatch)
    secret = "k" * length
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.setenv("GROQ_ENV", "production")
    assert config._resolve_jwt_secret() == secret


def test_empty_secret_keeps_dev_default_behavior(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("JWT_SECRET", "")
    monkeypatch.setenv("GROQ_ENV", "development")
    assert config._resolve_jwt_secret() == config._INSECURE_DEV_JWT_SECRET
