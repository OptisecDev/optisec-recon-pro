"""
Tests for full-length license signatures (web/license.py).

New keys carry the full 64-hex-char HMAC-SHA256 signature instead of only
its first 16 hex chars. Keys issued before that (16-char signature) are
still accepted by default so existing installs keep working;
OPTISEC_LICENSE_REQUIRE_FULL_SIG=1 turns that acceptance off.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from web.license import generate_license_key, verify_license_key

ENV = "OPTISEC_LICENSE_REQUIRE_FULL_SIG"


def _split(key: str) -> tuple[str, str]:
    body, sig = key.rsplit(".", 1)
    return body, sig


@pytest.fixture
def full_key():
    return generate_license_key("pro", "Test Co", "test@example.com", days=30)


@pytest.fixture
def short_key(full_key):
    body, sig = _split(full_key)
    return f"{body}.{sig[:16]}"


def test_new_key_has_full_64_char_signature(full_key):
    _, sig = _split(full_key)
    assert len(sig) == 64
    assert all(c in "0123456789abcdef" for c in sig)


def test_full_signature_key_verifies(monkeypatch, full_key):
    monkeypatch.delenv(ENV, raising=False)
    valid, err, lic = verify_license_key(full_key)
    assert valid is True, err
    assert lic.tier == "pro"


def test_full_signature_key_verifies_when_full_sig_required(monkeypatch, full_key):
    monkeypatch.setenv(ENV, "1")
    valid, err, _ = verify_license_key(full_key)
    assert valid is True, err


def test_short_signature_key_accepted_by_default(monkeypatch, short_key):
    monkeypatch.delenv(ENV, raising=False)
    valid, err, lic = verify_license_key(short_key)
    assert valid is True, err
    assert lic.tier == "pro"


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_short_signature_key_rejected_when_full_sig_required(monkeypatch, short_key, value):
    monkeypatch.setenv(ENV, value)
    valid, err, lic = verify_license_key(short_key)
    assert valid is False
    assert lic is None
    assert "signature" in err.lower()


def test_tampered_full_signature_rejected(monkeypatch, full_key):
    monkeypatch.delenv(ENV, raising=False)
    body, sig = _split(full_key)
    flipped = ("0" if sig[-1] != "0" else "1")
    valid, _, _ = verify_license_key(f"{body}.{sig[:-1]}{flipped}")
    assert valid is False


def test_tampered_short_signature_rejected(monkeypatch, short_key):
    monkeypatch.delenv(ENV, raising=False)
    body, sig = _split(short_key)
    flipped = ("0" if sig[-1] != "0" else "1")
    valid, _, _ = verify_license_key(f"{body}.{sig[:-1]}{flipped}")
    assert valid is False


@pytest.mark.parametrize("length", [8, 15, 17, 32, 63, 65])
def test_other_signature_lengths_rejected(monkeypatch, full_key, length):
    """Only 64 (full) or 16 (older keys) are valid lengths -- a truncated
    prefix of any other length must not verify."""
    monkeypatch.delenv(ENV, raising=False)
    body, sig = _split(full_key)
    sig = (sig * 2)[:length]
    valid, _, _ = verify_license_key(f"{body}.{sig}")
    assert valid is False
