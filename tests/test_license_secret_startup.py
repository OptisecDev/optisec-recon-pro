"""
Tests for hardening OPTISEC_LICENSE_SECRET (Phase 2 of the license-secret
fix): config._resolve_license_secret() mirrors config._resolve_jwt_secret()
exactly -- a real OPTISEC_LICENSE_SECRET always wins; otherwise production
(GROQ_ENV=production or RENDER set) must raise at startup, an explicit
GROQ_ENV=development/dev/test/testing may opt into a clearly-labeled
insecure default, and any other unconfigured state also raises rather than
silently guessing.

web/license.py no longer reads OPTISEC_LICENSE_SECRET from os.environ with a
silent hardcoded fallback -- it imports LICENSE_SECRET from config.
Signatures are produced with LICENSE_SECRET only; verification accepts the
old public default secret ("optisec-license-engine-v4-singularity-2026")
only as a deprecated, explicitly-logged legacy path for keys issued before
this fix.

Calls config._resolve_license_secret() directly (rather than reimporting
the config module, whose module-level LICENSE_SECRET is only computed once
and cached by Python's import system) so each scenario is independent.
"""

import hashlib
import hmac
import json
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import config


def _clear_env(monkeypatch):
    monkeypatch.delenv("OPTISEC_LICENSE_SECRET", raising=False)
    monkeypatch.delenv("GROQ_ENV", raising=False)
    monkeypatch.delenv("RENDER", raising=False)


def test_real_secret_is_used_regardless_of_env_mode(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("OPTISEC_LICENSE_SECRET", "a-real-random-license-secret")
    monkeypatch.setenv("GROQ_ENV", "production")
    assert config._resolve_license_secret() == "a-real-random-license-secret"


def test_missing_secret_in_production_raises(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GROQ_ENV", "production")
    with pytest.raises(RuntimeError, match="OPTISEC_LICENSE_SECRET"):
        config._resolve_license_secret()


def test_missing_secret_on_render_raises(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("RENDER", "true")
    with pytest.raises(RuntimeError, match="OPTISEC_LICENSE_SECRET"):
        config._resolve_license_secret()


@pytest.mark.parametrize("flag", ["development", "dev", "test", "testing"])
def test_missing_secret_with_explicit_dev_flag_returns_labeled_insecure_default(monkeypatch, flag):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GROQ_ENV", flag)
    secret = config._resolve_license_secret()
    assert secret == config._INSECURE_DEV_LICENSE_SECRET
    assert "INSECURE" in secret


def test_missing_secret_with_no_env_flags_at_all_still_raises(monkeypatch):
    # Fail closed: an unconfigured environment is not implicitly "dev mode".
    _clear_env(monkeypatch)
    with pytest.raises(RuntimeError, match="OPTISEC_LICENSE_SECRET"):
        config._resolve_license_secret()


def test_missing_secret_with_unrecognized_env_value_still_raises(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GROQ_ENV", "staging")
    with pytest.raises(RuntimeError, match="OPTISEC_LICENSE_SECRET"):
        config._resolve_license_secret()


def test_web_license_secret_matches_config_license_secret():
    from web import license as license_mod
    assert license_mod.LICENSE_SECRET == config.LICENSE_SECRET


def test_generate_then_verify_with_current_secret_succeeds():
    from web.license import generate_license_key, verify_license_key

    key = generate_license_key("pro", "Test Co", "test@example.com", days=30)
    valid, err, lic = verify_license_key(key)
    assert valid is True
    assert err == ""
    assert lic is not None
    assert lic.tier == "pro"


def _sign_with_legacy_secret(payload: dict) -> str:
    from web.license import _LEGACY_LICENSE_SECRET

    data_bytes = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(_LEGACY_LICENSE_SECRET.encode(), data_bytes, hashlib.sha256).hexdigest()
    encoded = base64.urlsafe_b64encode(data_bytes).decode().rstrip("=")
    return f"OPS4-{payload['tier'].upper()}-{encoded}.{sig[:16]}"


def test_key_signed_with_legacy_secret_is_accepted_and_logs_warning(caplog):
    import logging
    from datetime import datetime, timedelta
    from web.license import verify_license_key, TIER_FEATURES, TIER_LIMITS

    now = datetime.utcnow()
    limits = TIER_LIMITS["pro"]
    payload = {
        "tier": "pro",
        "issued_to": "Legacy Co",
        "email": "legacy@example.com",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "features": TIER_FEATURES["pro"],
        "max_targets": limits["max_targets"],
        "max_scans_day": limits["max_scans_day"],
        "max_users": limits["max_users"],
        "version": "4.0",
    }
    legacy_key = _sign_with_legacy_secret(payload)

    with caplog.at_level(logging.WARNING, logger="optisec"):
        valid, err, lic = verify_license_key(legacy_key)

    assert valid is True
    assert err == ""
    assert lic is not None
    assert any(
        "legacy default secret" in record.message for record in caplog.records
    )


def test_key_with_bad_signature_under_both_secrets_is_rejected():
    from web.license import verify_license_key

    forged = "OPS4-ENTERPRISE-" + base64.urlsafe_b64encode(
        json.dumps({"tier": "enterprise"}).encode()
    ).decode().rstrip("=") + ".0000000000000000"
    valid, err, lic = verify_license_key(forged)
    assert valid is False
    assert lic is None
