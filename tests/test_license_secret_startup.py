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
Signatures are produced with, and verified against, LICENSE_SECRET only.

Phase 3 (final closure, this file's current state): the deprecated
fallback that additionally accepted a key signed with the old hardcoded
public default secret ("optisec-license-engine-v4-singularity-2026") has
been deleted outright -- that secret sat in the public repo, so any key
forged with it must now be rejected unconditionally, with no legacy
acceptance path and no verified_via_legacy_secret flag left anywhere in
web/license.py. See test_key_signed_with_the_old_public_default_secret_is_now_rejected
below for the regression guard.

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


# The old hardcoded public default secret web/license.py used to accept as a
# deprecated fallback -- deliberately still hardcoded here (not imported;
# the constant no longer exists in web/license.py) so this test proves a key
# forged with that exact, previously-public value is rejected now that the
# fallback branch is gone.
_OLD_PUBLIC_DEFAULT_SECRET = "optisec-license-engine-v4-singularity-2026"


def _sample_license_payload(tier: str = "pro") -> dict:
    from datetime import datetime, timedelta
    from web.license import TIER_FEATURES, TIER_LIMITS

    now = datetime.utcnow()
    limits = TIER_LIMITS[tier]
    return {
        "tier": tier,
        "issued_to": "Test Co",
        "email": "test@example.com",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "features": TIER_FEATURES[tier],
        "max_targets": limits["max_targets"],
        "max_scans_day": limits["max_scans_day"],
        "max_users": limits["max_users"],
        "version": "4.0",
    }


def _sign_with(secret: str, payload: dict) -> str:
    data_bytes = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(secret.encode(), data_bytes, hashlib.sha256).hexdigest()
    encoded = base64.urlsafe_b64encode(data_bytes).decode().rstrip("=")
    return f"OPS4-{payload['tier'].upper()}-{encoded}.{sig[:16]}"


def test_legacy_secret_constant_and_flag_are_gone_from_web_license():
    """Regression guard for the security closure itself: no trace of the
    deprecated legacy-secret path (constant, flag, or the word "legacy")
    may remain in web/license.py's source."""
    import inspect
    import web.license as license_mod

    assert not hasattr(license_mod, "_LEGACY_LICENSE_SECRET")
    source = inspect.getsource(license_mod)
    assert "legacy" not in source.lower()
    assert "verified_via_legacy_secret" not in source


def test_key_signed_with_the_old_public_default_secret_is_now_rejected():
    """The old default secret sat in the public repo -- a key forged with
    it must be rejected unconditionally, with no fallback acceptance path
    left at all."""
    from web.license import verify_license_key

    payload = _sample_license_payload()
    forged_key = _sign_with(_OLD_PUBLIC_DEFAULT_SECRET, payload)

    valid, err, lic = verify_license_key(forged_key)
    assert valid is False
    assert lic is None
    assert "invalid" in err.lower() or "forged" in err.lower()


def test_key_signed_with_the_current_secret_is_still_accepted():
    import config
    from web.license import verify_license_key

    payload = _sample_license_payload()
    real_key = _sign_with(config.LICENSE_SECRET, payload)

    valid, err, lic = verify_license_key(real_key)
    assert valid is True
    assert err == ""
    assert lic is not None
    assert lic.tier == "pro"


def test_key_with_bad_signature_under_both_secrets_is_rejected():
    from web.license import verify_license_key

    forged = "OPS4-ENTERPRISE-" + base64.urlsafe_b64encode(
        json.dumps({"tier": "enterprise"}).encode()
    ).decode().rstrip("=") + ".0000000000000000"
    valid, err, lic = verify_license_key(forged)
    assert valid is False
    assert lic is None
