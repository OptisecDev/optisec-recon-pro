"""
Tests for the fix removing the hardcoded JWT secret fallback
("optisec-enterprise-key-change-in-production") from config.py and
web/auth.py.

config._resolve_jwt_secret() is now the single source of truth (web/auth.py
imports JWT_SECRET from config rather than duplicating its own
os.environ.get(..., <hardcoded default>) call): a real JWT_SECRET always
wins; otherwise production (GROQ_ENV=production or RENDER set) must raise
at startup, an explicit GROQ_ENV=development/dev/test/testing may opt into
a clearly-labeled insecure default, and any other unconfigured state also
raises rather than silently guessing.

Calls config._resolve_jwt_secret() directly (rather than reimporting the
config module, whose module-level JWT_SECRET is only computed once and
cached by Python's import system) so each scenario is independent.
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


def test_real_secret_is_used_regardless_of_env_mode(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("JWT_SECRET", "a-real-random-secret")
    monkeypatch.setenv("GROQ_ENV", "production")
    assert config._resolve_jwt_secret() == "a-real-random-secret"


def test_missing_secret_in_production_raises(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GROQ_ENV", "production")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        config._resolve_jwt_secret()


def test_missing_secret_on_render_raises(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("RENDER", "true")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        config._resolve_jwt_secret()


@pytest.mark.parametrize("flag", ["development", "dev", "test", "testing"])
def test_missing_secret_with_explicit_dev_flag_returns_labeled_insecure_default(monkeypatch, flag):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GROQ_ENV", flag)
    secret = config._resolve_jwt_secret()
    assert secret == config._INSECURE_DEV_JWT_SECRET
    assert "INSECURE" in secret


def test_missing_secret_with_no_env_flags_at_all_still_raises(monkeypatch):
    # Fail closed: an unconfigured environment is not implicitly "dev mode".
    _clear_env(monkeypatch)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        config._resolve_jwt_secret()


def test_missing_secret_with_unrecognized_env_value_still_raises(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GROQ_ENV", "staging")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        config._resolve_jwt_secret()


def test_web_auth_secret_key_matches_config_jwt_secret():
    from web import auth
    assert auth.SECRET_KEY == config.JWT_SECRET
