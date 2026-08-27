"""Tests for the fail-fast fix on Eternal Core's field-level encryption.

Before this fix, EncryptedString (app/models/eternal/base.py) silently fell
back to storing/returning plaintext whenever FIELD_ENCRYPTION_KEY was unset:
`self._fernet = Fernet(...) if FIELD_ENCRYPTION_KEY else None`, and both
process_bind_param/process_result_value passed the value through unchanged
whenever self._fernet was None. There was no warning, log line, or error --
Target.input_value (PII) would be written to Postgres as plaintext with no
indication anything was wrong.

app.core.config._resolve_field_encryption_key() now raises RuntimeError at
import time (module-level, mirroring the existing JWT_SECRET fail-fast
pattern in config.py) if the key is missing or is not a valid Fernet key.
EncryptedString.__init__ no longer has a None-fernet branch at all.

Calls config._resolve_field_encryption_key() directly (rather than
reimporting app.core.config, whose module-level FIELD_ENCRYPTION_KEY is only
computed once and cached by Python's import system) so each scenario is
independent -- same approach as tests/test_jwt_secret_startup.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography.fernet import Fernet

from app.core import config
from app.models.eternal.base import EncryptedString


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("FIELD_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="FIELD_ENCRYPTION_KEY"):
        config._resolve_field_encryption_key()


@pytest.mark.parametrize("bad_key", ["not-a-valid-fernet-key", "short", "12345"])
def test_malformed_key_raises(monkeypatch, bad_key):
    monkeypatch.setenv("FIELD_ENCRYPTION_KEY", bad_key)
    with pytest.raises(RuntimeError, match="FIELD_ENCRYPTION_KEY"):
        config._resolve_field_encryption_key()


def test_valid_key_is_returned_unchanged(monkeypatch):
    real_key = Fernet.generate_key().decode()
    monkeypatch.setenv("FIELD_ENCRYPTION_KEY", real_key)
    assert config._resolve_field_encryption_key() == real_key


def test_encrypted_string_construction_fails_with_empty_key(monkeypatch):
    # Guards against the old silent-fallback branch ever coming back: an
    # empty/falsy key must blow up loudly, not produce a passthrough cipher.
    monkeypatch.setattr("app.models.eternal.base.FIELD_ENCRYPTION_KEY", "")
    with pytest.raises(Exception):
        EncryptedString(512)


def test_encrypted_string_round_trips_with_valid_key(monkeypatch):
    real_key = Fernet.generate_key().decode()
    monkeypatch.setattr("app.models.eternal.base.FIELD_ENCRYPTION_KEY", real_key)

    column_type = EncryptedString(512)
    plaintext = "target@example.com"
    ciphertext = column_type.process_bind_param(plaintext, None)

    assert ciphertext != plaintext
    assert column_type.process_result_value(ciphertext, None) == plaintext


def test_encrypted_string_different_keys_cannot_decrypt_each_other(monkeypatch):
    key_a = Fernet.generate_key().decode()
    key_b = Fernet.generate_key().decode()

    monkeypatch.setattr("app.models.eternal.base.FIELD_ENCRYPTION_KEY", key_a)
    column_a = EncryptedString(512)
    ciphertext = column_a.process_bind_param("secret-value", None)

    monkeypatch.setattr("app.models.eternal.base.FIELD_ENCRYPTION_KEY", key_b)
    column_b = EncryptedString(512)
    with pytest.raises(Exception):
        column_b.process_result_value(ciphertext, None)


def test_encrypted_string_none_passthrough(monkeypatch):
    real_key = Fernet.generate_key().decode()
    monkeypatch.setattr("app.models.eternal.base.FIELD_ENCRYPTION_KEY", real_key)

    column_type = EncryptedString(512)
    assert column_type.process_bind_param(None, None) is None
    assert column_type.process_result_value(None, None) is None
