"""Tests for modules/vpn/wireguard.py's _wg_genkey() fallback when the `wg`
CLI is not installed: it must produce a mathematically valid Curve25519
keypair (public key = X25519 base-point multiplication of the private key),
not two independent random byte strings.
"""
import base64
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import modules.vpn.wireguard as wireguard


def _raise_file_not_found(*args, **kwargs):
    raise FileNotFoundError("wg: command not found")


def test_genkey_fallback_produces_valid_curve25519_keypair(monkeypatch):
    monkeypatch.setattr(subprocess, "check_output", _raise_file_not_found)

    priv_b64, pub_b64 = wireguard._wg_genkey()

    priv_bytes = base64.b64decode(priv_b64)
    pub_bytes = base64.b64decode(pub_b64)
    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32

    # The public key must be the point mathematically derived from the
    # private key, not an independently-random value.
    derived_pub_bytes = X25519PrivateKey.from_private_bytes(priv_bytes).public_key().public_bytes_raw()
    assert pub_bytes == derived_pub_bytes


def test_genkey_fallback_keys_are_not_independently_random(monkeypatch):
    monkeypatch.setattr(subprocess, "check_output", _raise_file_not_found)

    priv1, pub1 = wireguard._wg_genkey()
    priv2, pub2 = wireguard._wg_genkey()

    assert priv1 != priv2
    assert pub1 != pub2


def test_genkey_uses_real_wg_cli_when_available(monkeypatch):
    calls = []

    def fake_check_output(cmd, **kwargs):
        calls.append(cmd)
        if cmd == ["wg", "genkey"]:
            return "fake_priv_key\n"
        if cmd == ["wg", "pubkey"]:
            return "fake_pub_key\n"
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    priv, pub = wireguard._wg_genkey()

    assert priv == "fake_priv_key"
    assert pub == "fake_pub_key"
    assert calls == [["wg", "genkey"], ["wg", "pubkey"]]
