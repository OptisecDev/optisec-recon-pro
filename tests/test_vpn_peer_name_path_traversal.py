"""
Tests for peer-name validation in modules/vpn/wireguard.py and
web/routers/vpn.py::peer_config.

add_peer()/remove_peer()/generate_qr_code() interpolate `name` straight
into a filesystem path (WG_CONFIG_DIR / f"{name}.conf") with no
sanitization, as does the peer_config route handler (built inline, not
via a module function). All four endpoints are admin-only, but an
unvalidated name like "../../../etc/cron.d/evil" still lets an
already-admin caller write/delete an arbitrary path (via add_peer/
remove_peer) or read any file whose name happens to end in ".conf" (via
peer_config/generate_qr_code) outside data/wireguard/ -- cheap hardening
regardless of the admin trust boundary.

Mirrors tests/test_vpn_peer_secret_leak.py's convention: call route
handler functions directly, monkeypatch.chdir(tmp_path) for filesystem
isolation.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from web.models import User
import web.routers.vpn as vpn_router
import modules.vpn.wireguard as wireguard


def _run(coro):
    return asyncio.run(coro)


def _fake_user(role: str = "admin", tier: str = "pro") -> User:
    return User(id=1, username="tester", email="tester@example.com",
                password_hash="x", role=role, subscription_tier=tier)


_TRAVERSAL_NAMES = [
    "../../../etc/cron.d/evil",
    "../../outside",
    "a/../../b",
    "..",
    "sub/dir",
]


class TestIsSafePeerName:
    @pytest.mark.parametrize("name", _TRAVERSAL_NAMES)
    def test_traversal_names_are_rejected(self, name):
        assert wireguard.is_safe_peer_name(name) is False

    def test_empty_name_is_rejected(self):
        assert wireguard.is_safe_peer_name("") is False

    @pytest.mark.parametrize("name", ["laptop", "phone-2", "office_pc", "a" * 64])
    def test_ordinary_names_are_accepted(self, name):
        assert wireguard.is_safe_peer_name(name) is True

    def test_over_length_name_is_rejected(self):
        assert wireguard.is_safe_peer_name("a" * 65) is False


class TestAddPeerRejectsTraversal:
    @pytest.mark.parametrize("name", _TRAVERSAL_NAMES)
    def test_traversal_name_is_rejected_before_any_file_write(self, name, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(wireguard, "_load_peers", lambda: [])
        monkeypatch.setattr(wireguard, "_save_peers", lambda peers: pytest.fail("must not persist"))

        result = wireguard.add_peer(name=name)

        assert "error" in result
        # Nothing written anywhere outside (or inside) the tmp cwd.
        assert not any(tmp_path.rglob("*.conf"))


class TestRemovePeerRejectsTraversal:
    @pytest.mark.parametrize("name", _TRAVERSAL_NAMES)
    def test_traversal_name_is_rejected(self, name, monkeypatch):
        monkeypatch.setattr(wireguard, "_load_peers", lambda: [{"name": "laptop", "ip": "10.13.37.2"}])
        monkeypatch.setattr(wireguard, "_save_peers", lambda peers: pytest.fail("must not persist"))

        result = wireguard.remove_peer(name)

        assert "error" in result


class TestGenerateQrCodeRejectsTraversal:
    @pytest.mark.parametrize("name", _TRAVERSAL_NAMES)
    def test_traversal_name_returns_none_without_touching_filesystem(self, name, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # A real target file placed just outside the intended directory --
        # if the guard is missing, "../outside.conf" would successfully
        # read this.
        (tmp_path / "outside.conf").write_text("[Interface]\nPrivateKey = LEAKED\n")

        assert wireguard.generate_qr_code(name) is None


class TestPeerConfigRouteRejectsTraversal:
    @pytest.mark.parametrize("name", _TRAVERSAL_NAMES)
    def test_traversal_name_returns_404_not_the_file_contents(self, name, tmp_path, monkeypatch):
        from fastapi import HTTPException
        monkeypatch.chdir(tmp_path)
        (tmp_path / "outside.conf").write_text("[Interface]\nPrivateKey = LEAKED_SECRET\n")

        with pytest.raises(HTTPException) as exc_info:
            _run(vpn_router.peer_config(name, user=_fake_user()))
        assert exc_info.value.status_code == 404

    def test_ordinary_name_still_works(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / "data" / "wireguard"
        config_dir.mkdir(parents=True)
        (config_dir / "laptop.conf").write_text("[Interface]\nPrivateKey = REAL\n")

        response = _run(vpn_router.peer_config("laptop", user=_fake_user()))

        assert "REAL" in response.body.decode()
