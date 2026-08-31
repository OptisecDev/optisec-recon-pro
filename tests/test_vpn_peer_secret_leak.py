"""Tests for the VPN peer-secret leak found during the 2026-08-29
Firewall/VPN/AI Security audit: GET /vpn/api/peers was returning every
peer's private_key and psk in full, not just the dedicated per-peer
.conf/QR download endpoints that legitimately need them.

Mirrors tests/test_autonomous_rt_router.py's convention: call the route
handler functions directly (bypassing FastAPI's Depends resolution) with
an already-built user, no HTTP client needed.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.models import User
import web.routers.vpn as vpn_router
import modules.vpn.wireguard as wireguard


def _run(coro):
    return asyncio.run(coro)


def _fake_user(role: str = "admin", tier: str = "pro") -> User:
    return User(id=1, username="tester", email="tester@example.com",
                password_hash="x", role=role, subscription_tier=tier)


_FAKE_PEERS = [
    {
        "name": "laptop",
        "ip": "10.13.37.2",
        "public_key": "pub_abc",
        "private_key": "SECRET_PRIVATE_KEY_1",
        "psk": "SECRET_PSK_1",
        "created_at": "2026-01-01T00:00:00",
        "last_handshake": None,
        "rx_bytes": 0,
        "tx_bytes": 0,
    },
    {
        "name": "phone",
        "ip": "10.13.37.3",
        "public_key": "pub_def",
        "private_key": "SECRET_PRIVATE_KEY_2",
        "psk": "SECRET_PSK_2",
        "created_at": "2026-01-02T00:00:00",
        "last_handshake": None,
        "rx_bytes": 0,
        "tx_bytes": 0,
    },
]


def test_list_peers_api_excludes_private_key_and_psk(monkeypatch):
    monkeypatch.setattr(wireguard, "_load_peers", lambda: _FAKE_PEERS)

    result = _run(vpn_router.list_peers_api(user=_fake_user()))

    assert result["peers"], "expected peers in response"
    for peer in result["peers"]:
        assert "private_key" not in peer
        assert "psk" not in peer
    assert {p["name"] for p in result["peers"]} == {"laptop", "phone"}
    assert {p["public_key"] for p in result["peers"]} == {"pub_abc", "pub_def"}


def test_vpn_home_page_context_excludes_private_key_and_psk(monkeypatch):
    """The dashboard's own peer list (passed into vpn.html's template
    context) must also be scrubbed, not just the JSON API -- same
    underlying data source, same rule."""
    monkeypatch.setattr(wireguard, "_load_peers", lambda: _FAKE_PEERS)

    peers = wireguard.list_peers_public()

    for peer in peers:
        assert "private_key" not in peer
        assert "psk" not in peer


def test_peer_config_download_still_returns_full_secrets(tmp_path, monkeypatch):
    """The dedicated .conf download endpoint is the legitimate place for
    real secrets -- a peer's owner needs them to configure their device."""
    monkeypatch.chdir(tmp_path)
    config_dir = tmp_path / "data" / "wireguard"
    config_dir.mkdir(parents=True)
    conf_text = (
        "[Interface]\nPrivateKey = SECRET_PRIVATE_KEY_1\n\n"
        "[Peer]\nPresharedKey = SECRET_PSK_1\n"
    )
    (config_dir / "laptop.conf").write_text(conf_text)

    response = _run(vpn_router.peer_config("laptop", user=_fake_user()))

    body = response.body.decode()
    assert "SECRET_PRIVATE_KEY_1" in body
    assert "SECRET_PSK_1" in body
