"""Tests for WireGuard Endpoint normalization: before this fix, add_peer()
always built `Endpoint = {endpoint}:{port}` -- if the admin had already
typed a port into the endpoint field (e.g. "vpn.example.com:51820"), the
client config ended up with "vpn.example.com:51820:51820", which every
WireGuard client rejects as an invalid endpoint.

Mirrors tests/test_vpn_peer_name_path_traversal.py's convention:
monkeypatch.chdir(tmp_path) for filesystem isolation, call module
functions directly.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.vpn.wireguard as wireguard


class TestNormalizeEndpoint:
    def test_bare_host_gets_listen_port_appended(self):
        assert wireguard._normalize_endpoint("vpn.example.com", 51820) == "vpn.example.com:51820"

    def test_host_with_explicit_port_is_used_as_is(self):
        assert wireguard._normalize_endpoint("vpn.example.com:51820", 51820) == "vpn.example.com:51820"

    def test_host_with_different_explicit_port_is_not_overridden(self):
        assert wireguard._normalize_endpoint("vpn.example.com:12345", 51820) == "vpn.example.com:12345"

    def test_bare_ipv4_gets_port_appended(self):
        assert wireguard._normalize_endpoint("203.0.113.5", 51820) == "203.0.113.5:51820"

    def test_ipv4_with_port_is_used_as_is(self):
        assert wireguard._normalize_endpoint("203.0.113.5:51820", 51820) == "203.0.113.5:51820"

    def test_bracketed_ipv6_with_port_is_used_as_is(self):
        assert wireguard._normalize_endpoint("[2001:db8::1]:51820", 51820) == "[2001:db8::1]:51820"

    def test_bracketed_ipv6_without_port_gets_port_appended(self):
        assert wireguard._normalize_endpoint("[2001:db8::1]", 51820) == "[2001:db8::1]:51820"

    @pytest.mark.parametrize("endpoint", [
        "vpn.example.com", "vpn.example.com:51820", "203.0.113.5",
        "203.0.113.5:51820", "[2001:db8::1]", "[2001:db8::1]:51820",
    ])
    def test_result_always_has_exactly_one_port(self, endpoint):
        result = wireguard._normalize_endpoint(endpoint, 51820)
        assert result.count(":51820") == 1


class TestAddPeerEmitsSinglePortEndpoint:
    @pytest.mark.parametrize("endpoint_input", ["vpn.example.com", "vpn.example.com:51820"])
    def test_client_config_endpoint_line_has_one_port(self, endpoint_input, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(wireguard, "_load_peers", lambda: [])
        monkeypatch.setattr(wireguard, "_save_peers", lambda peers: None)

        result = wireguard.add_peer(name="laptop", endpoint=endpoint_input, port=51820)

        endpoint_line = next(l for l in result["config"].splitlines() if l.startswith("Endpoint"))
        assert endpoint_line == "Endpoint = vpn.example.com:51820"
