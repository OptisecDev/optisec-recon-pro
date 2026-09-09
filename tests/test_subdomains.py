"""
Regression tests for the wildcard-DNS false-positive fix in
modules/recon/subdomains.py.

Root cause (confirmed manually against optisecdev.github.io, a GitHub Pages
domain): DNS A-record resolution alone was treated as proof a subdomain is a
real, live asset. Any *.github.io (or *.vercel.app / *.netlify.app / etc.)
wildcard-DNS domain resolves every single wordlist guess to the same shared
IPs, so the old brute-force-then-resolve logic reported the entire wordlist
(144/144 guesses) as "found" regardless of whether anything was actually
hosted there. `curl -vI` against one of those guesses showed the real
signal: the TLS handshake fails with a SAN mismatch, because the wildcard
cert only covers one level of subdomain.

enumerate_subdomains() now runs a second, cheap verification pass
(_verify_live_host -> _tls_san_check, with an _http_head_check fallback for
hosts with no TLS) before counting a DNS hit as a live subdomain, and
returns {"subdomains": [...confirmed...], "unconfirmed": [...rejected or
inconclusive...]} instead of a bare list.

These tests stub _resolve/_tls_san_check/_http_head_check directly so they
never touch the network.
"""

import pytest

import modules.recon.subdomains as subs_mod


def _wordlist(tmp_path, words):
    path = tmp_path / "wordlist.txt"
    path.write_text("\n".join(words))
    return path


def test_wildcard_dns_domain_excludes_unverified_hits(tmp_path, monkeypatch):
    """Every guess resolving (wildcard DNS) must NOT be enough on its own —
    a TLS handshake that succeeds but whose cert SAN doesn't cover the guess
    (the exact github.io signature) must exclude it from the confirmed
    bucket and tag it as a decisive rejection, not a silent drop."""
    monkeypatch.setattr(subs_mod, "WORDLIST_PATH", _wordlist(tmp_path, ["grafana", "www", "doesnotexist"]))
    monkeypatch.setattr(subs_mod, "_resolve", lambda sub: "185.199.108.153")
    monkeypatch.setattr(subs_mod, "_tls_san_check", lambda host: False)
    monkeypatch.setattr(
        subs_mod, "_http_head_check",
        lambda host: pytest.fail("HTTP fallback must not run after a decisive TLS SAN mismatch"),
    )

    result = subs_mod.enumerate_subdomains("optisecdev.github.io")

    assert result["subdomains"] == []
    assert len(result["unconfirmed"]) == 3
    assert all(u["reason"] == "tls_san_mismatch" for u in result["unconfirmed"])
    assert {u["subdomain"] for u in result["unconfirmed"]} == {
        "grafana.optisecdev.github.io", "www.optisecdev.github.io", "doesnotexist.optisecdev.github.io",
    }


def test_real_subdomain_confirmed_via_tls_san(tmp_path, monkeypatch):
    """Happy path / no-regression check: a genuine subdomain (DNS resolves
    AND the live-host probe confirms it) must still be counted, and a
    wordlist guess that never resolves must still be silently absent (not
    even in the unconfirmed bucket — DNS never found anything to verify)."""
    monkeypatch.setattr(subs_mod, "WORDLIST_PATH", _wordlist(tmp_path, ["www", "doesnotexist"]))

    def fake_resolve(sub):
        return "93.184.216.34" if sub == "www.example.com" else None

    monkeypatch.setattr(subs_mod, "_resolve", fake_resolve)
    monkeypatch.setattr(subs_mod, "_tls_san_check", lambda host: True)
    monkeypatch.setattr(
        subs_mod, "_http_head_check",
        lambda host: pytest.fail("HTTP fallback must not run when TLS already confirms"),
    )

    result = subs_mod.enumerate_subdomains("example.com")

    assert result["subdomains"] == [
        {"subdomain": "www.example.com", "ip": "93.184.216.34", "verified_via": "tls_san"}
    ]
    assert result["unconfirmed"] == []


def test_http_fallback_used_only_when_tls_handshake_cannot_complete(tmp_path, monkeypatch):
    """A host with no TLS on 443 at all (handshake never completes) must
    fall back to the HTTP probe rather than being rejected outright."""
    monkeypatch.setattr(subs_mod, "WORDLIST_PATH", _wordlist(tmp_path, ["api"]))
    monkeypatch.setattr(subs_mod, "_resolve", lambda sub: "203.0.113.9")
    monkeypatch.setattr(subs_mod, "_tls_san_check", lambda host: None)  # handshake never completed
    monkeypatch.setattr(subs_mod, "_http_head_check", lambda host: True)  # real HTTP app behind it

    result = subs_mod.enumerate_subdomains("example.com")

    assert result["subdomains"] == [
        {"subdomain": "api.example.com", "ip": "203.0.113.9", "verified_via": "http"}
    ]
    assert result["unconfirmed"] == []


def test_inconclusive_probe_is_not_silently_dropped(tmp_path, monkeypatch):
    """Trade-off case: DNS resolves but BOTH probes fail to even connect
    (network hiccup / target blocks probes). This must not be silently
    discarded (false negative) and must not be counted as confirmed (false
    positive) — it belongs in "unconfirmed" tagged distinctly from a
    decisive rejection, so a reviewer can tell the difference."""
    monkeypatch.setattr(subs_mod, "WORDLIST_PATH", _wordlist(tmp_path, ["flaky"]))
    monkeypatch.setattr(subs_mod, "_resolve", lambda sub: "203.0.113.10")
    monkeypatch.setattr(subs_mod, "_tls_san_check", lambda host: None)
    monkeypatch.setattr(subs_mod, "_http_head_check", lambda host: None)

    result = subs_mod.enumerate_subdomains("example.com")

    assert result["subdomains"] == []
    assert result["unconfirmed"] == [
        {"subdomain": "flaky.example.com", "ip": "203.0.113.10", "reason": "probe_failed"}
    ]


def test_hostname_matches_san_wildcard_is_single_label_only():
    sans = ["*.optisecdev.github.io", "optisecdev.github.io"]
    assert subs_mod._hostname_matches_san("www.optisecdev.github.io", sans) is True
    assert subs_mod._hostname_matches_san("optisecdev.github.io", sans) is True
    # Two-level guess (the actual bug): wildcard only covers ONE label, so
    # this must NOT match.
    assert subs_mod._hostname_matches_san("grafana.www.optisecdev.github.io", sans) is False
    assert subs_mod._hostname_matches_san("evil.com", sans) is False
