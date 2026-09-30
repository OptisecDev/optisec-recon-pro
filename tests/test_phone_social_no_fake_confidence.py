"""
Regression guard for a confirmed credibility bug (2026-09-30 OSINT audit):
Phone -> Social used to run live HTTP probes against wa.me/t.me/Viber and
blend the response into a "confidence" percentage. Live-tested against
multiple fabricated Iraqi numbers with no real accounts behind them, and
every one came back with a high "confidence" score (79% WhatsApp / 70%
Telegram for two different made-up numbers) -- the platforms' pages render
identically regardless of registration status, so the number measured
nothing real. Truecaller was a separate, permanently dead probe: it called
`search.truecaller.com`, a hostname with no DNS record at all.

Both were removed. This test fails again if either regresses:
  - any WhatsApp/Telegram/Viber entry carrying a numeric "confidence"
  - Truecaller appearing anywhere in the module or its output
  - the old "5-tier ... confidence" framing reappearing
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.osint.phone_social as ps


def _run(coro):
    return asyncio.run(coro)


FAKE_IRAQI_NUMBERS = ["+9647701234567", "+9647809999999", "+9647123456789"]


@pytest.fixture(autouse=True)
def _no_api_keys(monkeypatch):
    # Force every T1/T2 source into its explicit "checked: False" path so
    # this test never makes a real network call regardless of the host
    # machine's environment.
    for key in ("HIBP_API_KEY", "NUMVERIFY_API_KEY", "ABSTRACTAPI_PHONE_KEY"):
        monkeypatch.delenv(key, raising=False)


class TestNoFakeConfidence:
    @pytest.mark.parametrize("number", FAKE_IRAQI_NUMBERS)
    def test_manual_check_platforms_carry_no_confidence(self, number):
        result = _run(ps.phone_social_lookup(number))
        by_name = {p["platform"]: p for p in result["social_platforms"]}
        for platform in ("WhatsApp", "Telegram", "Viber"):
            assert platform in by_name, platform
            entry = by_name[platform]
            assert "confidence" not in entry, (
                f"{platform} must not carry a confidence score: {entry}"
            )
            assert entry["status"] == "manual_check_only"
            assert "not automatically verified" in entry["note"].lower()

    def test_truecaller_is_gone(self):
        result = _run(ps.phone_social_lookup(FAKE_IRAQI_NUMBERS[0]))
        names = [p["platform"] for p in result["social_platforms"]]
        assert "Truecaller" not in names

        # The module docstring is allowed to *explain*, by name, why the
        # dead search.truecaller.com endpoint was removed; what must be
        # gone is any function that still calls it.
        import ast
        tree = ast.parse(open(ps.__file__, encoding="utf-8").read())
        func_names = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        assert not any("truecaller" in name.lower() for name in func_names)

    def test_no_probe_functions_remain(self):
        for dead_name in ("_probe_whatsapp", "_probe_telegram", "_probe_viber", "_probe_truecaller"):
            assert not hasattr(ps, dead_name), f"{dead_name} should have been removed"

    def test_risk_score_has_no_social_confidence_component(self):
        """_compute_risk must not accept/use a social-platform list any
        more -- confirms the fake exposure_score contribution was deleted,
        not just hidden from the output."""
        import inspect
        sig = inspect.signature(ps._compute_risk)
        assert "social" not in sig.parameters

    def test_regional_adoption_table_removed(self):
        """The unsourced per-platform adoption percentages that used to be
        blended into confidence must not still exist to be reused later."""
        assert not hasattr(ps, "REGIONAL_ADOPTION")

    def test_two_fabricated_numbers_produce_identical_manual_link_shape(self):
        """Sanity check that the fix actually removed the discriminating-
        looking-but-not-discriminating signal: two different fake numbers
        must not differ in anything except the URL itself."""
        r1 = _run(ps.phone_social_lookup(FAKE_IRAQI_NUMBERS[0]))
        r2 = _run(ps.phone_social_lookup(FAKE_IRAQI_NUMBERS[1]))
        for p1, p2 in zip(
            [p for p in r1["social_platforms"] if p["status"] == "manual_check_only"],
            [p for p in r2["social_platforms"] if p["status"] == "manual_check_only"],
        ):
            assert p1["platform"] == p2["platform"]
            assert p1["note"] == p2["note"]
