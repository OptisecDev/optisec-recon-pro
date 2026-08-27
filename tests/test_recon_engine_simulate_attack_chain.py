"""Tests for app/services/recon/recon_engine.py's simulate_attack_chain().

simulate_attack_chain() returns a fixed 5-step attack-chain template
(Reconnaissance -> Initial Access -> Privilege Escalation -> Persistence ->
Impact) persisted with a real executed_at timestamp, but no real engine
performs any of these steps. Every step dict must be tagged simulated=True
at the root, with a bilingual note/note_ar explaining it's a fixed
simulation template and not the result of an actual exploitation attempt.

Uses a fake EternalSessionLocal (no real Postgres/Timescale connection
required) so the test stays isolated, mirroring the fake-based approach in
tests/test_eternal_archive.py.
"""
import asyncio
import uuid

import app.services.recon.recon_engine as recon_engine
from app.services.recon.recon_engine import simulate_attack_chain


class _FakeEternalSession:
    """Stands in for EternalSessionLocal(): add()/commit()/refresh() are all
    no-ops since SimulationStep already has every field the caller reads
    (step_order, mitre_tactic, description, executed_at) set directly."""

    def __init__(self):
        self.added = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass


def _run_simulation(monkeypatch):
    monkeypatch.setattr(recon_engine, "EternalSessionLocal", lambda: _FakeEternalSession())
    return asyncio.run(simulate_attack_chain(uuid.uuid4()))


def test_every_step_is_tagged_simulated_at_root(monkeypatch):
    steps = _run_simulation(monkeypatch)

    assert len(steps) == 5
    for step in steps:
        assert step["simulated"] is True
        assert isinstance(step.get("note"), str) and step["note"]
        assert isinstance(step.get("note_ar"), str) and step["note_ar"]


def test_note_is_bilingual_and_distinguishes_simulation_from_real_execution(monkeypatch):
    steps = _run_simulation(monkeypatch)

    for step in steps:
        assert "simulat" in step["note"].lower()
        # Arabic note should contain the Arabic word for simulation (محاكاة)
        assert "محاكاة" in step["note_ar"]


def test_template_content_itself_is_unchanged(monkeypatch):
    steps = _run_simulation(monkeypatch)

    tactics = [s["mitre_tactic"] for s in steps]
    assert tactics == [
        "Reconnaissance",
        "Initial Access",
        "Privilege Escalation",
        "Persistence",
        "Impact",
    ]
    assert [s["step_order"] for s in steps] == [1, 2, 3, 4, 5]
    for step in steps:
        assert step["executed_at"]
        assert step["description"]
