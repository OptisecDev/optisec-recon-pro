"""
Tests for adversary-name filtering in modules/ioc_correlation.py.

Companion to tests/test_darkweb_intelligence.py's regression coverage and
tests/test_otx_feed.py: the same documented incident (OTX's free-text
`adversary` field returning a generic phrase like "Artificial Intelligence"
and being trusted as a confirmed threat actor) also reached this module's
clustering/scoring/pattern-detection logic. Verifies the fix applies here
too via modules.threat_intel.actor_naming.looks_like_threat_actor_name.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.ioc_correlation as ic


def _ioc(ioc_type, value, malware="TestMalware", adversary="", source="ALIENVAULT-OTX"):
    return {
        "id": f"{ioc_type}:{value}",
        "type": ioc_type,
        "value": value,
        "malware": malware,
        "confidence": 80,
        "source": source,
        "adversary": adversary,
        "tags": [],
        "threat_score": 80,
    }


class TestVerifiedAdversaryHelper:
    def test_verified_name_is_kept(self):
        assert ic._verified_adversary(_ioc("ip", "1.2.3.4", adversary="APT28")) == "APT28"

    def test_generic_phrase_is_rejected(self):
        assert ic._verified_adversary(_ioc("ip", "1.2.3.4", adversary="Artificial Intelligence")) == ""

    def test_missing_adversary_is_empty(self):
        assert ic._verified_adversary(_ioc("ip", "1.2.3.4")) == ""


class TestComputeClusterScoreActorBonus:
    def test_verified_actor_earns_bonus(self):
        iocs = [_ioc("ip", "1.2.3.4"), _ioc("domain", "evil.example")]
        with_actor = ic._compute_cluster_score(iocs, "APT28")
        without_actor = ic._compute_cluster_score(iocs, "")
        assert with_actor > without_actor


class TestCorrelateIocsAdversaryClustering:
    def test_generic_adversary_phrase_does_not_create_actor_cluster(self):
        """Regression for the documented incident: two IOCs both carrying
        adversary="Artificial Intelligence" must not be grouped into a
        "[Actor] Artificial Intelligence" cluster, and must not trigger the
        "attributed threat actor activity" pattern or an actor score bonus."""
        iocs = [
            _ioc("ip", "203.0.113.10", malware="Unknown", adversary="Artificial Intelligence"),
            _ioc("domain", "example-corp.test", malware="Unknown", adversary="Artificial Intelligence"),
        ]
        clusters = ic.correlate_iocs(iocs)

        actor_clusters = [c for c in clusters if c["strategy"] == "adversary"]
        assert actor_clusters == []
        assert not any("Artificial Intelligence" in c["name"] for c in clusters)
        for c in clusters:
            assert c["adversary"] == ""
            assert "attributed threat actor activity" not in c["patterns"]

    def test_verified_actor_name_still_creates_actor_cluster(self):
        """Sanity check the fix didn't disable real attribution: a verified
        actor name shared by 2+ IOCs must still form an adversary cluster."""
        iocs = [
            _ioc("ip", "203.0.113.20", malware="Unknown", adversary="APT28"),
            _ioc("domain", "another-evil.test", malware="Unknown", adversary="APT28"),
        ]
        clusters = ic.correlate_iocs(iocs)

        actor_clusters = [c for c in clusters if c["strategy"] == "adversary"]
        assert len(actor_clusters) == 1
        assert actor_clusters[0]["adversary"] == "APT28"
        assert actor_clusters[0]["name"] == "[Actor] APT28"
        assert "attributed threat actor activity" in actor_clusters[0]["patterns"]

    def test_malware_cluster_does_not_surface_generic_adversary_text(self):
        """Even outside the dedicated adversary-clustering strategy, the
        malware-family cluster's `adversary` field (and its "attributed
        threat actor activity" pattern) must not surface unverified text."""
        iocs = [_ioc("ip", "203.0.113.30", malware="Emotet", adversary="Artificial Intelligence")]
        clusters = ic.correlate_iocs(iocs)

        malware_clusters = [c for c in clusters if c["strategy"] == "malware_family"]
        assert len(malware_clusters) == 1
        assert malware_clusters[0]["adversary"] == ""
        assert "attributed threat actor activity" not in malware_clusters[0]["patterns"]
