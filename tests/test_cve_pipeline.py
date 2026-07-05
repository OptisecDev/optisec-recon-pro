"""
Tests for the CVE Submission Pipeline: drafting logic and CVE JSON 5.0
rendering (modules/bug_bounty/cve_pipeline.py) and the router's
persistence/query helpers (web/routers/cve_submission.py).

Mirrors tests/test_threat_sharing.py's conventions: plain pytest, async
functions driven via asyncio.run(), monkeypatch for isolation, an in-memory
SQLite engine wired in place of web.database.SessionLocal, and no real
network calls (httpx.AsyncClient is monkeypatched, never actually invoked).

SAFETY INVARIANT this suite exists to protect: there is no submit-to-MITRE
function anywhere in cve_pipeline.py — draft generation and CVE JSON 5.0
export are the only outputs. Tests assert this shape rather than assume it.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.database as database
from web.database import Base
from web.models import User, Target, Scan, Finding, CveDraft
import modules.bug_bounty.cve_pipeline as pipeline
import web.routers.cve_submission as cve_router


def _run(coro):
    return asyncio.run(coro)


# ── Isolated in-memory DB fixture (same pattern as test_honeypot.py) ───────

@pytest.fixture
def db(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())
    monkeypatch.setattr(database, "SessionLocal", TestSessionLocal)
    yield TestSessionLocal
    _run(engine.dispose())


async def _seed_user(session_factory, **overrides) -> User:
    defaults = dict(username="u1", email="u1@example.com", password_hash="x",
                     role="analyst", api_key_hash="k1", is_active=True)
    defaults.update(overrides)
    async with session_factory() as db_:
        user = User(**defaults)
        db_.add(user)
        await db_.commit()
        await db_.refresh(user)
        return user


async def _seed_finding(session_factory, user_id: int, **overrides) -> Finding:
    async with session_factory() as db_:
        target = Target(user_id=user_id, url="https://example.com", name="example")
        db_.add(target)
        await db_.flush()
        scan = Scan(id=f"scan_{overrides.get('_scan_suffix', 'a')}", user_id=user_id,
                    target_id=target.id, target_url="https://example.com", status="done")
        db_.add(scan)
        await db_.flush()
        defaults = dict(
            scan_id=scan.id, target_id=target.id, vuln_type="XSS", severity="high",
            url="https://example.com/search?q=1", parameter="q",
            payload="<script>alert(1)</script>", evidence="Reflected in response body",
        )
        defaults.update({k: v for k, v in overrides.items() if not k.startswith("_")})
        finding = Finding(**defaults)
        db_.add(finding)
        await db_.commit()
        await db_.refresh(finding)
        return finding


# ── 1. CWE mapping ──────────────────────────────────────────────────────────

class TestCweForVulnType:
    def test_xss_maps_to_cwe_79(self):
        cwe = pipeline.cwe_for_vuln_type("XSS")
        assert cwe["cwe_id"] == "CWE-79"

    def test_sqli_maps_to_cwe_89(self):
        assert pipeline.cwe_for_vuln_type("SQLi")["cwe_id"] == "CWE-89"

    def test_ssrf_maps_to_cwe_918(self):
        assert pipeline.cwe_for_vuln_type("SSRF")["cwe_id"] == "CWE-918"

    def test_open_redirect_maps_to_cwe_601(self):
        assert pipeline.cwe_for_vuln_type("Open Redirect")["cwe_id"] == "CWE-601"

    def test_lfi_maps_to_cwe_98(self):
        assert pipeline.cwe_for_vuln_type("LFI")["cwe_id"] == "CWE-98"

    def test_case_insensitive(self):
        assert pipeline.cwe_for_vuln_type("xss") == pipeline.cwe_for_vuln_type("XSS")

    def test_unknown_type_falls_back(self):
        cwe = pipeline.cwe_for_vuln_type("some-made-up-type")
        assert cwe["cwe_id"] == "NVD-CWE-noinfo"

    def test_empty_string_falls_back(self):
        cwe = pipeline.cwe_for_vuln_type("")
        assert cwe["cwe_id"] == "NVD-CWE-noinfo"


# ── 2. Suggested CVSS defaults ─────────────────────────────────────────────

class TestSuggestedCvss:
    @pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
    def test_known_severity_returns_vector_and_score(self, severity):
        result = pipeline.suggested_cvss(severity)
        assert result["vector"].startswith("CVSS:3.1/")
        assert float(result["score"]) > 0

    def test_unknown_severity_falls_back_to_medium(self):
        assert pipeline.suggested_cvss("nonsense") == pipeline.SUGGESTED_CVSS_BY_SEVERITY["medium"]

    def test_case_insensitive(self):
        assert pipeline.suggested_cvss("HIGH") == pipeline.suggested_cvss("high")

    def test_critical_scores_higher_than_low(self):
        crit = float(pipeline.suggested_cvss("critical")["score"])
        low = float(pipeline.suggested_cvss("low")["score"])
        assert crit > low


# ── 3. Draft ref generation ─────────────────────────────────────────────────

class TestNewDraftRef:
    def test_format(self):
        ref = pipeline.new_draft_ref()
        assert ref.startswith("CVE-DRAFT-")
        assert len(ref) == len("CVE-DRAFT-") + 8

    def test_unique_across_calls(self):
        refs = {pipeline.new_draft_ref() for _ in range(20)}
        assert len(refs) == 20


# ── 4. draft_from_finding — suggests fields, never fabricates a real CVE ───

class TestDraftFromFinding:
    def test_builds_title_and_product_from_url(self):
        draft = pipeline.draft_from_finding({
            "type": "XSS", "severity": "high",
            "url": "https://example.com/search?q=1", "parameter": "q",
            "evidence": "Reflected in response",
        })
        assert "XSS" in draft["title"]
        assert draft["product"] == "example.com"
        assert draft["vendor"] == "Unknown"

    def test_includes_parameter_and_evidence_in_description(self):
        draft = pipeline.draft_from_finding({
            "type": "SQLi", "severity": "critical", "url": "https://x.com/api",
            "parameter": "id", "evidence": "Boolean-based blind SQLi confirmed",
        })
        assert "id" in draft["description"]
        assert "Boolean-based blind SQLi confirmed" in draft["description"]

    def test_falls_back_to_payload_when_no_evidence(self):
        draft = pipeline.draft_from_finding({
            "type": "XSS", "severity": "medium", "url": "https://x.com",
            "payload": "<script>alert(1)</script>",
        })
        assert "<script>alert(1)</script>" in draft["description"]

    def test_maps_problem_type_from_vuln_type(self):
        draft = pipeline.draft_from_finding({"type": "SSRF", "severity": "high", "url": "https://x.com"})
        assert draft["problem_type"].startswith("CWE-918")

    def test_suggests_cvss_from_severity(self):
        draft = pipeline.draft_from_finding({"type": "XSS", "severity": "critical", "url": "https://x.com"})
        assert draft["cvss_vector"] == pipeline.SUGGESTED_CVSS_BY_SEVERITY["critical"]["vector"]

    def test_references_include_finding_url(self):
        draft = pipeline.draft_from_finding({"type": "XSS", "severity": "low", "url": "https://x.com/a"})
        assert draft["references"] == ["https://x.com/a"]

    def test_no_url_produces_unknown_product_and_no_references(self):
        draft = pipeline.draft_from_finding({"type": "XSS", "severity": "low", "url": ""})
        assert draft["product"] == "Unknown"
        assert draft["references"] == []

    def test_versions_affected_placeholder_present(self):
        draft = pipeline.draft_from_finding({"type": "XSS", "severity": "low", "url": "https://x.com"})
        assert draft["versions_affected"] == [{"version": "unspecified", "status": "affected"}]


# ── 5. build_cve_json_5 — CVE JSON 5.0 record shape ────────────────────────

class TestBuildCveJson5:
    def _base_draft(self, **overrides):
        base = dict(
            title="XSS in ExampleApp", description="Reflected XSS via 'q' parameter.",
            vendor="Unknown", product="example.com",
            versions_affected=[{"version": "unspecified", "status": "affected"}],
            problem_type="CWE-79 Cross-Site Scripting (XSS)", severity="high",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score="8.1",
            references=["https://example.com/a"], credits=[{"name": "Jane", "type": "finder"}],
            cna_org=None,
        )
        base.update(overrides)
        return base

    def test_top_level_shape(self):
        record = pipeline.build_cve_json_5(self._base_draft())
        assert record["dataType"] == "CVE_RECORD"
        assert record["dataVersion"] == "5.1"
        assert "cveMetadata" in record and "containers" in record

    def test_cve_id_is_tbd_placeholder_not_a_real_id(self):
        record = pipeline.build_cve_json_5(self._base_draft())
        assert record["cveMetadata"]["cveId"] == "CVE-TBD-TBD"
        assert record["cveMetadata"]["state"] == "DRAFT"

    def test_cna_container_has_title_and_description(self):
        record = pipeline.build_cve_json_5(self._base_draft())
        cna = record["containers"]["cna"]
        assert cna["title"] == "XSS in ExampleApp"
        assert cna["descriptions"][0]["lang"] == "en"
        assert "Reflected XSS" in cna["descriptions"][0]["value"]

    def test_affected_block_uses_vendor_product_versions(self):
        record = pipeline.build_cve_json_5(self._base_draft())
        affected = record["containers"]["cna"]["affected"][0]
        assert affected["vendor"] == "Unknown"
        assert affected["product"] == "example.com"
        assert affected["versions"] == [{"version": "unspecified", "status": "affected"}]

    def test_problem_type_extracts_cwe_id(self):
        record = pipeline.build_cve_json_5(self._base_draft())
        pt = record["containers"]["cna"]["problemTypes"][0]["descriptions"][0]
        assert pt["type"] == "CWE"
        assert pt["cweId"] == "CWE-79"

    def test_problem_type_without_cwe_prefix_omits_cwe_id(self):
        record = pipeline.build_cve_json_5(self._base_draft(problem_type="Unclassified issue"))
        pt = record["containers"]["cna"]["problemTypes"][0]["descriptions"][0]
        assert "cweId" not in pt

    def test_references_mapped_to_url_objects(self):
        record = pipeline.build_cve_json_5(self._base_draft())
        assert record["containers"]["cna"]["references"] == [{"url": "https://example.com/a"}]

    def test_metrics_populated_when_cvss_present(self):
        record = pipeline.build_cve_json_5(self._base_draft())
        metrics = record["containers"]["cna"]["metrics"]
        assert metrics[0]["cvssV3_1"]["vectorString"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
        assert metrics[0]["cvssV3_1"]["baseScore"] == 8.1

    def test_metrics_empty_when_no_cvss(self):
        record = pipeline.build_cve_json_5(self._base_draft(cvss_vector=None, cvss_score=None))
        assert record["containers"]["cna"]["metrics"] == []

    def test_credits_mapped(self):
        record = pipeline.build_cve_json_5(self._base_draft())
        assert record["containers"]["cna"]["credits"][0]["value"] == "Jane"
        assert record["containers"]["cna"]["credits"][0]["type"] == "finder"

    def test_no_references_or_credits_produces_empty_lists(self):
        record = pipeline.build_cve_json_5(self._base_draft(references=[], credits=[]))
        cna = record["containers"]["cna"]
        assert cna["references"] == []
        assert cna["credits"] == []

    def test_missing_versions_affected_gets_placeholder(self):
        record = pipeline.build_cve_json_5(self._base_draft(versions_affected=None))
        assert record["containers"]["cna"]["affected"][0]["versions"] == [
            {"version": "unspecified", "status": "affected"}
        ]

    def test_cna_org_used_as_provider_shortname_when_set(self):
        record = pipeline.build_cve_json_5(self._base_draft(cna_org="MyOrg CNA"))
        assert record["containers"]["cna"]["providerMetadata"]["shortName"] == "MyOrg CNA"

    def test_cna_org_defaults_to_tbd(self):
        record = pipeline.build_cve_json_5(self._base_draft(cna_org=None))
        assert record["containers"]["cna"]["providerMetadata"]["shortName"] == "TBD"


# ── 6. search_nvd — read-only lookup, mocked HTTP, never raises ───────────

class _FakeHttpResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self):
        return self._json_data


class _FakeAsyncClient:
    def __init__(self, response=None, exc=None, **kw):
        self._response = response
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, params=None, headers=None):
        if self._exc:
            raise self._exc
        return self._response


def _nvd_payload():
    return {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T00:00:00",
                "lastModified": "2021-12-11T00:00:00",
                "descriptions": [{"lang": "en", "value": "Log4Shell RCE."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
                "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
            }
        }],
    }


class TestSearchNvd:
    def test_search_by_cve_id_parses_fields(self, monkeypatch):
        monkeypatch.setattr(pipeline.httpx, "AsyncClient",
                             lambda *a, **kw: _FakeAsyncClient(response=_FakeHttpResponse(200, _nvd_payload())))
        result = _run(pipeline.search_nvd(cve_id="CVE-2021-44228"))
        assert result["source"] == "nvd"
        assert result["vulnerabilities"][0]["cve_id"] == "CVE-2021-44228"
        assert result["vulnerabilities"][0]["severity"] == "CRITICAL"

    def test_search_by_keyword(self, monkeypatch):
        monkeypatch.setattr(pipeline.httpx, "AsyncClient",
                             lambda *a, **kw: _FakeAsyncClient(response=_FakeHttpResponse(200, _nvd_payload())))
        result = _run(pipeline.search_nvd(keyword="log4j"))
        assert result["total"] == 1

    def test_http_error_returns_error_not_raise(self, monkeypatch):
        monkeypatch.setattr(pipeline.httpx, "AsyncClient",
                             lambda *a, **kw: _FakeAsyncClient(response=_FakeHttpResponse(500)))
        result = _run(pipeline.search_nvd(keyword="x"))
        assert "error" in result
        assert result["vulnerabilities"] == []

    def test_connection_error_returns_error_not_raise(self, monkeypatch):
        monkeypatch.setattr(pipeline.httpx, "AsyncClient",
                             lambda *a, **kw: _FakeAsyncClient(exc=ConnectionError("no network")))
        result = _run(pipeline.search_nvd(keyword="x"))
        assert "error" in result

    def test_no_query_still_returns_shape(self, monkeypatch):
        monkeypatch.setattr(pipeline.httpx, "AsyncClient",
                             lambda *a, **kw: _FakeAsyncClient(response=_FakeHttpResponse(200, {"vulnerabilities": [], "totalResults": 0})))
        result = _run(pipeline.search_nvd())
        assert result["vulnerabilities"] == []


# ── 7. Router persistence — get_finding_for_user / create_draft ───────────

class TestGetFindingForUser:
    def test_returns_finding_owned_by_user(self, db):
        async def go():
            user = await _seed_user(db)
            finding = await _seed_finding(db, user.id)
            async with db() as db_:
                return await cve_router.get_finding_for_user(db_, finding.id, user.id)
        result = _run(go())
        assert result is not None

    def test_returns_none_for_other_users_finding(self, db):
        async def go():
            owner = await _seed_user(db, username="owner", email="owner@example.com", api_key_hash="k-owner")
            other = await _seed_user(db, username="other", email="other@example.com", api_key_hash="k-other")
            finding = await _seed_finding(db, owner.id)
            async with db() as db_:
                return await cve_router.get_finding_for_user(db_, finding.id, other.id)
        assert _run(go()) is None

    def test_returns_none_for_nonexistent_finding(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                return await cve_router.get_finding_for_user(db_, 9999, user.id)
        assert _run(go()) is None


class TestCreateDraft:
    def test_from_finding_id_auto_derives_fields(self, db):
        async def go():
            user = await _seed_user(db)
            finding = await _seed_finding(db, user.id, vuln_type="SQLi", severity="critical")
            async with db() as db_:
                return await cve_router.create_draft(db_, user=user, payload={}, finding=finding)
        row = _run(go())
        assert row.source_module == "scan_finding"
        assert row.finding_id is not None
        assert "SQLi" in row.title
        assert row.problem_type.startswith("CWE-89")

    def test_manual_payload_requires_title_and_description(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                await cve_router.create_draft(db_, user=user, payload={"title": "x"}, finding=None)
        with pytest.raises(ValueError):
            _run(go())

    def test_manual_payload_saved_when_complete(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                return await cve_router.create_draft(
                    db_, user=user,
                    payload={"title": "RCE in Foo", "description": "Detailed desc", "severity": "critical"},
                    finding=None,
                )
        row = _run(go())
        assert row.source_module == "manual"
        assert row.title == "RCE in Foo"
        assert row.severity == "critical"

    def test_manual_overrides_apply_on_top_of_finding_derivation(self, db):
        async def go():
            user = await _seed_user(db)
            finding = await _seed_finding(db, user.id, vuln_type="XSS", severity="low")
            async with db() as db_:
                return await cve_router.create_draft(
                    db_, user=user, payload={"title": "Custom override title"}, finding=finding,
                )
        row = _run(go())
        assert row.title == "Custom override title"
        assert row.source_module == "scan_finding"  # still tagged as finding-derived

    def test_draft_ref_is_unique_per_call(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                r1 = await cve_router.create_draft(
                    db_, user=user, payload={"title": "A", "description": "d"}, finding=None,
                )
            async with db() as db_:
                r2 = await cve_router.create_draft(
                    db_, user=user, payload={"title": "B", "description": "d"}, finding=None,
                )
            return r1.draft_ref, r2.draft_ref
        ref1, ref2 = _run(go())
        assert ref1 != ref2

    def test_reporter_defaults_to_requesting_user(self, db):
        async def go():
            user = await _seed_user(db, username="analyst1", email="analyst1@example.com", api_key_hash="k2")
            async with db() as db_:
                return await cve_router.create_draft(
                    db_, user=user, payload={"title": "A", "description": "d"}, finding=None,
                )
        row = _run(go())
        assert row.reporter_name == "analyst1"
        assert row.reporter_email == "analyst1@example.com"

    def test_status_always_starts_as_draft(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                return await cve_router.create_draft(
                    db_, user=user, payload={"title": "A", "description": "d"}, finding=None,
                )
        assert _run(go()).status == "draft"


class TestListDrafts:
    def test_lists_only_requesting_users_drafts(self, db):
        async def go():
            owner = await _seed_user(db, username="owner", email="owner@example.com", api_key_hash="k-owner")
            other = await _seed_user(db, username="other", email="other@example.com", api_key_hash="k-other")
            async with db() as db_:
                await cve_router.create_draft(db_, user=owner, payload={"title": "A", "description": "d"}, finding=None)
                await cve_router.create_draft(db_, user=other, payload={"title": "B", "description": "d"}, finding=None)
            async with db() as db_:
                return await cve_router.list_drafts(db_, user_id=owner.id)
        rows = _run(go())
        assert len(rows) == 1
        assert rows[0].title == "A"

    def test_filters_by_status(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                row = await cve_router.create_draft(db_, user=user, payload={"title": "A", "description": "d"}, finding=None)
                row.status = "exported"
                await db_.commit()
                await cve_router.create_draft(db_, user=user, payload={"title": "B", "description": "d"}, finding=None)
            async with db() as db_:
                return await cve_router.list_drafts(db_, user_id=user.id, status="exported")
        rows = _run(go())
        assert len(rows) == 1
        assert rows[0].title == "A"

    def test_orders_newest_first(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                await cve_router.create_draft(db_, user=user, payload={"title": "First", "description": "d"}, finding=None)
                await cve_router.create_draft(db_, user=user, payload={"title": "Second", "description": "d"}, finding=None)
            async with db() as db_:
                return await cve_router.list_drafts(db_, user_id=user.id)
        rows = _run(go())
        assert rows[0].title == "Second"

    def test_respects_limit(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                for i in range(5):
                    await cve_router.create_draft(db_, user=user, payload={"title": f"T{i}", "description": "d"}, finding=None)
            async with db() as db_:
                return await cve_router.list_drafts(db_, user_id=user.id, limit=2)
        assert len(_run(go())) == 2

    def test_empty_when_no_drafts(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                return await cve_router.list_drafts(db_, user_id=user.id)
        assert _run(go()) == []


class TestGetDraft:
    def test_returns_own_draft(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                created = await cve_router.create_draft(db_, user=user, payload={"title": "A", "description": "d"}, finding=None)
            async with db() as db_:
                return await cve_router.get_draft(db_, draft_id=created.id, user_id=user.id)
        assert _run(go()) is not None

    def test_returns_none_for_other_users_draft(self, db):
        async def go():
            owner = await _seed_user(db, username="owner", email="owner@example.com", api_key_hash="k-owner")
            other = await _seed_user(db, username="other", email="other@example.com", api_key_hash="k-other")
            async with db() as db_:
                created = await cve_router.create_draft(db_, user=owner, payload={"title": "A", "description": "d"}, finding=None)
            async with db() as db_:
                return await cve_router.get_draft(db_, draft_id=created.id, user_id=other.id)
        assert _run(go()) is None

    def test_returns_none_for_missing_draft(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                return await cve_router.get_draft(db_, draft_id=9999, user_id=user.id)
        assert _run(go()) is None


# ── 8. Serialization helpers — disclaimer always present ───────────────────

class TestDraftToDict:
    def test_includes_disclaimer_in_every_serialization(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                return await cve_router.create_draft(db_, user=user, payload={"title": "A", "description": "d"}, finding=None)
        row = _run(go())
        d = cve_router._draft_to_dict(row)
        assert "MITRE" in d["disclaimer_en"]
        assert "CNA" in d["disclaimer_en"]
        assert "CNA" in d["disclaimer_ar"]

    def test_list_item_has_no_description_field(self, db):
        async def go():
            user = await _seed_user(db)
            async with db() as db_:
                return await cve_router.create_draft(db_, user=user, payload={"title": "A", "description": "d"}, finding=None)
        row = _run(go())
        item = cve_router._list_item(row)
        assert "description" not in item
        assert item["draft_ref"] == row.draft_ref


# ── 9. Safety invariant — no submit-to-MITRE capability exists ─────────────

class TestNoLiveSubmissionCapability:
    def test_module_has_no_submit_function(self):
        assert not hasattr(pipeline, "submit_cve_to_mitre")

    def test_module_never_imports_cve_services_base_url(self):
        import inspect
        source = inspect.getsource(pipeline)
        assert "cveawg.mitre.org" not in source

    def test_router_has_no_submit_route(self):
        paths = {getattr(r, "path", "") for r in cve_router.router.routes}
        assert not any("submit" in p for p in paths)
