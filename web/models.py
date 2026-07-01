from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from web.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="viewer")  # admin | analyst | viewer
    api_key = Column(String(64), unique=True, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

    targets = relationship("Target", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    darkweb_monitors = relationship("DarkWebMonitor", back_populates="user", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    url = Column(String(500), nullable=False)
    name = Column(String(200))
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target")
    findings = relationship("Finding", back_populates="target")
    reports = relationship("Report", back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target_url = Column(String(500), nullable=False)
    scan_types = Column(JSON)
    status = Column(String(20), default="pending")  # pending | running | done | failed
    progress = Column(Integer, default=0)
    results = Column(JSON)
    error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    user = relationship("User", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    vuln_type = Column(String(100))
    severity = Column(String(20))
    url = Column(String(500))
    parameter = Column(String(200))
    payload = Column(Text)
    evidence = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    target = relationship("Target", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(255))
    file_path = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="reports")
    target = relationship("Target", back_populates="reports")
    scan = relationship("Scan", back_populates="reports")


class DarkWebMonitor(Base):
    """A domain/email watched for new dark web / breach exposure — see
    modules/darkweb/monitor.py for the check logic."""
    __tablename__ = "darkweb_monitors"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target = Column(String(255), nullable=False)
    target_type = Column(String(10), default="domain")  # domain | email
    label = Column(String(200))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_checked_at = Column(DateTime)

    user = relationship("User", back_populates="darkweb_monitors")
    alerts = relationship("DarkWebAlert", back_populates="monitor", cascade="all, delete-orphan")


class DarkWebAlert(Base):
    """A single new leak event discovered for a DarkWebMonitor — `fingerprint`
    dedupes re-checks so the same leak is never stored twice."""
    __tablename__ = "darkweb_alerts"

    id = Column(Integer, primary_key=True)
    monitor_id = Column(Integer, ForeignKey("darkweb_monitors.id", ondelete="CASCADE"), nullable=False)
    fingerprint = Column(String(64), nullable=False, index=True)
    source = Column(String(50))  # breach | paste | github_secret | threat_actor | leakcheck
    severity = Column(String(20))
    title = Column(String(300))
    detail = Column(JSON)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    acknowledged = Column(Boolean, default=False)

    monitor = relationship("DarkWebMonitor", back_populates="alerts")


class HoneypotEvent(Base):
    """A single connection captured by one of the lightweight honeypot
    listeners (modules/honeypot/listeners.py) — SSH, FTP or a fake HTTP
    admin panel, each bound to a non-standard port that never overlaps a
    real service (see modules/honeypot/manager.py). Enriched at write time
    with geolocation + AbuseIPDB reputation (modules/honeypot/enrichment.py)
    so reads never need a fresh lookup. Global, not per-user — every
    logged-in user can see the same feed, like the global threat feed."""
    __tablename__ = "honeypot_events"

    id = Column(Integer, primary_key=True)
    service = Column(String(20), nullable=False, index=True)  # ssh | ftp | http_admin
    source_ip = Column(String(45), nullable=False, index=True)  # IPv4/IPv6
    source_port = Column(Integer)
    dest_port = Column(Integer)
    payload = Column(Text)          # raw attacker input, truncated (see listeners.MAX_PAYLOAD_BYTES)
    session_data = Column(JSON)     # structured protocol detail: banner/commands/headers/path...
    country = Column(String(100))
    country_code = Column(String(5))
    city = Column(String(100))
    isp = Column(String(200))
    abuse_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="UNKNOWN")  # LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN
    enrichment = Column(JSON)       # full raw enrichment payload (geo + abuseipdb)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("ix_honeypot_events_ip_time", "source_ip", "created_at"),
    )


class ThreatShare(Base):
    """Audit trail of every outbound IOC share — see
    modules/threat_intel/threat_sharing.py. Each row is one explicit,
    human-triggered share action (never automatic, see ENABLE_THREAT_SHARING
    in config.py); only a technical indicator (ip/domain/hash/cve/url) is
    ever stored here — never a customer identity, monitored target, or
    scan result."""
    __tablename__ = "threat_shares"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ioc_type = Column(String(30), nullable=False)   # ip | domain | hash_md5 | hash_sha1 | hash_sha256 | cve | url
    ioc_value = Column(String(500), nullable=False, index=True)
    source_module = Column(String(30))  # honeypot | darkweb | vulnerability_intel | manual
    severity = Column(String(20))
    tlp = Column(String(10), default="AMBER")
    destination = Column(String(50), default="alienvault_otx")
    status = Column(String(20))   # success | failed | disabled | invalid
    detail = Column(JSON)         # sanitized result/error detail — no PII
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User")


class CveDraft(Base):
    """A locally-drafted CVE report — see modules/bug_bounty/cve_pipeline.py.
    Pure drafting aid: nothing here is ever submitted to MITRE automatically.
    `status` only ever moves draft -> exported (a human downloaded the CVE
    JSON 5.0 record); actual submission to a CNA is a manual, out-of-band
    human action. May be derived from an existing Finding (source_module
    "scan_finding") or entered manually ("manual")."""
    __tablename__ = "cve_drafts"

    id = Column(Integer, primary_key=True)
    draft_ref = Column(String(30), unique=True, nullable=False, index=True)  # CVE-DRAFT-XXXXXXXX
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    source_module = Column(String(20), default="manual")  # manual | scan_finding
    status = Column(String(20), default="draft")  # draft | exported

    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    vendor = Column(String(200), default="Unknown")
    product = Column(String(200))
    versions_affected = Column(JSON)   # [{"version": "...", "status": "affected", "lessThan": "..."}]
    problem_type = Column(String(200))  # e.g. "CWE-79 Cross-Site Scripting (XSS)"
    severity = Column(String(20))       # critical | high | medium | low
    cvss_vector = Column(String(120))
    cvss_score = Column(String(10))
    references = Column(JSON)           # ["https://..."]
    credits = Column(JSON)              # [{"name": "...", "type": "finder"}]

    reporter_name = Column(String(200))
    reporter_email = Column(String(200))
    cna_org = Column(String(200))       # informational only — no live submission is performed

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    exported_at = Column(DateTime)

    user = relationship("User")
    finding = relationship("Finding")


class SchedulerLock(Base):
    """Single-row-per-job lock so periodic tasks (e.g. the dark web scan
    sweep in modules/darkweb/scheduler.py) never run concurrently across
    multiple uvicorn workers/instances (Render runs 2 workers). Acquired via
    an atomic conditional UPDATE keyed on `job_name`; `locked_at` older than
    the caller's staleness threshold is treated as free, so a crashed holder
    can never deadlock the job forever."""
    __tablename__ = "scheduler_locks"

    job_name = Column(String(100), primary_key=True)
    locked_at = Column(DateTime)
    locked_by = Column(String(100))
