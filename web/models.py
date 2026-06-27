from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey
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
