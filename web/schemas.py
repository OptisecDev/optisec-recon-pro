"""Pydantic request/response schemas for OPTISEC API."""
from __future__ import annotations
from typing import Any, List, Optional
from pydantic import BaseModel, Field, field_validator
import re


# ─── Generic ──────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Invalid credentials")


class SuccessResponse(BaseModel):
    success: bool = Field(True, example=True)
    message: Optional[str] = Field(None, example="Operation completed")


# ─── Auth ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, example="admin",
                          description="Username or email address")
    password: str = Field(..., min_length=1, example="Optisec123!",
                          description="Account password")


class LoginResponse(BaseModel):
    access_token: str = Field(..., description="JWT bearer token (30-min expiry)")
    token_type: str = Field("bearer", example="bearer")
    user: UserShort


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example="analyst1",
                          description="3–50 characters, alphanumeric + underscore")
    email: str = Field(..., example="analyst@optisec.io")
    password: str = Field(..., min_length=8, example="StrongPass1!",
                          description="Min 8 chars, must include uppercase, digit, special char")


class RegisterResponse(BaseModel):
    id: int
    username: str
    role: str = Field(..., example="viewer")
    api_key: str = Field(..., description="64-char API key for programmatic access")


class APIKeyResponse(BaseModel):
    api_key: str = Field(..., description="New 64-char API key")


# ─── Users (shared) ───────────────────────────────────────────────────────────

class UserShort(BaseModel):
    id: int
    username: str
    role: str = Field(..., example="admin",
                      description="One of: admin | analyst | viewer")


class UserDetail(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: Optional[str]
    last_login: Optional[str]


# ─── Targets ──────────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    url: str = Field(..., example="https://tesla.com",
                     description="Target URL or domain (required)")
    name: str = Field("", example="Tesla Main",
                      description="Friendly name (optional)")
    notes: str = Field("", description="Free-text notes")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL is required")
        return v


class TargetResponse(BaseModel):
    id: int
    url: str
    name: str
    created_at: Optional[str]


# ─── Scans ────────────────────────────────────────────────────────────────────

SCAN_TYPES = ["subdomain", "dns", "whois", "nmap", "ssl", "headers",
              "ports", "xss", "sqli", "ssrf", "lfi", "redirect", "osint"]


class ScanRequest(BaseModel):
    target: str = Field(..., example="tesla.com",
                        description="Domain or URL to scan")
    scan_types: List[str] = Field(
        default=[],
        example=["xss", "sqli", "subdomain"],
        description=f"Subset of scan modules to run. Leave empty to run all. "
                    f"Available: {', '.join(SCAN_TYPES)}"
    )
    target_id: Optional[int] = Field(None, description="Link to existing Target record")


class ScanLaunchResponse(BaseModel):
    scan_id: str = Field(..., example="scan_a3f2b1c9d4e5f678",
                         description="Unique scan ID for polling /api/scan/{{scan_id}}")


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str = Field(..., example="running",
                        description="One of: pending | running | done | failed")
    progress: int = Field(..., ge=0, le=100, example=58, description="Completion %")
    target: str
    results: dict = Field({}, description="Partial or final module results keyed by module name")
    error: Optional[str]
    created_at: Optional[str]
    completed_at: Optional[str]


class ScanListItem(BaseModel):
    id: str
    target: str
    status: str
    progress: int
    created_at: Optional[str]


# ─── Findings ─────────────────────────────────────────────────────────────────

class FindingResponse(BaseModel):
    id: int
    scan_id: str
    type: str = Field(..., example="XSS", description="Vulnerability type")
    severity: str = Field(..., example="high",
                          description="One of: critical | high | medium | low | info")
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: Optional[str]


# ─── NLP ──────────────────────────────────────────────────────────────────────

class NLPRequest(BaseModel):
    text: str = Field(..., example="افحص tesla.com عن ثغرات XSS",
                      description="Natural-language command in Arabic or English")


class NLPResponse(BaseModel):
    action: str = Field(..., example="scan",
                        description="Parsed action: scan | subdomain | osint | report | unknown")
    target: Optional[str] = Field(None, example="tesla.com")
    scan_type: Optional[str] = Field(None, example="xss")
    raw: str = Field(..., description="Original input text")


# ─── AI Analyze ───────────────────────────────────────────────────────────────

class AIAnalyzeRequest(BaseModel):
    scan_id: str = Field(..., example="scan_a3f2b1c9d4e5f678",
                         description="Scan ID whose results should be analyzed")
    model: Optional[str] = Field(None, example="llama3-70b-8192",
                                 description="Groq model override (optional)")


class AIAnalyzeResponse(BaseModel):
    scan_id: str
    analysis: str = Field(..., description="Markdown-formatted AI security analysis")
    model: str = Field(..., description="Groq model used")
    tokens_used: Optional[int]


# ─── Quick Scan utilities ─────────────────────────────────────────────────────

class HeadersScanRequest(BaseModel):
    url: str = Field(..., example="https://example.com")


class PortsScanRequest(BaseModel):
    host: str = Field(..., example="192.168.1.1")
    ports: Optional[str] = Field(None, example="80,443,8080",
                                 description="Comma-separated ports; leave blank for top-1000")


class SSLScanRequest(BaseModel):
    domain: str = Field(..., example="example.com")


# ─── Reports ──────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    scan_id: str = Field(..., example="scan_a3f2b1c9d4e5f678")
    title: Optional[str] = Field(None, example="Q2 Security Assessment")


class ReportResponse(BaseModel):
    report_id: int
    filename: str
    download_url: str


# ─── Admin ────────────────────────────────────────────────────────────────────

class UserPatch(BaseModel):
    role: Optional[str] = Field(None, example="analyst",
                                description="One of: admin | analyst | viewer")
    is_active: Optional[bool] = Field(None)
