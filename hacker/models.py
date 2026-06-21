"""Structured data model shared by every attack module and the report renderer."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    """Ordered severity levels. `rank()` gives a sortable integer (higher = worse)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def rank(self) -> int:
        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ThreatClass(str, enum.Enum):
    """The five threat classes this tool targets."""

    CREDENTIALS = "credential_extraction"
    SESSIONS = "session_hijacking"
    DOS = "denial_of_service"
    DB_INJECTION = "database_injection"
    PROMPT_INJECTION = "prompt_injection"


class Method(str, enum.Enum):
    STATIC = "static"   # SAST — read the repo
    DYNAMIC = "dynamic"  # DAST — probe the running app


class Finding(BaseModel):
    """A single security finding produced by a module."""

    threat_class: ThreatClass
    method: Method
    severity: Severity
    title: str
    detail: str
    # Where it was found: a file path (static) or a URL/endpoint (dynamic).
    location: str | None = None
    # Raw evidence (matched line, response snippet, header value) — never secrets in full.
    evidence: str | None = None
    # Concrete fix, ideally referencing one of the user's defensive skills.
    remediation: str | None = None
    # True once a static finding is confirmed by a dynamic probe (or vice versa).
    cross_validated: bool = False

    def sort_key(self) -> tuple[int, str]:
        return (-self.severity.rank(), self.threat_class.value)


class ScanReport(BaseModel):
    """The full output of a scan run."""

    target_repo: str | None = None
    target_urls: list[str] = Field(default_factory=list)
    safe_mode: bool = True
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = Field(default_factory=list)

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    def ranked(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
