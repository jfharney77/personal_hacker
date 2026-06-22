"""Structured data model shared by every attack module and the report renderer."""
from __future__ import annotations

import enum
import hashlib
import re
from datetime import datetime, timezone

from pydantic import BaseModel, Field, computed_field


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
    ACCESS_CONTROL = "broken_access_control"
    INPUT_ABUSE = "server_side_request_and_path_abuse"
    MISCONFIGURATION = "security_misconfiguration"
    SUPPLY_CHAIN = "supply_chain"


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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """A stable identity for this finding across runs.

        Deliberately excludes volatile detail (line numbers, latency deltas, nonces,
        query-string values) so a cosmetic code change doesn't make a known finding look
        new — and so a baseline/suppression entry keeps matching after a refactor.
        """
        return _fingerprint(self.threat_class.value, self.title, self.location)

    def sort_key(self) -> tuple[int, str]:
        return (-self.severity.rank(), self.threat_class.value)


def _normalize_location(location: str | None) -> str:
    """Strip the volatile parts of a location: query strings and trailing line numbers."""
    if not location:
        return ""
    loc = location.split("?", 1)[0]          # drop query string (param values vary)
    loc = re.sub(r":\d+$", "", loc)           # drop trailing :<line> from "file.py:17"
    return loc.rstrip("/")


def _fingerprint(threat_class: str, title: str, location: str | None) -> str:
    raw = f"{threat_class}|{title}|{_normalize_location(location)}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


class ScanReport(BaseModel):
    """The full output of a scan run."""

    target_repo: str | None = None
    target_urls: list[str] = Field(default_factory=list)
    safe_mode: bool = True
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = Field(default_factory=list)
    # Findings dropped by the suppression list — kept for audit, excluded from gating.
    suppressed: list[Finding] = Field(default_factory=list)

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    def apply_suppressions(self, fingerprints: set[str]) -> None:
        """Move any finding whose fingerprint is suppressed out of `findings`."""
        if not fingerprints:
            return
        keep, dropped = [], []
        for f in self.findings:
            (dropped if f.fingerprint in fingerprints else keep).append(f)
        self.findings = keep
        self.suppressed.extend(dropped)

    def ranked(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
