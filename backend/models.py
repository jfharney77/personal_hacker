"""SQLModel tables for targets, scans, findings, and suppressions."""
# NOTE: deliberately NO `from __future__ import annotations` — SQLAlchemy/SQLModel
# can't resolve relationship generics (list["Scan"]) when annotations are strings.
from datetime import datetime, timezone

from sqlalchemy import JSON, Column
from sqlmodel import Field, Relationship, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Target(SQLModel, table=True):
    """A project to scan: how to reach it (URLs) and/or where its source is (repo_path)."""

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    allowlist: list = Field(default_factory=list, sa_column=Column(JSON))
    target_urls: list = Field(default_factory=list, sa_column=Column(JSON))
    repo_path: str | None = None
    safe_mode: bool = True
    offline: bool = False
    ssrf_canary: bool = False
    i_own_this: bool = False
    llm_provider: str = "claude"
    llm_model: str | None = None
    # Optional auth block, shaped like config.AuthConfig (login_url, identities, ...).
    auth: dict | None = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utcnow)

    scans: list["Scan"] = Relationship(
        back_populates="target", sa_relationship_kwargs={"cascade": "all, delete-orphan"})


class Scan(SQLModel, table=True):
    """One execution of the engine against a target."""

    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    status: str = "pending"  # pending | running | done | error
    error: str | None = None
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    # Denormalized severity counts for fast dashboard/trend rendering.
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    suppressed_count: int = 0

    target: Target | None = Relationship(back_populates="scans")
    findings: list["Finding"] = Relationship(
        back_populates="scan", sa_relationship_kwargs={"cascade": "all, delete-orphan"})


class Finding(SQLModel, table=True):
    """A persisted finding from a scan."""

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    fingerprint: str = Field(index=True)
    threat_class: str
    method: str
    severity: str = Field(index=True)
    title: str
    detail: str
    location: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    cross_validated: bool = False
    suppressed: bool = False

    scan: Scan | None = Relationship(back_populates="findings")


class Suppression(SQLModel, table=True):
    """A fingerprint muted across future scans (accepted risk / false positive)."""

    id: int | None = Field(default=None, primary_key=True)
    fingerprint: str = Field(index=True, unique=True)
    reason: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
