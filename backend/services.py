"""Bridge the scanning engine (hacker/) to the persistence layer."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import Session, select

from hacker.config import AuthConfig, Scope
from hacker.graph import run_scan
from hacker.models import Finding as EngineFinding

from .db import get_engine
from .models import Finding, Scan, Suppression, Target


def target_to_scope(target: Target, suppress: list[str]) -> Scope:
    """Translate a stored Target (+ global suppressions) into an engine Scope."""
    return Scope(
        allowlist=list(target.allowlist or []),
        target_urls=list(target.target_urls or []),
        repo_path=target.repo_path,
        safe_mode=target.safe_mode,
        offline=target.offline,
        ssrf_canary=target.ssrf_canary,
        i_own_this=target.i_own_this,
        llm_provider=target.llm_provider,
        llm_model=target.llm_model,
        auth=AuthConfig(**target.auth) if target.auth else None,
        suppress=suppress,
    )


def _persist_finding(scan_id: int, ef: EngineFinding, suppressed: bool) -> Finding:
    return Finding(
        scan_id=scan_id,
        fingerprint=ef.fingerprint,
        threat_class=ef.threat_class.value,
        method=ef.method.value,
        severity=ef.severity.value,
        title=ef.title,
        detail=ef.detail,
        location=ef.location,
        evidence=ef.evidence,
        remediation=ef.remediation,
        cross_validated=ef.cross_validated,
        suppressed=suppressed,
    )


def run_scan_for(scan_id: int) -> None:
    """Execute a scan (engine call), persisting status, findings, and severity counts.

    Designed to run in a background task: it owns its own DB session.
    """
    with Session(get_engine()) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        target = session.get(Target, scan.target_id)
        if target is None:
            scan.status = "error"
            scan.error = "target not found"
            session.add(scan)
            session.commit()
            return

        scan.status = "running"
        session.add(scan)
        session.commit()

        suppress = [s.fingerprint for s in session.exec(select(Suppression)).all()]
        try:
            report = run_scan(target_to_scope(target, suppress))
        except Exception as e:  # never let a scan failure crash the server
            scan.status = "error"
            scan.error = str(e)[:500]
            scan.finished_at = datetime.now(timezone.utc)
            session.add(scan)
            session.commit()
            return

        for ef in report.findings:
            session.add(_persist_finding(scan_id, ef, suppressed=False))
        for ef in report.suppressed:
            session.add(_persist_finding(scan_id, ef, suppressed=True))

        counts = report.counts()
        scan.total = len(report.findings)
        scan.critical = counts["critical"]
        scan.high = counts["high"]
        scan.medium = counts["medium"]
        scan.low = counts["low"]
        scan.info = counts["info"]
        scan.suppressed_count = len(report.suppressed)
        scan.status = "done"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
