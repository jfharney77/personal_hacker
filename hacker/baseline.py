"""Baseline + diff: gate CI on *newly introduced* findings, not the whole backlog.

A baseline is just a saved ScanReport JSON. We fingerprint each finding by
(threat_class, title, location) so the same issue matches across runs even if
evidence/latency text changes slightly. `new_findings()` returns the findings
present now but absent from the baseline.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, ScanReport

FindingKey = tuple[str, str, str]


def finding_key(f: Finding) -> FindingKey:
    return (f.threat_class.value, f.title, f.location or "")


def load_baseline_keys(path: str | Path) -> set[FindingKey]:
    """Load a saved report JSON and return the set of finding fingerprints.

    A missing baseline file is treated as an empty baseline (first run → all new).
    """
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    report = ScanReport.model_validate(data)
    return {finding_key(f) for f in report.findings}


def new_findings(report: ScanReport, baseline_keys: set[FindingKey]) -> list[Finding]:
    """Findings in `report` that aren't in the baseline, ranked worst-first."""
    fresh = [f for f in report.findings if finding_key(f) not in baseline_keys]
    return sorted(fresh, key=lambda f: f.sort_key())


def write_baseline(report: ScanReport, path: str | Path) -> None:
    Path(path).write_text(report.model_dump_json(indent=2))
