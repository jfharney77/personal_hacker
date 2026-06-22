"""Baseline + diff: gate CI on *newly introduced* findings, not the whole backlog.

A baseline is just a saved ScanReport JSON. We match findings across runs by their
stable `Finding.fingerprint` (which ignores line numbers, latency text, and query
values), so the same issue keeps matching after a cosmetic refactor. `new_findings()`
returns the findings present now but absent from the baseline.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, ScanReport


def load_baseline_keys(path: str | Path) -> set[str]:
    """Load a saved report JSON and return the set of finding fingerprints.

    A missing baseline file is treated as an empty baseline (first run → all new).
    """
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    report = ScanReport.model_validate(data)
    return {f.fingerprint for f in report.findings}


def new_findings(report: ScanReport, baseline_keys: set[str]) -> list[Finding]:
    """Findings in `report` that aren't in the baseline, ranked worst-first."""
    fresh = [f for f in report.findings if f.fingerprint not in baseline_keys]
    return sorted(fresh, key=lambda f: f.sort_key())


def write_baseline(report: ScanReport, path: str | Path) -> None:
    Path(path).write_text(report.model_dump_json(indent=2))
