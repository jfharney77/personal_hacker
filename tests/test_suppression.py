"""Suppression: accepted-risk / false-positive findings are moved out of the report."""
from hacker.config import Scope
from hacker.models import Finding, Method, ScanReport, Severity, ThreatClass


def _finding(title, loc="x"):
    return Finding(threat_class=ThreatClass.CREDENTIALS, method=Method.STATIC,
                   severity=Severity.HIGH, title=title, detail="d", location=loc)


def test_apply_suppressions_moves_matching_findings():
    keep = _finding("Keep me")
    drop = _finding("Mute me")
    report = ScanReport(findings=[keep, drop])
    report.apply_suppressions({drop.fingerprint})

    assert [f.title for f in report.findings] == ["Keep me"]
    assert [f.title for f in report.suppressed] == ["Mute me"]


def test_empty_suppression_is_noop():
    report = ScanReport(findings=[_finding("A")])
    report.apply_suppressions(set())
    assert len(report.findings) == 1
    assert report.suppressed == []


def test_scope_carries_suppressions():
    s = Scope(allowlist=["localhost"], target_urls=["http://localhost"], suppress=["abc123"])
    assert s.suppress == ["abc123"]
