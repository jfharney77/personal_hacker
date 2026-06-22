"""Baseline diff + CI gating."""
from hacker.baseline import load_baseline_keys, new_findings, write_baseline
from hacker.cli import main
from hacker.models import Finding, Method, ScanReport, Severity, ThreatClass


def _finding(title, sev=Severity.HIGH, loc="x"):
    return Finding(threat_class=ThreatClass.CREDENTIALS, method=Method.STATIC,
                   severity=sev, title=title, detail="d", location=loc)


def test_new_findings_excludes_baselined(tmp_path):
    old = ScanReport(findings=[_finding("A"), _finding("B")])
    base = tmp_path / "base.json"
    write_baseline(old, base)

    current = ScanReport(findings=[_finding("A"), _finding("C")])  # B fixed, C is new
    keys = load_baseline_keys(base)
    fresh = new_findings(current, keys)
    titles = {f.title for f in fresh}
    assert titles == {"C"}


def test_missing_baseline_means_everything_is_new(tmp_path):
    keys = load_baseline_keys(tmp_path / "nope.json")
    assert keys == set()
    current = ScanReport(findings=[_finding("A")])
    assert len(new_findings(current, keys)) == 1


def test_fingerprint_stable_across_evidence_changes():
    a = _finding("Same title")
    b = _finding("Same title")
    b.evidence = "different evidence text"
    assert a.fingerprint == b.fingerprint


def test_fingerprint_ignores_line_numbers_and_query_values():
    a = _finding("SQL injection", loc="app/db.py:17")
    b = _finding("SQL injection", loc="app/db.py:42")  # moved by a refactor
    assert a.fingerprint == b.fingerprint
    c = _finding("SQL injection", loc="http://x/users?name=alice")
    d = _finding("SQL injection", loc="http://x/users?name=bob")
    assert c.fingerprint == d.fingerprint


def test_cli_fail_on_gates_only_new_findings(tmp_path, monkeypatch):
    """End-to-end CLI: with a baseline covering the existing High, the gate passes;
    without a baseline it fails."""
    import hacker.cli as cli

    report = ScanReport(findings=[_finding("Pre-existing high", Severity.HIGH)])
    monkeypatch.setattr(cli, "run_scan", lambda scope, **kw: report)
    monkeypatch.setattr(cli, "load_scope", lambda p: _DummyScope())

    base = tmp_path / "base.json"
    write_baseline(report, base)

    # No baseline → the High trips the gate → exit 1.
    assert main(["--scope", "x", "--fail-on", "high"]) == 1
    # Baseline contains that same High → no NEW findings → exit 0.
    assert main(["--scope", "x", "--fail-on", "high", "--baseline", str(base)]) == 0


class _DummyScope:
    i_own_this = False
