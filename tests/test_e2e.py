"""End-to-end: the full pipeline finds all five threat classes in the vulnerable
app, cross-validates SAST+DAST, and produces a clean report on the hardened app."""
from pathlib import Path

from hacker.config import AuthConfig, Identity, Scope
from hacker.graph import run_scan
from hacker.models import Severity, ThreatClass
from hacker.report import render_markdown

VULN_REPO = str(Path(__file__).parent / "fixtures" / "vulnerable_app")
HARDENED_REPO = str(Path(__file__).parent / "fixtures" / "hardened_app")

# The five classes reachable without logging in (access control needs auth).
_UNAUTH_CLASSES = [tc for tc in ThreatClass if tc != ThreatClass.ACCESS_CONTROL]


def _auth():
    return AuthConfig(
        login_url="http://localhost/auth/login",
        token_json_path="token", token_header="X-Session-Token",
        identities=[Identity(name="alice", body={"username": "alice"}),
                    Identity(name="bob", body={"username": "bob"})],
    )


def test_full_scan_covers_all_five_classes(local_scope, vuln_client):
    scope = Scope(allowlist=["localhost"], target_urls=["http://localhost"], repo_path=VULN_REPO)
    report = run_scan(scope, client=vuln_client)

    found = {f.threat_class for f in report.findings}
    for tc in _UNAUTH_CLASSES:
        assert tc in found, f"missing findings for {tc}"


def test_authenticated_scan_finds_access_control(vuln_client):
    scope = Scope(allowlist=["localhost"], target_urls=["http://localhost"],
                  repo_path=VULN_REPO, auth=_auth())
    report = run_scan(scope, client=vuln_client)
    found = {f.threat_class for f in report.findings}
    for tc in ThreatClass:
        assert tc in found, f"missing findings for {tc}"

    # At least one Critical (the SQL injection / exposed env).
    assert any(f.severity == Severity.CRITICAL for f in report.findings)

    # DB injection appears in both SAST and DAST → cross-validated.
    db = [f for f in report.findings if f.threat_class == ThreatClass.DB_INJECTION]
    assert any(f.cross_validated for f in db)

    # Report renders without error and is ranked Critical-first.
    md = render_markdown(report)
    assert "Security Report" in md
    assert report.ranked()[0].severity == Severity.CRITICAL


def test_hardened_app_has_no_high_severity(hardened_client):
    scope = Scope(allowlist=["localhost"], target_urls=["http://localhost"], repo_path=HARDENED_REPO)
    report = run_scan(scope, client=hardened_client)
    high = [f for f in report.findings if f.severity.rank() >= Severity.HIGH.rank()]
    assert not high, f"false positives on hardened app: {[f.title for f in high]}"


def test_scan_refuses_out_of_scope_target():
    import pytest
    from hacker.config import ScopeError
    scope = Scope(allowlist=["localhost"], target_urls=["http://localhost"])
    # Sneak an out-of-scope URL past validate_self by adding it after construction.
    scope.target_urls.append("http://evil.example.com")
    with pytest.raises(ScopeError):
        run_scan(scope)
