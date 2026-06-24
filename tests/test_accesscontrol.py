"""Auth-aware scanning + the broken-access-control (IDOR / mass-assignment) module."""
from hacker.auth import authenticate_all
from hacker.config import AuthConfig, Identity, Scope
from hacker.models import Severity, ThreatClass
from hacker.modules import accesscontrol
from hacker.recon import run_recon


def _auth_scope(repo=None):
    return Scope(
        allowlist=["localhost"],
        target_urls=["http://localhost"],
        repo_path=repo,
        auth=AuthConfig(
            login_url="http://localhost/auth/login",
            token_json_path="token",
            token_header="X-Session-Token",
            identities=[
                Identity(name="alice", body={"username": "alice"}),
                Identity(name="bob", body={"username": "bob"}),
            ],
        ),
    )


def test_authenticate_all_logs_in_both_identities(vuln_client):
    sessions = authenticate_all(_auth_scope(), vuln_client)
    assert len(sessions) == 2
    assert all(s.authenticated for s in sessions)
    assert sessions[0].headers["X-Session-Token"] == "token-alice"


def test_idor_detected_on_vulnerable_app(vuln_client):
    scope = _auth_scope()
    sessions = authenticate_all(scope, vuln_client)
    recon = run_recon(scope, "http://localhost", client=vuln_client)
    findings = accesscontrol.run_dynamic(scope, recon, vuln_client, sessions=sessions)
    assert any("IDOR" in f.title and f.severity == Severity.CRITICAL for f in findings)


def test_mass_assignment_detected_on_vulnerable_app(vuln_client):
    scope = _auth_scope()
    sessions = authenticate_all(scope, vuln_client)
    recon = run_recon(scope, "http://localhost", client=vuln_client)
    findings = accesscontrol.run_dynamic(scope, recon, vuln_client, sessions=sessions)
    assert any("Mass-assignment" in f.title for f in findings)


def test_vertical_privilege_escalation_detected_on_vulnerable_app(vuln_client):
    scope = _auth_scope()
    sessions = authenticate_all(scope, vuln_client)
    recon = run_recon(scope, "http://localhost", client=vuln_client)
    findings = accesscontrol.run_dynamic(scope, recon, vuln_client, sessions=sessions)
    assert any("Vertical privilege escalation" in f.title for f in findings)


def test_no_access_control_findings_without_auth(vuln_client):
    # No sessions → module must be a no-op (never guesses).
    scope = Scope(allowlist=["localhost"], target_urls=["http://localhost"])
    recon = run_recon(scope, "http://localhost", client=vuln_client)
    assert accesscontrol.run_dynamic(scope, recon, vuln_client, sessions=[]) == []


def test_hardened_app_has_no_access_control_findings(hardened_client):
    scope = _auth_scope()
    sessions = authenticate_all(scope, hardened_client)
    recon = run_recon(scope, "http://localhost", client=hardened_client)
    findings = accesscontrol.run_dynamic(scope, recon, hardened_client, sessions=sessions)
    assert findings == [], [f.title for f in findings]
