"""Each module must find its planted vulnerability in the fixture app."""
from pathlib import Path

from hacker.models import Severity, ThreatClass
from hacker.modules import credentials, dbinjection, dos, promptinjection, sessions
from hacker.recon import run_recon

FIXTURE_REPO = str(Path(__file__).parent / "fixtures" / "vulnerable_app")


def _recon(scope, client):
    return run_recon(scope, "http://localhost", client=client)


# ---- class 1: credentials ----
def test_credentials_static_finds_hardcoded_secret():
    findings = credentials.run_static(FIXTURE_REPO)
    assert any("Hardcoded secret" in f.title for f in findings)


def test_credentials_dynamic_finds_exposed_env(local_scope, vuln_client):
    recon = _recon(local_scope, vuln_client)
    findings = credentials.run_dynamic(local_scope, recon, vuln_client)
    assert any(".env" in f.title and f.severity == Severity.CRITICAL for f in findings)


# ---- class 2: sessions ----
def test_sessions_finds_insecure_cookie(local_scope, vuln_client):
    recon = _recon(local_scope, vuln_client)
    findings = sessions.run_dynamic(local_scope, recon, vuln_client)
    assert any("missing" in f.title.lower() for f in findings)


def test_sessions_finds_token_in_url(local_scope, vuln_client):
    recon = _recon(local_scope, vuln_client)
    findings = sessions.run_dynamic(local_scope, recon, vuln_client)
    assert any("token via URL" in f.title for f in findings)


# ---- class 3: dos ----
def test_dos_static_flags_missing_rate_limit():
    findings = dos.run_static(FIXTURE_REPO)
    assert any("No rate limiting" in f.title for f in findings)


def test_dos_dynamic_observes_no_throttle(local_scope, vuln_client):
    recon = _recon(local_scope, vuln_client)
    findings = dos.run_dynamic(local_scope, recon, vuln_client)
    assert any("No rate limiting observed" in f.title for f in findings)


# ---- class 4: db injection ----
def test_dbinjection_static_finds_raw_sql():
    findings = dbinjection.run_static(FIXTURE_REPO)
    assert any(f.threat_class == ThreatClass.DB_INJECTION for f in findings)


def test_dbinjection_dynamic_confirms_injection(local_scope, vuln_client):
    recon = _recon(local_scope, vuln_client)
    findings = dbinjection.run_dynamic(local_scope, recon, vuln_client)
    assert any(f.severity == Severity.CRITICAL for f in findings)


# ---- class 5: prompt injection ----
def test_promptinjection_finds_leak(local_scope, vuln_client):
    recon = _recon(local_scope, vuln_client)
    findings = promptinjection.run_dynamic(local_scope, recon, vuln_client)
    assert any(f.threat_class == ThreatClass.PROMPT_INJECTION for f in findings)
