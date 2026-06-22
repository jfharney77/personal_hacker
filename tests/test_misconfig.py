"""Security headers / CORS / TLS posture module."""
from hacker.config import Scope
from hacker.models import Severity
from hacker.modules import misconfig
from hacker.recon import run_recon


def _scope():
    return Scope(allowlist=["localhost"], target_urls=["http://localhost"])


def test_flags_permissive_cors_with_credentials(vuln_client):
    scope = _scope()
    recon = run_recon(scope, "http://localhost", client=vuln_client)
    findings = misconfig.run_dynamic(scope, recon, vuln_client)
    assert any(f.title == "Permissive CORS with credentials" and f.severity == Severity.HIGH
               for f in findings)


def test_flags_missing_security_headers(vuln_client):
    scope = _scope()
    recon = run_recon(scope, "http://localhost", client=vuln_client)
    titles = {f.title for f in misconfig.run_dynamic(scope, recon, vuln_client)}
    assert any("Content-Security-Policy" in t for t in titles)


def test_hardened_has_no_medium_or_higher(hardened_client):
    scope = _scope()
    recon = run_recon(scope, "http://localhost", client=hardened_client)
    findings = misconfig.run_dynamic(scope, recon, hardened_client)
    bad = [f for f in findings if f.severity.rank() >= Severity.MEDIUM.rank()]
    assert bad == [], [f.title for f in bad]


def test_tls_skipped_for_http(vuln_client):
    # http target must not attempt a TLS handshake (no crash, no TLS findings).
    scope = _scope()
    recon = run_recon(scope, "http://localhost", client=vuln_client)
    findings = misconfig.run_dynamic(scope, recon, vuln_client)
    assert not any("TLS" in f.title or "certificate" in f.title.lower() for f in findings)
