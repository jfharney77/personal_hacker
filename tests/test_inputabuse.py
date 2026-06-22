"""SSRF / path traversal / open redirect module."""
from pathlib import Path

from hacker.models import Severity, ThreatClass
from hacker.modules import inputabuse
from hacker.modules.inputabuse import SSRFCanary
from hacker.recon import run_recon

VULN_REPO = str(Path(__file__).parent / "fixtures" / "vulnerable_app")
HARD_REPO = str(Path(__file__).parent / "fixtures" / "hardened_app")


def test_static_flags_all_three_patterns():
    titles = {f.title for f in inputabuse.run_static(VULN_REPO)}
    assert any("SSRF" in t for t in titles)
    assert any("traversal" in t.lower() for t in titles)
    assert any("redirect" in t.lower() for t in titles)


def test_static_clean_on_hardened():
    highs = [f for f in inputabuse.run_static(HARD_REPO) if f.severity.rank() >= Severity.HIGH.rank()]
    assert highs == [], [f.location for f in highs]


def test_dynamic_open_redirect(local_scope, vuln_client):
    recon = run_recon(local_scope, "http://localhost", client=vuln_client)
    findings = inputabuse.run_dynamic(local_scope, recon, vuln_client)
    assert any(f.title == "Open redirect" for f in findings)


def test_dynamic_path_traversal(local_scope, vuln_client):
    recon = run_recon(local_scope, "http://localhost", client=vuln_client)
    findings = inputabuse.run_dynamic(local_scope, recon, vuln_client)
    assert any(f.title == "Path traversal" and f.severity == Severity.CRITICAL for f in findings)


def test_dynamic_ssrf_confirmed_via_canary(local_scope, vuln_client):
    recon = run_recon(local_scope, "http://localhost", client=vuln_client)
    with SSRFCanary() as canary:
        findings = inputabuse.run_dynamic(local_scope, recon, vuln_client, canary=canary)
    assert any(f.title.startswith("SSRF") and f.severity == Severity.CRITICAL for f in findings)


def test_dynamic_clean_on_hardened(hardened_client):
    from hacker.config import Scope
    scope = Scope(allowlist=["localhost"], target_urls=["http://localhost"])
    recon = run_recon(scope, "http://localhost", client=hardened_client)
    with SSRFCanary() as canary:
        findings = inputabuse.run_dynamic(scope, recon, hardened_client, canary=canary)
    assert all(f.threat_class != ThreatClass.INPUT_ABUSE or f.severity.rank() < Severity.HIGH.rank()
               for f in findings), [f.title for f in findings]
