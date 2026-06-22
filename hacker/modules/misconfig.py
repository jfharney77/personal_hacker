"""Threat class — security misconfiguration (headers / CORS / TLS).

Passive: reasons over the headers recon already captured, adds one CORS preflight
and (for https targets) one TLS handshake. Near-zero false positives, so severities
are kept deliberately low to sit beneath real exploits in the report.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from ..config import Scope
from ..models import Finding, Method, Severity, ThreatClass

TC = ThreatClass.MISCONFIGURATION
_ATTACKER_ORIGIN = "https://attacker.example"

# (header, severity if missing, human note)
_HEADER_RULES = [
    ("content-security-policy", Severity.MEDIUM, "Content-Security-Policy"),
    ("strict-transport-security", Severity.MEDIUM, "Strict-Transport-Security (HSTS)"),
    ("x-content-type-options", Severity.LOW, "X-Content-Type-Options: nosniff"),
    ("x-frame-options", Severity.LOW, "X-Frame-Options (clickjacking)"),
    ("referrer-policy", Severity.INFO, "Referrer-Policy"),
]


def run_dynamic(scope: Scope, recon: Recon, client: httpx.Client) -> list[Finding]:  # type: ignore[name-defined]
    findings: list[Finding] = []
    headers = {k.lower(): v for k, v in recon.baseline_headers.items()}
    is_https = recon.base_url.lower().startswith("https://")

    findings.extend(_header_findings(headers, recon.base_url, is_https))
    findings.extend(_cors_findings(scope, recon, client))
    if is_https:
        findings.extend(_tls_findings(recon.base_url))
    return findings


def _header_findings(headers: dict, base_url: str, is_https: bool) -> list[Finding]:
    out: list[Finding] = []
    for name, sev, label in _HEADER_RULES:
        if name == "strict-transport-security" and not is_https:
            continue  # HSTS only meaningful over https
        if name not in headers:
            out.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=sev,
                title=f"Missing security header: {label}", location=base_url,
                detail=f"The response did not set {label}.",
                remediation=f"Set {label} on all responses."))
        elif name == "content-security-policy" and ("unsafe-inline" in headers[name] or "*" in headers[name]):
            out.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.LOW,
                title="Weak Content-Security-Policy", location=base_url,
                evidence=headers[name][:120],
                detail="CSP allows unsafe-inline or wildcard sources, weakening XSS protection.",
                remediation="Remove unsafe-inline/wildcards; use nonces or hashes."))
    # Version fingerprinting.
    for h in ("server", "x-powered-by"):
        if h in headers and any(c.isdigit() for c in headers[h]):
            out.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.INFO,
                title=f"Version disclosure via {h}", location=base_url, evidence=headers[h],
                detail="The response advertises an exact software version, aiding attackers.",
                remediation=f"Suppress or genericize the {h} header."))
    return out


def _cors_findings(scope: Scope, recon: Recon, client: httpx.Client) -> list[Finding]:  # type: ignore[name-defined]
    try:
        r = client.get(scope.guard(recon.base_url + "/"),
                       headers={"Origin": _ATTACKER_ORIGIN})
    except httpx.HTTPError:
        return []
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    reflects = acao == _ATTACKER_ORIGIN or acao == "*"
    if reflects and acac:
        return [Finding(
            threat_class=TC, method=Method.DYNAMIC, severity=Severity.HIGH,
            title="Permissive CORS with credentials", location=recon.base_url,
            evidence=f"Allow-Origin: {acao!r}; Allow-Credentials: true",
            detail="The server reflects an arbitrary Origin AND allows credentials, letting any "
                   "site make authenticated cross-origin requests on a victim's behalf.",
            remediation="Echo only a vetted allowlist of origins; never combine reflected/`*` "
                        "origin with Allow-Credentials: true.")]
    if acao == _ATTACKER_ORIGIN:
        return [Finding(
            threat_class=TC, method=Method.DYNAMIC, severity=Severity.MEDIUM,
            title="Reflective CORS origin", location=recon.base_url,
            evidence=f"Allow-Origin reflected: {acao!r}",
            detail="The server reflects the request Origin in Access-Control-Allow-Origin.",
            remediation="Restrict Access-Control-Allow-Origin to an explicit allowlist.")]
    return []


def _tls_findings(base_url: str) -> list[Finding]:
    split = urlsplit(base_url)
    host, port = split.hostname, split.port or 443
    if not host:
        return []
    out: list[Finding] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we inspect the cert ourselves rather than reject
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                version = ss.version()
    except (OSError, ssl.SSLError):
        return []

    if version and version.replace("v", "").replace(".", "") and version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding(
            threat_class=TC, method=Method.DYNAMIC, severity=Severity.HIGH,
            title=f"Weak TLS version negotiated ({version})", location=base_url,
            detail="The server negotiated an obsolete TLS/SSL version.",
            remediation="Require TLS 1.2+ and disable older protocols."))

    not_after = (cert or {}).get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days
            if days < 0:
                out.append(_tls_finding("Expired TLS certificate", Severity.HIGH, base_url,
                                        f"expired {-days} days ago"))
            elif days < 14:
                out.append(_tls_finding("TLS certificate expiring soon", Severity.MEDIUM, base_url,
                                        f"expires in {days} days"))
        except ValueError:
            pass
    return out


def _tls_finding(title, sev, base_url, evidence) -> Finding:
    return Finding(threat_class=TC, method=Method.DYNAMIC, severity=sev, title=title,
                   location=base_url, evidence=evidence,
                   detail="TLS certificate problem detected during the handshake.",
                   remediation="Renew/rotate the certificate and automate renewal.")
