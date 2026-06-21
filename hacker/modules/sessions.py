"""Threat class 2 — session hijacking.

DAST: inspect Set-Cookie flags, detect tokens passed via URL, decode JWTs and
test for `alg:none` and weak signing secrets.
SAST: flag session tokens read from query params instead of headers.
"""
from __future__ import annotations

import re

import httpx
import jwt

from ..config import Scope
from ..models import Finding, Method, Severity, ThreatClass
from ..recon import Recon
from ._common import iter_source_files, scan_lines

TC = ThreatClass.SESSIONS

# A short, illustrative weak-secret list. Real runs can extend this.
_WEAK_SECRETS = ["secret", "changeme", "password", "jwt_secret", "your-secret-key", "123456", "test"]

# SAST: token read from a query param (mirrors /security-web-vulns #3).
_QUERY_TOKEN_PAT = re.compile(r"(?i)token\s*[:=].*Query\s*\(|request\.query_params\[['\"]token")
_PY_SUFFIXES = (".py",)


def run_static(repo_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_source_files(repo_path, _PY_SUFFIXES):
        for lineno, line in scan_lines(path, _QUERY_TOKEN_PAT):
            findings.append(Finding(
                threat_class=TC, method=Method.STATIC, severity=Severity.HIGH,
                title="Session token read from URL query parameter",
                location=f"{path}:{lineno}", evidence=line,
                detail="Tokens in the query string land in access logs, proxies, and "
                       "browser history — they are trivially stealable.",
                remediation="Read the token only from a request header (e.g. "
                            "`x_session_token: str = Header(...)`). See /security-web-vulns fix #3.",
            ))
    return findings


def run_dynamic(scope: Scope, recon: Recon, client: httpx.Client) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Cookie flag hygiene from the recon baseline (plus a /login probe).
    cookies = list(recon.set_cookie)
    try:
        r = client.get(scope.guard(recon.base_url + "/login"))
        getter = getattr(r.headers, "get_list", None)
        cookies += getter("set-cookie") if getter else (
            [r.headers["set-cookie"]] if "set-cookie" in r.headers else [])
    except httpx.HTTPError:
        pass

    for raw in cookies:
        missing = [flag for flag in ("HttpOnly", "Secure", "SameSite") if flag.lower() not in raw.lower()]
        if missing:
            findings.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.HIGH,
                title=f"Session cookie missing {', '.join(missing)}",
                location=recon.base_url, evidence=raw.split("=")[0] + "=…; " + "; ".join(
                    p for p in raw.split(";")[1:]),
                detail="Cookies without HttpOnly are readable by XSS; without Secure they "
                       "leak over HTTP; without SameSite they enable CSRF.",
                remediation="Set HttpOnly, Secure, and SameSite=Lax/Strict on all session cookies.",
            ))

    # 2. Token-in-URL accepted by the server.
    for ep in recon.endpoints:
        if "token" in [p.lower() for p in ep.params] and ep.method == "GET":
            findings.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.HIGH,
                title="Endpoint accepts session token via URL", location=recon.base_url + ep.path,
                detail=f"{ep.method} {ep.path} declares a `token` query parameter.",
                remediation="Accept the token only via header. See /security-web-vulns fix #3.",
            ))

    # 3. JWT weaknesses on any JWT-looking cookie value.
    for raw in cookies:
        m = re.search(r"=([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)", raw)
        if m:
            findings.extend(_inspect_jwt(m.group(1), recon.base_url))
    return findings


def _inspect_jwt(token: str, location: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return findings

    if str(header.get("alg", "")).lower() == "none":
        findings.append(Finding(
            threat_class=TC, method=Method.DYNAMIC, severity=Severity.CRITICAL,
            title="JWT accepts alg:none", location=location, evidence=f"header={header}",
            detail="A token signed with `alg:none` is unsigned — anyone can forge a session.",
            remediation="Pin the allowed algorithm server-side and reject `none`.",
        ))

    for secret in _WEAK_SECRETS:
        try:
            jwt.decode(token, secret, algorithms=["HS256"])
            findings.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.CRITICAL,
                title="JWT signed with a weak/guessable secret", location=location,
                evidence=f"secret guessed from a small wordlist",
                detail="The HMAC secret was recovered from a tiny wordlist; tokens can be forged.",
                remediation="Use a long random secret (>=32 bytes) from the environment; rotate it.",
            ))
            break
        except jwt.PyJWTError:
            continue
    return findings
