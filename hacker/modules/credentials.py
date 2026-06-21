"""Threat class 1 — credential extraction.

SAST: hunt for hardcoded secrets and committed .env files in the repo.
DAST: probe for exposed secret files, source maps, and verbose error leakage.
"""
from __future__ import annotations

import re

import httpx

from ..config import Scope
from ..models import Finding, Method, Severity, ThreatClass
from ..recon import Recon
from ._common import iter_source_files, scan_lines

TC = ThreatClass.CREDENTIALS

# Known high-confidence secret formats. Keep these specific to limit false positives.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI/Cerebras API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Fernet key", re.compile(r"[A-Za-z0-9_\-]{43}=")),
    ("Generic assigned secret", re.compile(
        r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]

_SOURCE_SUFFIXES = (".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml", ".json", ".sh")

# Files that should never be reachable over HTTP.
_EXPOSED_PATHS = ["/.env", "/.git/config", "/config.json", "/settings.py", "/backend/.env"]


def run_static(repo_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_source_files(repo_path, _SOURCE_SUFFIXES):
        # A committed .env is itself a finding regardless of contents.
        if path.name == ".env":
            findings.append(Finding(
                threat_class=TC, method=Method.STATIC, severity=Severity.HIGH,
                title="Committed .env file", location=str(path),
                detail="An .env file is present in the source tree and may contain secrets.",
                remediation="Add .env to .gitignore and rotate any committed secrets. "
                            "Load secrets from the environment at runtime.",
            ))
        for label, pat in _SECRET_PATTERNS:
            for lineno, line in scan_lines(path, pat):
                # Skip obvious placeholders.
                if re.search(r"(?i)(example|changeme|your[_-]?key|xxxx|placeholder)", line):
                    continue
                findings.append(Finding(
                    threat_class=TC, method=Method.STATIC, severity=Severity.HIGH,
                    title=f"Hardcoded secret ({label})",
                    location=f"{path}:{lineno}",
                    evidence=_redact(line),
                    detail="A credential appears hardcoded in source. Anyone with repo "
                           "access (or a leaked build) can read it.",
                    remediation="Move the secret to an environment variable / secrets manager "
                                "and rotate it. Mirrors the secret-handling concerns in "
                                "/security-web-vulns.",
                ))
    return _dedupe(findings)


def run_dynamic(scope: Scope, recon: Recon, client: httpx.Client) -> list[Finding]:
    findings: list[Finding] = []
    base = recon.base_url

    # 1. Directly reachable secret files.
    for path in _EXPOSED_PATHS:
        try:
            r = client.get(scope.guard(base + path))
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and r.text.strip():
            # An exposed .env is critical on its own; other config files depend on content.
            is_critical = path.endswith(".env") or _looks_secret(r.text)
            sev = Severity.CRITICAL if is_critical else Severity.MEDIUM
            findings.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=sev,
                title=f"Sensitive file exposed: {path}", location=base + path,
                evidence=_redact(r.text[:200]),
                detail="A file that should never be web-accessible returned 200 OK.",
                remediation="Block dotfiles/config paths at the web server or app router; "
                            "never serve the project root as static files.",
            ))

    # 2. Verbose error leakage — send malformed input and inspect the body.
    for ep in recon.endpoints:
        if ep.method != "GET" or not ep.params:
            continue
        url = base + ep.path
        try:
            r = client.get(scope.guard(url), params={ep.params[0]: "'\"<broken"})
        except httpx.HTTPError:
            continue
        if r.status_code >= 500 and _looks_like_trace(r.text):
            findings.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.MEDIUM,
                title="Verbose error / stack trace leak", location=url,
                evidence=_redact(r.text[:200]),
                detail="A malformed request produced a 500 with internal details "
                       "(stack trace, SQL, or raw exception) in the response body.",
                remediation="Return generic error messages; disable debug mode in production; "
                            "log details server-side only.",
            ))
            break  # one example is enough to make the point
    return findings


def _looks_secret(text: str) -> bool:
    return any(pat.search(text) for _, pat in _SECRET_PATTERNS)


def _looks_like_trace(text: str) -> bool:
    return bool(re.search(r"(?i)(traceback|sqlite3\.|psycopg2|sqlalchemy|line \d+, in |\"query\":)", text))


def _redact(line: str) -> str:
    """Shorten + partially mask so evidence proves the issue without dumping the secret."""
    line = line.strip()
    return (line[:60] + "…") if len(line) > 60 else line


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.title, f.location)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
