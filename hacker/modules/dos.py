"""Threat class 3 — denial of service. SAFE MODE by design.

This module never floods a target. It *detects missing protections* statically
and confirms them with a tiny bounded burst (default 15 requests) purely to see
whether a 429 ever appears. Sustained/active load testing is intentionally out
of scope unless safe_mode is disabled (a future, gated feature).
"""
from __future__ import annotations

import re
import time

import httpx

from ..config import Scope
from ..models import Finding, Method, Severity, ThreatClass
from ..recon import Recon
from ._common import iter_source_files, scan_lines

TC = ThreatClass.DOS

_PY = (".py",)
# Catastrophic-backtracking smell: nested quantifiers in a regex literal.
_REDOS_PAT = re.compile(r"re\.(compile|match|search|fullmatch)\(.*(\(\.\*\)\+|\(\.\+\)\+|\(\[.*\]\+\)\+|\(\.\*\)\*)")
# Unbounded queries: a list/all without an obvious limit nearby.
_UNBOUNDED_PAT = re.compile(r"(?i)\.(all|fetchall)\(\)|SELECT\s+.*FROM(?!.*LIMIT)")

# Bounded burst size used to check for rate limiting in safe mode.
SAFE_BURST = 15


def run_static(repo_path: str) -> list[Finding]:
    findings: list[Finding] = []
    has_limiter = False
    for path in iter_source_files(repo_path, _PY):
        # Require real usage, not prose — a comment mentioning slowapi isn't protection.
        text_hits_limiter = list(scan_lines(
            path, re.compile(r"(from|import)\s+slowapi|@limiter\.limit\(|Limiter\(|RateLimiter\(")))
        if text_hits_limiter:
            has_limiter = True
        for lineno, line in scan_lines(path, _REDOS_PAT):
            findings.append(Finding(
                threat_class=TC, method=Method.STATIC, severity=Severity.MEDIUM,
                title="Possible ReDoS (catastrophic backtracking)",
                location=f"{path}:{lineno}", evidence=line,
                detail="A regex with nested quantifiers can hang on crafted input, "
                       "consuming CPU and stalling the server.",
                remediation="Simplify the regex or bound input length; consider re2.",
            ))
        for lineno, line in scan_lines(path, _UNBOUNDED_PAT):
            findings.append(Finding(
                threat_class=TC, method=Method.STATIC, severity=Severity.LOW,
                title="Unbounded query / no pagination",
                location=f"{path}:{lineno}", evidence=line,
                detail="Returning all rows lets a large table exhaust memory/bandwidth.",
                remediation="Add LIMIT/pagination and a sane maximum page size.",
            ))

    if repo_path and not has_limiter:
        findings.append(Finding(
            threat_class=TC, method=Method.STATIC, severity=Severity.HIGH,
            title="No rate limiting found in source", location=repo_path,
            detail="No slowapi/limiter usage detected anywhere in the project. Auth and "
                   "expensive endpoints can be hammered freely.",
            remediation="Add slowapi and apply @limiter.limit() to sensitive endpoints. "
                        "See /security-https-bruteforce.",
        ))
    return findings


def run_dynamic(scope: Scope, recon: Recon, client: httpx.Client) -> list[Finding]:
    findings: list[Finding] = []
    if not scope.safe_mode:
        # Active load testing would go here, behind explicit confirmation. Not implemented.
        pass

    # Pick a cheap GET endpoint to probe rate limiting with a small bounded burst.
    target = next((e for e in recon.endpoints if e.method == "GET"), None)
    if target is None:
        return findings
    url = recon.base_url + target.path

    saw_429 = False
    for _ in range(SAFE_BURST):
        try:
            r = client.get(scope.guard(url))
        except httpx.HTTPError:
            break
        if r.status_code == 429:
            saw_429 = True
            break
        time.sleep(0.02)  # gentle; we are not trying to overwhelm anything

    if not saw_429:
        findings.append(Finding(
            threat_class=TC, method=Method.DYNAMIC, severity=Severity.MEDIUM,
            title="No rate limiting observed", location=url,
            evidence=f"{SAFE_BURST} rapid requests, never a 429",
            detail="A small bounded burst was never throttled. An attacker can scale this "
                   "up to brute-force or exhaust resources.",
            remediation="Add rate limiting (slowapi) on this and other public endpoints. "
                        "See /security-https-bruteforce.",
        ))
    return findings
