"""Threat class 4 — database injection.

SAST: detect string-built SQL (f-strings, %/+ concatenation, raw text()).
DAST: boolean/error probes plus a time-based oracle, each compared to a control
request so we only report a finding when the target's behavior actually changes.
All payloads are benign markers — nothing that writes or destroys data.
"""
from __future__ import annotations

import re
import time

import httpx

from ..config import Scope
from ..models import Finding, Method, Severity, ThreatClass
from ..recon import Recon
from ._common import iter_source_files, scan_lines

TC = ThreatClass.DB_INJECTION
_PY = (".py",)

# String-built SQL: f-string or concatenation feeding execute(), or raw text().
_RAW_SQL_PAT = re.compile(
    r"""(?ix)
    \.execute\(\s*f["']            |   # execute(f"...
    \.execute\(\s*["'].*%\s*\(?    |   # execute("... % (
    \.execute\(\s*["'].*["']\s*\+  |   # execute("..." +
    (?:select|insert|update|delete)\b.*["']\s*\+   |  # SQL literal + var
    \btext\(\s*f["']                  # sqlalchemy text(f"...
""")

_ERROR_SIGNS = re.compile(r"(?i)(sql syntax|sqlite3\.|psycopg2|near \"|unrecognized token|OperationalError)")


def run_static(repo_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_source_files(repo_path, _PY):
        for lineno, line in scan_lines(path, _RAW_SQL_PAT):
            findings.append(Finding(
                threat_class=TC, method=Method.STATIC, severity=Severity.HIGH,
                title="SQL query built from string interpolation",
                location=f"{path}:{lineno}", evidence=line,
                detail="Untrusted input concatenated into SQL allows injection.",
                remediation="Use parameterized queries / bound parameters; never f-string or "
                            "concatenate user input into SQL.",
            ))
    return findings


def run_dynamic(scope: Scope, recon: Recon, client: httpx.Client) -> list[Finding]:
    findings: list[Finding] = []
    for ep in recon.endpoints:
        if ep.method != "GET" or not ep.params:
            continue
        url = recon.base_url + ep.path
        param = ep.params[0]

        # Control request to compare against.
        try:
            control = client.get(scope.guard(url), params={param: "normaltext"})
        except httpx.HTTPError:
            continue

        # 1. Error-based: a single quote provokes a DB error in the body.
        try:
            broken = client.get(scope.guard(url), params={param: "'"})
        except httpx.HTTPError:
            broken = None
        if broken is not None and _ERROR_SIGNS.search(broken.text) and not _ERROR_SIGNS.search(control.text):
            findings.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.CRITICAL,
                title="Error-based SQL injection", location=url,
                evidence=f"param={param!r}: a single quote triggered a DB error",
                detail="Injecting a quote produced a database error absent from the control "
                       "response — input reaches the SQL engine unescaped.",
                remediation="Parameterize the query. See the SAST findings for the source line.",
            ))
            continue  # already confirmed for this endpoint

        # 2. Time-based oracle: a SLEEP payload measurably delays the response.
        base_latency = _timed(client, scope, url, {param: "normaltext"})
        sleep_latency = _timed(client, scope, url, {param: "x' AND SLEEP(2)-- "})
        if base_latency is not None and sleep_latency is not None and sleep_latency - base_latency > 1.5:
            findings.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.CRITICAL,
                title="Time-based (blind) SQL injection", location=url,
                evidence=f"param={param!r}: SLEEP payload added {sleep_latency - base_latency:.1f}s",
                detail="A time-delay payload measurably slowed the response vs. control, "
                       "indicating the input controls query execution.",
                remediation="Parameterize the query and validate input types.",
            ))
    return findings


def _timed(client: httpx.Client, scope: Scope, url: str, params: dict) -> float | None:
    try:
        start = time.perf_counter()
        client.get(scope.guard(url), params=params)
        return time.perf_counter() - start
    except httpx.HTTPError:
        return None
