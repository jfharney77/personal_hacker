"""Threat class — SSRF / path traversal / open redirect (input used as a location).

SAST: flag user input flowing into an outbound request, a file open, or a redirect.
DAST: confirm each with a benign, control-compared probe. SSRF is confirmed only via
a tool-controlled local canary (we never point the target at internal infrastructure),
so the test can never itself become an SSRF attack.
"""
from __future__ import annotations

import http.server
import re
import threading
import uuid

import httpx

from ..config import Scope
from ..models import Finding, Method, Severity, ThreatClass
from ..recon import Recon
from ._common import injectable_endpoints, iter_source_files, scan_lines, send_probe

TC = ThreatClass.INPUT_ABUSE
_PY = (".py",)

# SAST: user input (bare identifier or f-string) used as a location. Anchored so that
# wrapping the value in a validator/join/lookup (the hardened pattern) does NOT match.
_SSRF_PAT = re.compile(
    r"(?:requests|httpx)\.(?:get|post|put|request)\(\s*(?:f[\"']|[A-Za-z_]\w*\s*[,)])"
    r"|urlopen\(\s*[A-Za-z_]\w*\s*[,)]")
_TRAVERSAL_PAT = re.compile(
    r"open\(\s*(?:f[\"']|[A-Za-z_]\w*\s*\+)|send_file\(\s*[A-Za-z_]\w*\s*[,)]")
_REDIRECT_PAT = re.compile(r"(?:RedirectResponse|redirect)\(\s*[A-Za-z_]\w*\s*\)")

# DAST payloads.
_TRAVERSAL_PAYLOAD = "../../../../../../../../etc/passwd"
_PASSWD_SIG = re.compile(r"root:.*:0:0:")
_REDIR_CANARY = "https://canary.invalid/REDIR_MARK"


def run_static(repo_path: str) -> list[Finding]:
    findings: list[Finding] = []
    rules = [
        (_SSRF_PAT, Severity.HIGH, "Server-side request from user input (SSRF risk)",
         "User-controlled value is passed to an outbound HTTP/URL call.",
         "Allowlist outbound hosts; block link-local/private ranges; never fetch "
         "user-supplied URLs directly."),
        (_TRAVERSAL_PAT, Severity.HIGH, "File path built from user input (traversal risk)",
         "User-controlled value is concatenated into a filesystem path.",
         "Canonicalize and confine paths to a base directory; reject '..'."),
        (_REDIRECT_PAT, Severity.MEDIUM, "Redirect target from user input (open redirect risk)",
         "User-controlled value is used as a redirect destination.",
         "Allowlist redirect targets or only permit relative same-site paths."),
    ]
    for path in iter_source_files(repo_path, _PY):
        for pat, sev, title, detail, fix in rules:
            for lineno, line in scan_lines(path, pat):
                findings.append(Finding(
                    threat_class=TC, method=Method.STATIC, severity=sev, title=title,
                    location=f"{path}:{lineno}", evidence=line, detail=detail, remediation=fix))
    return findings


def run_dynamic(
    scope: Scope, recon: Recon, client: httpx.Client, canary: "SSRFCanary | None" = None
) -> list[Finding]:
    findings: list[Finding] = []
    # Probe GET query params and POST/PUT/PATCH body params (forms found by the crawler).
    for ep in injectable_endpoints(recon):
        url = recon.base_url + ep.path
        for param in ep.params:
            findings.extend(_probe_param(scope, client, recon.base_url, ep, url, param, canary))
    return findings


def _probe_param(scope, client, base_url, ep, url, param, canary) -> list[Finding]:
    out: list[Finding] = []

    # Control request to compare against.
    control = send_probe(scope, client, ep, base_url, {param: "benign"}, follow_redirects=False)
    if control is None:
        return out

    # 1. Open redirect — fully safe, we never follow the redirect.
    r = send_probe(scope, client, ep, base_url, {param: _REDIR_CANARY}, follow_redirects=False)
    if r is not None and r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("location", "")
        if loc.startswith(_REDIR_CANARY):
            out.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.HIGH,
                title="Open redirect", location=url,
                evidence=f"param={param!r} → Location: {loc}",
                detail="The endpoint redirected to an attacker-supplied external URL.",
                remediation="Allowlist redirect targets or only permit relative same-site paths."))
            return out  # this param is clearly location-controlled; one finding is enough

    # 2. Path traversal — read-only, signature-confirmed vs control.
    r = send_probe(scope, client, ep, base_url, {param: _TRAVERSAL_PAYLOAD}, follow_redirects=False)
    if r is not None and _PASSWD_SIG.search(r.text) and not _PASSWD_SIG.search(control.text):
        out.append(Finding(
            threat_class=TC, method=Method.DYNAMIC, severity=Severity.CRITICAL,
            title="Path traversal", location=url,
            evidence=f"param={param!r}: response contained /etc/passwd signature",
            detail="A '../' payload made the endpoint return file contents outside its intended "
                   "directory.",
            remediation="Canonicalize and confine paths to a base directory; reject '..'."))
        return out

    # 3. SSRF — confirmed ONLY by our own canary being hit (no internal traffic generated).
    if canary is not None:
        nonce = canary.new_nonce()
        send_probe(scope, client, ep, base_url, {param: canary.url(nonce)}, follow_redirects=False)
        if canary.was_hit(nonce):
            out.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.CRITICAL,
                title="SSRF (server-side request forgery)", location=url,
                evidence=f"param={param!r}: target fetched our canary URL (nonce {nonce})",
                detail="The endpoint fetched a URL we supplied — an attacker could make it reach "
                       "internal services or cloud metadata.",
                remediation="Allowlist outbound hosts; block link-local/private ranges; never "
                            "fetch user-supplied URLs directly."))
    return out


class SSRFCanary:
    """A local HTTP listener used to confirm SSRF safely. The target is only ever asked
    to fetch THIS server (on localhost), never real internal infrastructure."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._hits: set[str] = set()
        hits = self._hits

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.add(self.path.rsplit("/", 1)[-1])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"canary-ok")

            def log_message(self, *a):  # silence
                pass

        self._server = http.server.HTTPServer((host, port), _Handler)
        self.host, self.port = self._server.server_address
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "SSRFCanary":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()

    def new_nonce(self) -> str:
        return uuid.uuid4().hex[:12]

    def url(self, nonce: str) -> str:
        return f"http://{self.host}:{self.port}/ssrf-{nonce}"

    def was_hit(self, nonce: str) -> bool:
        return f"ssrf-{nonce}" in self._hits
