# Spec 01 — SSRF / Path Traversal / Open Redirect module

**Threat class (new):** `ThreatClass.INPUT_ABUSE` → `"server_side_request_and_path_abuse"`
**Style:** active confirmation (DAST) + pattern detection (SAST)
**Effort:** ~5% — one module, enum value, fixture additions, tests.

## Context

The three highest-impact "untrusted input is used as a location" bugs share a shape:
a parameter that the server turns into an outbound **URL** (SSRF), a **file path**
(directory traversal), or a **redirect target** (open redirect). They aren't covered
today. Each is individually common and, for SSRF especially, severe (cloud metadata
theft, internal port scanning).

## Detection

New file `hacker/modules/inputabuse.py`, exposing `run_static` and `run_dynamic`,
registered in `hacker/modules/__init__.py` and called from `hacker/graph.py` (it
participates in cross-validation like the others).

### SAST (`run_static`)
Reuse `iter_source_files` + `scan_lines` from `modules/_common.py`. Flag:
- **SSRF**: `requests.get(<var>)`, `httpx.get(<var>)`, `urlopen(<var>)` where the
  argument is not a string literal — HIGH.
- **Traversal**: `open(<var>)`, `send_file(<var>)`, `os.path.join(<root>, <var>)`,
  `Path(<var>).read_*` with request-derived input — HIGH.
- **Open redirect**: `RedirectResponse(<var>)` / `redirect(<var>)` where target is
  request-derived — MEDIUM.

### DAST (`run_dynamic`) — safe by design
For each GET/POST endpoint param (from `recon.endpoints`), run three probes, each
compared to a control request so we only report on a behavior change:

1. **Open redirect** (fully safe): set the param to `https://canary.example/REDIR_MARK`.
   If the response is a 30x whose `Location` starts with that canary → CONFIRMED HIGH.
2. **Path traversal** (read-only): send `../../../../etc/hostname` (and a Windows
   variant). If the body changes vs control and matches a traversal signature
   (`root:.*:0:0:` for passwd, a hostname pattern, or "No such file" path echo) →
   CONFIRMED CRITICAL.
3. **SSRF** (safe, no internal traffic): set the param to a single **allowlisted**
   callback URL the tool controls — `http://<scope.ssrf_canary_host>/ssrf-<nonce>`
   (defaults to a localhost port the module briefly binds). SSRF is confirmed only if
   that callback is actually hit (the nonce shows up in the local listener). **We never
   point the target at `169.254.169.254` or arbitrary internal hosts** — confirmation is
   via our own canary, so the test cannot itself become an attack. If no canary host is
   configured, downgrade to a *passive* signal: the target fetched our URL and reflected
   its response body → MEDIUM "possible SSRF".

`Scope.guard()` still gates every request the tool sends. Add an optional
`ssrf_canary_host` to `Scope` (defaults to `127.0.0.1:0` ephemeral); document that the
canary listener binds locally only.

## Fixtures
- `vulnerable_app`: add `/fetch?url=` (does `httpx.get(url)` and returns body — SSRF),
  `/file?name=` (`open("data/"+name)` — traversal), `/go?next=` (`RedirectResponse(next)`
  — open redirect).
- `hardened_app`: `/fetch` with an allowlist of permitted hosts; `/file` that rejects
  `..` and resolves within a base dir; `/go` that only redirects to relative same-site paths.

## Tests (`tests/test_inputabuse.py`)
- SAST finds each pattern in the vulnerable fixture.
- DAST confirms open-redirect (Location canary) and traversal (passwd/hostname signature).
- SSRF: stand up a local `http.server` listener in the test, point the canary at it,
  assert the nonce was received.
- Hardened fixture → zero HIGH/CRITICAL (no false positives).

## Remediation text (in findings)
- SSRF → "Resolve and allowlist outbound hosts; block link-local/private ranges; never
  fetch user-supplied URLs directly."
- Traversal → "Canonicalize and confine paths to a base directory; reject `..`."
- Open redirect → "Allowlist redirect targets or only permit relative same-site paths."

## Severity & cross-validation
Traversal/SSRF confirmed dynamically = CRITICAL; SAST-only = HIGH. When both fire for
the class, `_triage` in `graph.py` marks them ✅ cross-validated automatically.
