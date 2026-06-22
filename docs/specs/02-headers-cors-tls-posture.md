# Spec 02 — Security Headers / CORS / TLS posture module

**Threat class (new):** `ThreatClass.MISCONFIGURATION` → `"security_misconfiguration"`
**Style:** passive analysis of responses already captured in recon (near-zero false positives)
**Effort:** ~5% — one mostly-passive module, enum value, fixture tweaks, tests.

## Context

Most apps ship with weak or missing security headers, over-permissive CORS, and
sometimes a sloppy TLS setup. These are cheap to detect, cheap to fix, and map cleanly
to known best practice — a high signal-to-noise addition. This module barely sends new
traffic: it reasons over the headers `recon` already collected (`Recon.baseline_headers`,
`Recon.set_cookie`) plus one OPTIONS preflight and one TLS handshake.

## Detection

New file `hacker/modules/misconfig.py` with `run_dynamic(scope, recon, client)`
(no static side). Registered in `modules/__init__.py` and `graph.py`.

### A. Response headers (passive — uses `recon.baseline_headers`)
Flag each missing/weak header. Keep severities calibrated so this never dominates a report:
- `Content-Security-Policy` missing → MEDIUM; present but contains `unsafe-inline`/`*` → LOW.
- `Strict-Transport-Security` missing on an https target → MEDIUM.
- `X-Content-Type-Options: nosniff` missing → LOW.
- `X-Frame-Options` / CSP `frame-ancestors` missing → LOW (clickjacking).
- `Referrer-Policy` missing → INFO.
- `Server`/`X-Powered-By` leaking exact versions → INFO (fingerprinting).

### B. CORS (one OPTIONS preflight per origin test)
Send a request with `Origin: https://attacker.example`. Report:
- `Access-Control-Allow-Origin` reflects the attacker origin **and**
  `Access-Control-Allow-Credentials: true` → HIGH (credentialed cross-origin theft).
- `Access-Control-Allow-Origin: *` with credentials → HIGH.
- Reflective ACAO without credentials → MEDIUM.

### C. TLS (only when a target URL is https)
Open a socket via `ssl` and inspect the peer cert (no third-party deps):
- Expired or expiring < 14 days → HIGH / MEDIUM.
- Self-signed on a non-local host → MEDIUM (acceptable on localhost — see
  `/security-https-bruteforce`, which intentionally uses a self-signed localhost cert).
- TLS < 1.2 negotiated → HIGH.
Skip TLS checks for `http://` and for local hosts (self-signed is expected there).

## Fixtures
- `vulnerable_app`: add a middleware that sets a permissive CORS reflector
  (`Access-Control-Allow-Origin: <echo Origin>`, `Allow-Credentials: true`) and sets no
  security headers.
- `hardened_app`: add `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  a restrictive `Content-Security-Policy`, `X-Frame-Options: DENY`, and a strict CORS
  policy (single allowed origin, no wildcard-with-credentials).

## Tests (`tests/test_misconfig.py`)
- Vulnerable fixture → CORS reflection flagged HIGH, missing CSP/HSTS flagged.
- Hardened fixture → no MEDIUM-or-higher findings.
- TLS check is unit-tested against a generated self-signed cert (reuse the cert-gen
  approach from `/security-https-bruteforce`) asserting "self-signed on non-local = MEDIUM"
  and "expired = HIGH"; localhost path asserts it's skipped.

## Remediation text
Each finding names the exact header/policy and the recommended value, e.g.
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, and CORS findings say
"echo only a vetted allowlist of origins; never combine `*`/reflected origin with
credentials."

## Note on noise
Because these are passive and numerous, group them: the report renderer already ranks by
severity; keep individual header gaps at LOW/INFO so they sit below real exploits. Consider
a future `--min-severity` CLI flag (out of scope here) if posture findings feel chatty.
