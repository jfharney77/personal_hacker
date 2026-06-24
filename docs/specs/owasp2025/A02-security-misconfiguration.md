# A02:2025 — Security Misconfiguration

**Definition**: The application, framework, web server, or platform is configured insecurely, exposing unnecessary features, default credentials, verbose errors, or missing hardening headers.

## Current coverage

`hacker/modules/misconfig.py` is the dedicated DAST module for this class:

- **Missing security headers**: checks for `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` (`@hacker/modules/misconfig.py:23-29` and `_header_findings`).
- **Weak CSP**: flags policies containing `unsafe-inline` or `*` (`@hacker/modules/misconfig.py:55-61`).
- **Version disclosure**: flags `Server` or `X-Powered-By` headers that contain version numbers (`@hacker/modules/misconfig.py:63-69`).
- **Permissive CORS**: sends an attacker-origin preflight and flags reflected origins with credentials (`@hacker/modules/misconfig.py:73-98`).
- **TLS posture**: checks negotiated TLS version (rejecting TLS 1.0/1.1/SSLv3) and certificate expiry within 14 days (`@hacker/modules/misconfig.py:101-138`).

Recon captures baseline headers for this module in `hacker/recon.py:37-44` and `run_recon()`.

The vulnerable fixture reflects arbitrary origins and allows credentials (`@tests/fixtures/vulnerable_app/main.py:42-50`); the hardened twin uses an explicit origin allowlist and security headers (`@tests/fixtures/hardened_app/main.py:14-34`).

## Gaps / future work

- **Default credentials**: no probe for common default passwords (e.g., `admin/admin`, `root/toor`) on login or admin endpoints.
- **Cloud metadata exposure**: no explicit probe for `http://169.254.169.254/` or instance metadata services. The SSRF canary only listens on localhost, so it cannot confirm this externally. Consider adding a safe metadata probe if the target is local.
- **Directory listing / exposed directories**: no check for directory indexes or open static folders beyond `/.env` and friends in `credentials.py`.
- **Debug mode / stack traces**: verbose error leakage is currently handled in `credentials.py`, not `misconfig.py`. Consider moving or cross-referencing it here.
- **Unnecessary HTTP methods**: no probe for `OPTIONS`, `TRACE`, or `TRACK` being enabled.
- **Default error pages**: no detection of framework-specific default error pages that leak implementation details.

## Suggested fixture additions

- Add an admin panel at `/admin` with a default login (`admin`/`admin`) in the vulnerable fixture; the hardened twin should require a strong, non-default credential.
- Add a `GET /metadata` endpoint that proxies to `169.254.169.254` in the vulnerable fixture; the hardened twin should block or not implement it.

## Decomposition

This entry does **not** need decomposition. The existing module is comprehensive; add the missing probes as small extensions. Default credentials and cloud metadata are the highest-value additions.
