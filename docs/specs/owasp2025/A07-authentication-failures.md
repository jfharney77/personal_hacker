# A07:2025 — Authentication Failures

**Definition**: Authentication mechanisms are implemented incorrectly or incompletely, allowing attackers to assume other users' identities or bypass authentication entirely.

## Current coverage

Authentication is partially covered by the `sessions` and `credentials` modules:

- **Token-in-URL**: `hacker/modules/sessions.py` flags `GET` endpoints that declare a `token` query parameter (`@hacker/modules/sessions.py:71-79`) and SAST-detects `request.query_params["token"]` patterns (`@hacker/modules/sessions.py:29-42`).
- **Insecure session cookies**: `hacker/modules/sessions.py` checks for missing `HttpOnly`, `Secure`, and `SameSite` flags (`@hacker/modules/sessions.py:48-69`).
- **JWT weaknesses**: `hacker/modules/sessions.py` detects `alg:none` and weak signing secrets (`@hacker/modules/sessions.py:89-117`).
- **Exposed credentials**: `hacker/modules/credentials.py` finds hardcoded secrets and exposed `.env` files (`@hacker/modules/credentials.py:34-62`, `65-108`).
- **Authentication helper**: `hacker/auth.py` allows the scanner to log in as configured identities and reuse tokens or cookies (`@hacker/auth.py:34-68`).

## Gaps / future work

- **Account enumeration**: no probe that checks whether login or password-reset endpoints reveal whether an account exists (e.g., different error messages or timing).
- **Brute-force resistance**: no login brute-force probe. The DoS module only checks for `429` on an arbitrary `GET` endpoint.
- **Weak password policy**: no detection of weak/default passwords, missing complexity requirements, or no rate limiting on auth endpoints.
- **Session fixation**: no check that the session ID rotates after login.
- **Missing MFA**: no detection that sensitive actions can be performed without a second factor.
- **Insecure password reset**: no check for weak reset tokens, reset tokens sent over HTTP, or reset flows that leak account existence.
- **Weak "remember me"**: no detection of long-lived, predictable remember-me tokens.
- **Plaintext password storage**: overlaps with A04 (cryptographic failures) but is fundamentally an authentication failure.

## Suggested fixture additions

- Add a `/auth/login` endpoint that returns different error messages for missing username vs. wrong password in the vulnerable fixture; the hardened twin should return a generic message.
- Add a `/auth/reset` endpoint that sends a short numeric reset token over HTTP or logs it in the response; the hardened twin should use a long random token and HTTPS.
- Add a `/auth/remember` endpoint that sets a predictable cookie; the hardened twin should use a secure, hashed token.

## Decomposition

This entry is **moderately large**. It does not need its own module yet, but several probes should be added to `sessions.py` or a new `authrobustness.py` module. Decompose into sub-tasks if more than 4–5 new probes are implemented.
