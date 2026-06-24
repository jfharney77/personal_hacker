# A04:2025 — Cryptographic Failures

**Definition**: Sensitive data is exposed or compromised through weak cryptography, missing encryption, improper key management, or flawed protocols.

## Current coverage

Cryptographic failures are detected across several existing modules, but there is no dedicated crypto module:

- **JWT weaknesses**: `hacker/modules/sessions.py` detects `alg:none` and weak HMAC secrets from a small wordlist (`@hacker/modules/sessions.py:89-117`).
- **Hardcoded secrets**: `hacker/modules/credentials.py` flags hardcoded API keys, Fernet keys, and generic secrets (`@hacker/modules/credentials.py:20-26`).
- **TLS posture**: `hacker/modules/misconfig.py` checks TLS version and certificate expiry (`@hacker/modules/misconfig.py:101-138`).
- **Exposed secrets**: `hacker/modules/credentials.py` probes for `/.env`, `/.git/config`, and other sensitive files (`@hacker/modules/credentials.py:31` and `run_dynamic`).

The hardened fixture reads secrets from environment variables (`@tests/fixtures/hardened_app/main.py:108`) and sets secure cookie flags (`@tests/fixtures/hardened_app/main.py:116-121`).

## Gaps / future work

- **Weak password hashing**: no detection of plaintext password storage, MD5/SHA1 hashes, or low work-factor bcrypt/argon2.
- **Insecure randomness**: no detection of `random` used for tokens, secrets, or IDs instead of `secrets` or `os.urandom`.
- **Weak key lengths / ciphers**: TLS check only covers protocol version, not cipher suites or key length.
- **Missing encryption at rest**: no detection of database columns or files storing sensitive data in plaintext.
- **Certificate pinning**: not relevant for most web apps, but no check for invalid/self-signed certs in production targets.
- **Secret rotation**: no detection of long-lived static secrets (this is more of a process finding).

## Suggested fixture additions

- Add a login endpoint in the vulnerable fixture that stores passwords in plaintext or uses MD5; the hardened twin should use bcrypt/argon2.
- Add a token generator that uses `random.choice()` instead of `secrets.token_urlsafe()`; the hardened twin should use `secrets`.

## Decomposition

This entry is **moderately large** and spans multiple modules. It does not need its own module yet, but it may be cleaner to create a new `crypto.py` module once the gaps above are implemented. Decompose into sub-tasks if more than 3–4 new probes are added.
