# OWASP Top 10:2025 specs for personal_hacker

This directory contains one spec per OWASP Top 10:2025 entry, mapping each risk to the current `personal_hacker` engine and identifying gaps.

Each spec follows the same structure:

- **Definition** — one-sentence OWASP description.
- **Current coverage** — existing modules, files, and probes that already detect this risk.
- **Gaps / future work** — what is missing and what new probes or modules would be needed.
- **Fixture suggestions** — new endpoints to add to `tests/fixtures/vulnerable_app/main.py` and the hardened twin.
- **Decomposition** — whether this entry should be split into smaller implementation tasks.

## Index

| # | OWASP entry | Status | Primary module(s) |
|---|---|---|---|
| A01 | [Broken Access Control](A01-broken-access-control.md) | Mostly covered | `accesscontrol.py` |
| A02 | [Security Misconfiguration](A02-security-misconfiguration.md) | Mostly covered | `misconfig.py` |
| A03 | [Software Supply Chain Failures](A03-software-supply-chain-failures.md) | Mostly covered | `supplychain.py` |
| A04 | [Cryptographic Failures](A04-cryptographic-failures.md) | Partial | `sessions.py`, `credentials.py`, `misconfig.py` |
| A05 | [Injection](A05-injection.md) | Mostly covered | `dbinjection.py`, `promptinjection.py`, `inputabuse.py` |
| A06 | [Insecure Design](A06-insecure-design.md) | Large gap | None dedicated |
| A07 | [Authentication Failures](A07-authentication-failures.md) | Partial | `sessions.py`, `credentials.py` |
| A08 | [Software or Data Integrity Failures](A08-data-integrity-failures.md) | Partial | `supplychain.py`, `inputabuse.py` |
| A09 | [Security Logging and Alerting Failures](A09-logging-and-alerting-failures.md) | Large gap | None dedicated |
| A10 | [Mishandling of Exceptional Conditions](A10-exceptional-conditions.md) | Partial | `credentials.py`, `dos.py` |

## Suggested implementation order

1. **A01, A02, A03, A05** — already have strong module coverage; specs are mostly documentation and minor extensions.
2. **A04, A07** — extend existing `sessions`/`credentials` modules with new probes.
3. **A10** — extend `credentials`/`dos` for exception handling and error leakage.
4. **A08** — extend `supplychain`/`inputabuse` for integrity checks.
5. **A06, A09** — likely require new modules; decompose after the specs are reviewed.
