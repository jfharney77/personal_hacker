# A08:2025 — Software or Data Integrity Failures

**Definition**: The application makes security decisions based on untrusted data or components without verifying their integrity, leading to deserialization attacks, malicious updates, or supply-chain compromise.

## Current coverage

Integrity is partially covered by:

- **Supply chain**: `hacker/modules/supplychain.py` checks for known-vulnerable dependencies and secrets in git history (`@hacker/modules/supplychain.py:29-33`).
- **SSRF**: `hacker/modules/inputabuse.py` can confirm that the target fetches attacker-supplied URLs when the SSRF canary is enabled (`@hacker/modules/inputabuse.py:108-121`). This catches some data-integrity failures that result from fetching untrusted resources.

There is no explicit integrity-checking module.

## Gaps / future work

- **Insecure deserialization**: no detection of `pickle.loads`, `yaml.load`, `json.loads` into arbitrary classes, or Python `marshmallow`/Pydantic mass-assignment gadgets.
- **Prototype pollution**: no detection of JavaScript prototype-pollution sinks in the frontend code (e.g., merging user input into objects unsafely).
- **Unsigned updates / auto-update**: no detection of apps that download updates over HTTP or without signature verification.
- **CI/CD artifact integrity**: no detection of unsigned build artifacts or insecure install scripts (e.g., `curl | bash`).
- **Dependency confusion**: overlaps with A03 but is fundamentally an integrity failure (trusting a public package with a private name).
- **Deserialization of untrusted data in cookies**: no detection of signed/unsigned session cookies; JWT integrity is covered by `sessions.py` but not serialization format.

## Suggested fixture additions

- Add a `POST /process` endpoint that calls `pickle.loads(body)` on user input in the vulnerable fixture; the hardened twin should use `json` with a strict schema or `pickle` only on a known allowlist.
- Add a frontend form that merges query params into a state object via `Object.assign({}, defaults, query)` in the vulnerable fixture; the hardened twin should avoid prototype pollution sinks.

## Decomposition

This entry is **moderately large** and spans SAST and DAST. It could be implemented as extensions to `supplychain.py` (CI/CD, dependency confusion) and `inputabuse.py` (deserialization), or as a new `integrity.py` module. Decompose if multiple new probes are added.
