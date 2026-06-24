# A06:2025 — Insecure Design

**Definition**: The application is built with design patterns or business workflows that are inherently unsafe, rather than having a specific implementation flaw.

## Current coverage

There is **no dedicated module** for insecure design. Some design-level risks are partially caught by other modules:

- **Broken access control** catches missing authorization design (`hacker/modules/accesscontrol.py`).
- **Input abuse** catches trusting user input as a location (`hacker/modules/inputabuse.py`).
- **Credential extraction** catches hardcoded secrets and unsafe secret handling (`hacker/modules/credentials.py`).

However, none of these address higher-level design flaws such as business-logic abuse, insecure workflows, or race conditions.

## Gaps / future work

This is the broadest OWASP entry and requires a new module or framework. Potential probes include:

- **Business logic abuse**: price/quantity manipulation, skipping workflow steps, using an API out of order (e.g., checkout before adding items), or abusing discount codes.
- **Race conditions**: sending parallel requests that together violate a limit (e.g., double spending, redeeming a single-use code twice).
- **Insecure workflow design**: endpoints that allow an action without required prerequisites (e.g., shipping before payment).
- **Over-collection of data**: endpoints that request or return more sensitive data than necessary.
- **Mass-assignment at design level**: already covered in `accesscontrol.py`, but worth extending to object creation (`POST`) and not just updates (`PUT`/`PATCH`).
- **Insecure defaults**: configuration defaults that are unsafe (e.g., debug mode, open CORS, permissive file uploads). Partially overlaps with A02.

Because these are application-specific, the module would likely need:

- A declarative way to describe valid workflow steps (e.g., a state machine or sequence check).
- A set of generic probes (e.g., reorder requests, repeat requests, swap IDs) that work across many apps.

## Suggested fixture additions

- Add a small e-commerce flow in the vulnerable fixture: `POST /cart/add`, `POST /checkout`, `POST /redeem`. Allow redeeming a one-time coupon twice due to missing idempotency; the hardened twin should use idempotency keys and proper state transitions.
- Add a `GET /profile` endpoint that returns the full user record including SSN; the hardened twin should return only needed fields.

## Decomposition

This entry **should be decomposed** after the spec is reviewed. It is too large for a single module. Suggested sub-tasks:

1. Business-logic abuse probes (price/qty manipulation, workflow skipping).
2. Race-condition detection (parallel request harness).
3. Data-minimization / over-collection checks.
4. Insecure defaults scan (overlap with A02; may be shared).
