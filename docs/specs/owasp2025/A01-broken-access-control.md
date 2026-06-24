# A01:2025 — Broken Access Control

**Definition**: Users can perform actions or access data outside their intended permissions because access controls are missing, incorrectly enforced, or bypassable.

## Current coverage

`personal_hacker` has a dedicated module for this class:

- `hacker/modules/accesscontrol.py` runs only when at least one authenticated identity is configured.
- With **two identities** it performs horizontal IDOR testing: it fetches the same object IDs as user A and user B and flags a `CRITICAL` finding if both users receive byte-identical responses (`@hacker/modules/accesscontrol.py:62-93`).
- It also probes **mass-assignment** on `PUT`/`PATCH` endpoints by injecting privileged fields (`owner`, `role`, `is_admin`, `user_id`) and restoring the original record afterward (`@hacker/modules/accesscontrol.py:96-136`).
- Authentication support lives in `hacker/auth.py`, which logs in as each configured identity and extracts tokens from JSON responses or cookies.

The test fixtures already include endpoints for these probes:

- `GET /api/notes/{note_id}` in the vulnerable fixture ignores object ownership (`@tests/fixtures/vulnerable_app/main.py:104-112`).
- `PUT /api/notes/{note_id}` accepts arbitrary fields (`@tests/fixtures/vulnerable_app/main.py:115-125`).
- The hardened twin scopes notes to the authenticated owner and restricts updates to an allowlist (`@tests/fixtures/hardened_app/main.py:81-105`).

## Gaps / future work

- **CSRF**: The `sessions.py` module checks `SameSite` cookie flags but does not send cross-origin state-changing requests to test actual CSRF vulnerability.
- **Vertical privilege escalation**: There is no probe for role-based access control (e.g., an admin-only endpoint reachable by a normal user).
- **Forced browsing / predictable IDs**: IDOR probes only use small integers `1..3` (`@hacker/modules/accesscontrol.py:24`). A broader ID space or UUID vs. integer comparison could be added.
- **Function-level authorization**: No check that `DELETE`/`POST` actions are authorized, only `GET` IDOR and `PUT`/`PATCH` mass-assignment.
- **CORS with credentials** is currently grouped under `misconfig.py` rather than access control. Consider cross-referencing it in this spec.

## Suggested fixture additions

- Add an `/admin/users` endpoint in the vulnerable fixture that returns all users without role checks, and ensure the hardened twin returns `403` for non-admin sessions.
- Add a `POST /api/notes` endpoint without CSRF protection (or with a `SameSite=None` session cookie) to demonstrate CSRF.

## Decomposition

This entry does **not** need to be decomposed now. The existing module covers the core cases well. Add CSRF and vertical escalation as incremental enhancements within the same module.
