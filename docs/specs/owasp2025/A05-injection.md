# A05:2025 — Injection

**Definition**: Untrusted data is sent to an interpreter as part of a command or query, causing the interpreter to execute unintended instructions or access unauthorized data.

## Current coverage

Injection is covered by three modules:

- **SQL injection**: `hacker/modules/dbinjection.py` performs SAST for string-built SQL and DAST with error-based and time-based oracles (`@hacker/modules/dbinjection.py:37-90`).
- **LLM / prompt injection**: `hacker/modules/promptinjection.py` sends adversarial payloads to endpoints flagged as LLM-backed and uses a heuristic or LLM judge (`@hacker/modules/promptinjection.py:47-86`).
- **Input-as-location abuse**: `hacker/modules/inputabuse.py` covers SSRF (via local canary), path traversal (`/etc/passwd` signature), and open redirect (`@hacker/modules/inputabuse.py:40-121`).

The vulnerable fixture includes:

- SQL injection in `GET /users` and `POST /api/find` (`@tests/fixtures/vulnerable_app/main.py:29-39`, `146-156`).
- A time-based oracle in `GET /search` (`@tests/fixtures/vulnerable_app/main.py:159-164`).
- SSRF, path traversal, and open redirect endpoints (`@tests/fixtures/vulnerable_app/main.py:59-82`).
- A naive LLM chat endpoint that leaks its system prompt (`@tests/fixtures/vulnerable_app/main.py:175-184`).

The hardened twin uses parameterized queries, allowlists, and input validation (`@tests/fixtures/hardened_app/main.py:37-62`, `124-129`).

## Gaps / future work

- **NoSQL injection**: no probes for MongoDB-style `$where` or operator injection.
- **Command injection**: no detection of `os.system`, `subprocess`, or shell pipelines built from user input.
- **LDAP / XPath injection**: no coverage.
- **XML external entity (XXE)**: no probe for XML parsers with external entities enabled.
- **Server-side template injection (SSTI)**: no detection of Jinja2 or other template engines rendering user input.
- **Log injection**: no detection of newlines or control characters in values written to logs.
- **Header injection / CRLF**: no coverage for response-splitting via user input in headers.

## Suggested fixture additions

- Add a `GET /ping` endpoint that runs `subprocess.run(f"ping -c 1 {host}", shell=True)` in the vulnerable fixture; the hardened twin should use `shlex.split` and an allowlist.
- Add an XML endpoint that parses user input with `etree.parse(...)` without disabling external entities; the hardened twin should disable DTDs/entities.

## Decomposition

This entry does **not** need decomposition. The existing modules cover the major injection types. Each missing variant (NoSQL, command, XXE, SSTI, log) can be added as a small, self-contained probe within the existing module structure.
