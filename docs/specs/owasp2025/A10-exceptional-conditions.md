# A10:2025 — Mishandling of Exceptional Conditions

**Definition**: The application does not handle errors, exceptions, or unexpected states safely, leading to crashes, denial of service, or leakage of sensitive information.

## Current coverage

Exception handling is partially covered by:

- **Verbose error leakage**: `hacker/modules/credentials.py` sends malformed input to a `GET` endpoint and flags 500 responses that contain stack traces or SQL internals (`@hacker/modules/credentials.py:88-107`).
- **DoS from unbounded operations**: `hacker/modules/dos.py` flags unbounded queries and missing rate limiting (`@hacker/modules/dos.py:32-68`).

There is no dedicated exception-handling module.

## Gaps / future work

- **Global exception handlers**: SAST scan for missing `try/except` around external I/O, database calls, or risky parsing; also detect whether FastAPI/Flask has a global error handler registered.
- **Sensitive data in error responses**: expand the existing verbose-error probe to look for more leakage patterns (environment variables, file paths, internal IPs, database connection strings).
- **Exception-based DoS**: probe for inputs that cause unhandled exceptions, infinite loops, or resource exhaustion (e.g., deeply nested JSON, ReDoS payloads, giant payloads). The DoS module already checks ReDoS SAST but does not DAST-test catastrophic regex.
- **Unhandled promise rejections / async exceptions**: in Python, detect bare `except:` or swallowed exceptions that hide failures.
- **Crash loops / health checks**: no detection of endpoints that return 500 on trivial input, indicating poor exception handling.
- **Debug mode**: overlaps with A02; FastAPI/Flask debug flags should be checked in source.

## Suggested fixture additions

- Add a `GET /parse` endpoint that calls `json.loads(user_input)` without a try/except and returns the raw exception in the vulnerable fixture; the hardened twin should catch `JSONDecodeError` and return a generic error.
- Add a ReDoS-susceptible regex endpoint in the vulnerable fixture and a bounded, safe regex in the hardened twin.

## Decomposition

This entry is **moderately large** but closely related to existing modules. It can be implemented as extensions to `credentials.py` (error leakage) and `dos.py` (exception-based DoS). Decompose if a new module is created for comprehensive exception handling.
