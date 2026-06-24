# A09:2025 — Security Logging and Alerting Failures

**Definition**: Security-relevant events are not logged, logs are missing required detail, or suspicious activity does not trigger alerts, allowing attackers to remain undetected.

## Current coverage

There is **no dedicated module** for logging and alerting. The engine does not inspect logs or check for logging configuration.

## Gaps / future work

This entry requires a new module. Potential detection strategies:

- **Missing auth event logging**: SAST scan for logging calls around login, logout, password reset, and privilege changes. Flag endpoints that perform these actions without nearby logging.
- **Missing failure logging**: check that failed logins, forbidden access attempts, and invalid input are logged at an appropriate level.
- **Insufficient log detail**: ensure logs include timestamp, user identity, action, object, and outcome (without sensitive data).
- **Sensitive data in logs**: flag logging of passwords, tokens, credit card numbers, or PII. This overlaps with `credentials.py` but is specifically about logs.
- **Log injection**: detect unsanitized user input written to logs (e.g., newlines, control characters) that could tamper with log parsing.
- **No alerting**: SAST scan for security-alert integrations (e.g., email/Slack/SIEM hooks) or absence of monitoring around auth endpoints.

Because this class is SAST-heavy, the module would primarily inspect source code rather than probe the running app. DAST could include:

- Sending suspicious traffic (e.g., failed logins, injection payloads) and checking whether the server logs are updated (only if the user grants access to logs).

## Suggested fixture additions

- Add a `/auth/login` endpoint in the vulnerable fixture that authenticates users but never logs success or failure; the hardened twin should log both with structured fields and omit passwords.
- Add a logging statement that prints the raw request body containing a password in the vulnerable fixture; the hardened twin should redact sensitive fields before logging.

## Decomposition

This entry **should be decomposed** after review. It needs its own module. Suggested sub-tasks:

1. Auth event logging coverage (login, logout, password reset).
2. Access-control failure logging (forbidden/IDOR attempts).
3. Sensitive-data-in-logs detection.
4. Log injection / log-tampering detection.
5. Alerting integration detection (optional, lower priority).
