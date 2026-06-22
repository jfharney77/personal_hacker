# TODO

Deferred work, roughly in priority order. Nothing here is started.

## Deployment / automation

- [ ] **Nightly per-project CI scan (deferred on purpose).** Wire `personal_hacker`
      into each project's pipeline rather than a central cron:
      - SAST scan on every push (`--fail-on high`, no running app needed).
      - Baseline-gated DAST scan nightly against that project's **staging** URL
        (`--baseline baseline.json --fail-on high`), so only *new* findings break the build.
      - Reuse the existing `/github-railway` and `/gitlab-railway` skills' CI patterns;
        emit JSON as a build artifact.
      - Now unblocked because findings have stable fingerprints (no re-alert spam).
- [ ] Optional central scheduler alternative: `/schedule` cloud agent or crontab iterating
      a project registry `{repo, staging_url, scope.yaml}`. Needs the registry built first.
- [ ] **SARIF output** (`--sarif`) so findings feed GitHub code scanning / the Security tab.

## Outstanding critique items (from the project review)

- [ ] **#5 — make "safe mode" a provably enforced property**, not a promise:
      - No writes at all in safe mode (gate the mass-assignment PUT/PATCH probe behind
        `safe_mode: false`; today it writes-then-restores best-effort).
      - Self-throttle the tool's own outbound requests (global rate limit) so a scan can't
        DoS a fragile staging box.
      - Stop storing login passwords in plaintext `scope.yaml` (env var / secrets ref).
- [ ] **#2 — SAST is regex, not analysis.** Move the highest-value detectors (SQLi raw
      query, SSRF/traversal taint) to an AST + light taint pass to cut false pos/neg.
      Until then, treat SAST findings as leads, not verdicts.
- [ ] **#3 (partial) — deepen dynamic probing.** POST/JSON bodies now covered; still missing:
      chained/stateful exploits (login → CSRF token → action), real DoS threshold discovery
      (not just "is there a 429"), and per-endpoint auth context.

## Packaging / DX

- [ ] `pyproject.toml` + console-script entrypoint (`personal-hacker`) so it isn't run via a
      hardcoded `.venv` path.
- [ ] LLM judge: add a call budget / cost cap; cache verdicts.
- [ ] Protocol coverage: GraphQL (introspection + injection), websockets, gRPC.

## Possible new modules (from the earlier brainstorm, not yet specced/built)

- [ ] XSS module (reflected + stored + DOM), live-confirming the `/security-web-vulns` #4 static check.
- [ ] Auth-robustness module: account enumeration, session fixation (does the session id
      rotate on login?), password policy, login brute-force exposure.
