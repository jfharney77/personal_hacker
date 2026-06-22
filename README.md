# personal_hacker

An automated, **safe-by-default** friendly hacker for your own web apps. Point it at
one of your FastAPI + React/vanilla-JS projects and it tries to break it across five
threat classes, then hands you a ranked report whose fixes line up with your
`/security-web-vulns` and `/security-https-bruteforce` skills.

| # | Threat class | Static (SAST) | Dynamic (DAST) |
|---|--------------|---------------|----------------|
| 1 | Credential extraction | hardcoded secrets, committed `.env` | exposed `/.env`, verbose error/stack-trace leaks |
| 2 | Session hijacking | token read from query param | cookie flags, token-in-URL, JWT `alg:none` / weak secret |
| 3 | Denial of service | missing rate limit, ReDoS, unbounded query | bounded burst rate-limit probe (never floods) |
| 4 | Database injection | string-built SQL / raw `text()` | error-based + time-based oracle (vs. control) |
| 5 | Prompt injection | — | jailbreak / system-prompt-exfil suite + LLM judge |
| 6 | Broken access control | — | IDOR across two identities + mass-assignment PUT (needs `auth`) |
| 7 | SSRF / traversal / redirect | input-as-location patterns | open redirect, path traversal (`/etc/passwd` sig), SSRF via local canary |
| 8 | Security misconfiguration | — | missing CSP/HSTS/headers, credentialed CORS reflection, weak/expiring TLS |
| 9 | Supply chain | vulnerable deps (OSV/offline DB), secrets in git **history** | — |

## Safety

The scope file is a hard contract. **No traffic leaves the process unless the target
host is on the `allowlist`** (`Scope.guard()` enforces this on every request). Non-local
hosts additionally require `i_own_this: true`. Safe mode (default on) means no destructive
writes and no sustained load — DoS testing is detection plus a tiny bounded burst only.

## Web UI (full-stack)

A React + FastAPI app (SQLite-backed) lets you manage targets, run scans from the browser,
browse findings, manage suppressions, and track posture over time.

```bash
scripts/start_all.sh    # backend :8000 + frontend :5173 (Ctrl-C stops both)
scripts/stop_all.sh     # stop from another terminal
```

Then open http://localhost:5173. Backend API docs at http://localhost:8000/docs.

## CLI usage

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config/scope.example.yaml config/scope.yaml   # then edit it
.venv/bin/python -m hacker --scope config/scope.yaml --out report.md --json report.json
```

CI gate: `--fail-on high` exits non-zero if any High/Critical finding is present.

To gate only on *new* issues (not pre-existing backlog), keep a baseline:

```bash
# once, to record the current state:
python -m hacker --scope config/scope.yaml --write-baseline baseline.json
# in CI, fail only on findings introduced since the baseline:
python -m hacker --scope config/scope.yaml --baseline baseline.json --fail-on high
```

Baseline matching and suppression use each finding's stable **fingerprint** (shown in the
report), which ignores line numbers, latency text, and query-string values — so a cosmetic
refactor doesn't make a known finding look new. To permanently mute an accepted risk or a
confirmed false positive, drop its fingerprint into a file and pass `--suppress`:

```bash
echo "a1b2c3d4e5f6a7b8  # accepted: internal-only endpoint" > suppress.txt
python -m hacker --scope config/scope.yaml --suppress suppress.txt
```

## Discovery

Recon enumerates endpoints from `/openapi.json` **and** by crawling HTML (links + forms),
so targets that don't expose an OpenAPI schema (non-FastAPI, or docs disabled in prod) are
still mapped. Injection modules probe both GET query params and POST/PUT/PATCH JSON bodies.

The agent brain / prompt-injection judge uses the provider in `scope.yaml`
(`claude` | `openai` | `cerebras` | `ollama`). If no LLM is configured/reachable, the
prompt-injection module falls back to a heuristic judge — it never silently under-reports.

## Architecture

```
hacker/
  config.py     # scope + safety guardrails (the allowlist guard)
  recon.py      # enumerate endpoints from /openapi.json, cookies, LLM-endpoint sniff
  graph.py      # orchestrator: recon -> modules -> triage (cross-validate SAST+DAST)
  llm.py        # multi-provider LLM layer + injection judge
  modules/      # one file per threat class (run_static / run_dynamic)
  report/       # Markdown + JSON renderer
tests/
  fixtures/vulnerable_app/   # intentionally vulnerable app (modules must find every planted bug)
  fixtures/hardened_app/     # fixed twin (must produce zero High/Critical — false-positive guard)
```

## Tests

```bash
.venv/bin/python -m pytest -q
```
