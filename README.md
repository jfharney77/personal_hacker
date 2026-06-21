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

## Safety

The scope file is a hard contract. **No traffic leaves the process unless the target
host is on the `allowlist`** (`Scope.guard()` enforces this on every request). Non-local
hosts additionally require `i_own_this: true`. Safe mode (default on) means no destructive
writes and no sustained load — DoS testing is detection plus a tiny bounded burst only.

## Usage

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
