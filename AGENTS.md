# personal_hacker — agent guide

A safe-by-default automated security scanner for your own FastAPI + React/vanilla-JS web apps. It combines SAST (static analysis over the repo) with DAST (dynamic probes against a running app) across nine threat classes, then produces a ranked, cross-validated report.

This repo has three parts:

- `hacker/` — the scanning engine (pure Python, CLI-runnable, importable).
- `backend/` + `frontend/` — a React + FastAPI full-stack UI with SQLite persistence.
- `tests/` — pytest suite using intentionally vulnerable + hardened fixture apps.

## Quick reference

```bash
# Install dependencies
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Full-stack UI
scripts/start_all.sh      # backend http://localhost:8000, frontend http://localhost:5173
scripts/stop_all.sh       # stop both

# CLI scan (copy and edit the example scope first)
cp config/scope.example.yaml config/scope.yaml
.venv/bin/python -m hacker --scope config/scope.yaml --out report.md --json report.json

# Tests
.venv/bin/python -m pytest -q
```

## Repository layout

```
hacker/                  # scanning engine
  __main__.py            # python -m hacker entrypoint
  cli.py                 # argparse + report writers
  config.py              # Scope + safety guardrails (Scope.guard is the gate)
  models.py              # Finding, Severity, ThreatClass, Method, ScanReport
  graph.py               # orchestrator: run_scan() + optional LangGraph wrapper
  recon.py               # endpoint discovery: /openapi.json + HTML crawl
  auth.py                # login as configured identities for authenticated scans
  llm.py                 # multi-provider LLM client + injection judge
  baseline.py            # diff reports by stable fingerprint for CI gating
  modules/               # one file per threat class
    _common.py           # helpers: iter_source_files, send_probe, injectable_endpoints
    credentials.py       # SAST: hardcoded secrets, .env; DAST: exposed files, trace leaks
    sessions.py          # SAST: token from query; DAST: cookie flags, token-in-URL, JWT flaws
    dos.py               # SAST: ReDoS, unbounded queries; DAST: bounded rate-limit burst
    dbinjection.py       # SAST: string-built SQL; DAST: error/time-based injection oracle
    promptinjection.py   # DAST: adversarial payloads against LLM endpoints + judge
    accesscontrol.py     # DAST: IDOR (needs 2 identities) + mass-assignment on PUT/PATCH
    inputabuse.py        # SAST+DAST: SSRF (canary), path traversal, open redirect
    misconfig.py         # DAST: missing headers, permissive CORS, weak TLS/expiring cert
    supplychain.py       # SAST: vulnerable deps (OSV/offline DB), secrets in git history
  report/render.py       # Markdown + JSON renderers
  data/known_vulns.json  # bundled offline advisory DB for supply-chain scans

backend/                 # FastAPI persistence layer
  db.py                  # SQLite engine (PERSONAL_HACKER_DB overrides path)
  models.py              # SQLModel tables: Target, Scan, Finding, Suppression
  services.py            # target_to_scope() and run_scan_for() (engine bridge)
  main.py                # REST API + CORS + dashboard endpoints

frontend/                # React + Vite UI
  vite.config.js         # dev server on :5173, proxies /api to :8000
  src/App.jsx            # routes: Dashboard, Targets, ScanDetail, Suppressions
  src/api.js             # thin fetch wrapper over backend endpoints
  src/pages/*.jsx        # UI pages
  src/styles.css         # custom CSS (no external UI framework)

scripts/
  start_all.sh, stop_all.sh, start_backend.sh, start_frontend.sh

tests/
  conftest.py            # fixtures: vuln_app, vuln_client, hardened_client, local_scope
  fixtures/vulnerable_app/main.py   # intentionally vulnerable target
  fixtures/hardened_app/main.py     # fixed twin (must produce zero High/Critical)
  test_*.py              # module, e2e, backend, baseline, suppression, config, crawler tests
```

## Core abstractions

- `Finding` (`hacker/models.py`): a single result with `threat_class`, `method` (static/dynamic), `severity`, `title`, `detail`, `location`, `evidence`, `remediation`, and `cross_validated`.
- `Finding.fingerprint`: a stable 16-char SHA-1 hash of `threat_class|title|normalized_location`. It ignores line numbers, query values, and latency text so baseline/suppression matching survives refactors.
- `ScanReport`: the full result. It holds `findings`, `suppressed`, and can rank + count.
- `Scope` (`hacker/config.py`): the safety contract. Every outbound request must pass `Scope.guard(url)` before any module touches a target. Non-local hosts require `i_own_this: true`.
- `Recon` (`hacker/recon.py`): pre-attack target map, built from `/openapi.json` and HTML crawling.
- `Session` (`hacker/auth.py`): an authenticated identity for DAST; two identities unlock IDOR testing.
- `Judge` (`hacker/llm.py` + `hacker/modules/promptinjection.py`): `judge(payload, reply) -> (leaked, why)`; LLM-backed with heuristic fallback.

## How the engine runs

`hacker/graph.py:run_scan()` is the source of truth:

1. Static phase (if `repo_path` is set): runs SAST modules in parallel over the repo.
2. Dynamic phase: for each `target_url`, authenticate if configured, run recon, then run each DAST module.
3. Triage: cross-validates any threat class seen in both SAST and DAST by marking those findings.
4. Suppression: moves findings whose fingerprints are in `scope.suppress` to `report.suppressed`.
5. Render: `hacker/report/render.py` produces Markdown + JSON.

## Safety rules

Safety is non-negotiable and lives in `hacker/config.py`:

- Every outbound request goes through `Scope.guard(url)` before `httpx` is called.
- Only hosts in `scope.allowlist` are reachable; non-local hosts also need `i_own_this: true`.
- `safe_mode` (default `true`) means no destructive writes and no sustained load. The DoS module probes with a 15-request burst and sleeps 20ms between requests.
- The SSRF canary (`inputabuse.SSRFCanary`) only ever asks the target to fetch localhost; it never points the target at real internal infrastructure.
- The access-control module restores modified records after mass-assignment tests (best-effort).

When adding a new dynamic probe, route it through `Scope.guard()` and prefer `_common.send_probe()`.

## Conventions and gotchas

- Use `from __future__ import annotations` in engine files, **except** `backend/models.py` — SQLModel/SQLAlchemy cannot resolve stringified generics (`list["Scan"]`) in relationships when future annotations are enabled.
- Imports belong at the top of the file. Never add imports mid-file.
- The engine uses `pydantic` v2 models; the backend uses `SQLModel` v0.0.38.
- Dynamic tests use Starlette's `TestClient` (an `httpx.Client` subclass) so tests run in-process.
- Set `offline=True` in tests to avoid non-deterministic OSV.dev network calls.
- The SQLite DB defaults to `personal_hacker.db` at the repo root and is gitignored. Override with `PERSONAL_HACKER_DB`.
- The backend runs as `backend.main:app` from the repo root because it uses package-relative imports; it shares the root `.venv`.
- The frontend dev server proxies `/api` to `http://localhost:8000`; production builds expect the same origin or an external reverse proxy.

## Adding a new threat module

1. Add a `ThreatClass` value in `hacker/models.py`.
2. Create `hacker/modules/<new>.py` with `run_static(repo_path)` and/or `run_dynamic(scope, recon, client, ...)`.
3. Import it in `hacker/modules/__init__.py` and add it to `ALL_MODULES`.
4. Wire it into `hacker/graph.py:run_scan()` in the static and/or dynamic phase.
5. Add a vulnerable fixture endpoint in `tests/fixtures/vulnerable_app/main.py` and a hardened twin in `tests/fixtures/hardened_app/main.py`.
6. Add tests in `tests/test_modules.py` (or a new file) that prove the module finds the bug and the hardened twin produces no High/Critical for that class.

## Common commands

```bash
# Full UI
scripts/start_all.sh
scripts/stop_all.sh

# Backend only (useful for frontend dev)
.venv/bin/uvicorn backend.main:app --reload --port 8000

# Frontend only
.venv/bin/python scripts/start_frontend.sh   # or: cd frontend && npm run dev

# CLI scan
.venv/bin/python -m hacker --scope config/scope.yaml --out report.md --json report.json
.venv/bin/python -m hacker --scope config/scope.yaml --fail-on high
.venv/bin/python -m hacker --scope config/scope.yaml --baseline baseline.json --fail-on high
.venv/bin/python -m hacker --scope config/scope.yaml --write-baseline baseline.json

# Tests
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest tests/test_e2e.py -q
.venv/bin/python -m pytest tests/test_backend.py -q
```

## Key design docs

- `README.md` — user-facing overview, CLI examples, and threat-class table.
- `CLAUDE.md` — existing codebase guide with conventions and gotchas.
- `TODO.md` — deferred work (CI integration, safe-mode enforcement, SARIF, AST-based SAST, etc.).
- `docs/specs/` — design specifications for individual modules.
