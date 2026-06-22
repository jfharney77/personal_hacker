# personal_hacker — codebase guide

An automated, **safe-by-default** security scanner for your own FastAPI + React/JS apps,
now with a full-stack UI. You point it at a project (a running URL and/or its source) and
it tries to break it across nine threat classes, persisting results so you can track
posture over time.

## Layout

```
hacker/            # the scanning ENGINE (pure Python, importable, CLI-runnable)
  config.py        # Scope + safety guardrails — Scope.guard() gates every request
  recon.py         # endpoint discovery: OpenAPI + HTML crawl (links/forms)
  graph.py         # orchestrator: recon -> modules -> triage -> suppressions
  llm.py           # multi-provider LLM layer (claude/openai/cerebras/ollama) + injection judge
  baseline.py      # baseline diff for CI gating (keys on Finding.fingerprint)
  models.py        # Finding / Severity / ThreatClass / ScanReport (pydantic)
  modules/         # one file per threat class; each has run_static and/or run_dynamic
  report/render.py # Markdown + JSON report
  cli.py           # `python -m hacker --scope scope.yaml`
  data/            # bundled offline advisory DB for the supply-chain module

backend/           # FastAPI + SQLite persistence wrapping the engine
  db.py            # SQLite engine (PERSONAL_HACKER_DB env overrides path)
  models.py        # SQLModel tables: Target, Scan, Finding, Suppression
  services.py      # target_to_scope() + run_scan_for() (engine call -> DB)
  main.py          # REST API (targets, scans, findings, suppressions, stats, trend)

frontend/          # React + Vite UI (Dashboard, Targets, ScanDetail, Suppressions)
scripts/           # start_backend.sh, start_frontend.sh, start_all.sh, stop_all.sh
tests/             # pytest; fixtures/vulnerable_app + hardened_app are scan targets
docs/specs/        # design specs for modules
```

## Nine threat classes (hacker/modules/)

credentials, sessions, dos, dbinjection, promptinjection, accesscontrol (IDOR +
mass-assignment), inputabuse (SSRF/traversal/redirect), misconfig (headers/CORS/TLS),
supplychain (vulnerable deps + git-history secrets).

## Running

- **Full app (UI + API):** `scripts/start_all.sh` (backend :8000, frontend :5173);
  `scripts/stop_all.sh` to stop. The backend runs as a module (`backend.main:app`) from
  the repo root because it uses package-relative imports; it shares the root `.venv`.
- **CLI only:** `.venv/bin/python -m hacker --scope config/scope.yaml --out report.md`
- **Tests:** `.venv/bin/python -m pytest -q` (engine + backend; 59 tests)

## Conventions & gotchas

- **Safety is non-negotiable:** every outbound request goes through `Scope.guard()` (host
  allowlist; non-local hosts need `i_own_this`). Safe mode keeps DoS to a bounded burst.
  When adding a dynamic probe, route it through `Scope.guard()` / `_common.send_probe()`.
- **New module checklist:** add a `ThreatClass`, create `modules/<x>.py` with
  `run_static`/`run_dynamic`, register it in `modules/__init__.py` AND wire it into
  `graph.py`, add a vulnerable + hardened fixture pair, and a test. Hardened fixtures must
  produce zero High/Critical (false-positive guard).
- **Finding identity:** `Finding.fingerprint` is the stable id (ignores line numbers /
  latency / query values). Baselines and suppressions key on it — don't put volatile data
  in `title`/`location` or you'll break matching.
- **`backend/models.py` must NOT use `from __future__ import annotations`** — SQLAlchemy
  can't resolve relationship generics (`list["Scan"]`) when annotations are strings.
- **Determinism in tests:** set `offline=True` to avoid the supply-chain module's OSV.dev
  network calls. Dynamic tests drive the fixture apps in-process via Starlette `TestClient`.
- The SQLite DB defaults to `personal_hacker.db` at the repo root (gitignored).
