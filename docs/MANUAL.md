# personal_hacker — User Manual

An automated, **safe-by-default** security scanner for your own FastAPI + React/JS apps.
You point it at a project — a running URL and/or its source — and it tries to break it
across nine threat classes, then gives you a ranked report. Use it two ways:

- **Web UI** — manage targets, run scans, browse findings, manage suppressions, track posture.
- **CLI** — scriptable, CI-friendly, exits non-zero on findings.

> ⚠️ **Only scan systems you own or are authorized to test.** The tool sends real attack
> traffic. Its safety rails (below) refuse to touch any host not on your allowlist.

---

## 1. Install

Requirements: Python 3.12+, and Node 18+ (only for the web UI).

```bash
git clone <your-repo-url> personal_hacker && cd personal_hacker
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Sanity check: `.venv/bin/python -m pytest -q` (should pass).

---

## 2. Core safety model (read this first)

Everything the tool does is gated by a **scope**. The single hard rule:

> No network request leaves the process unless its host is on the `allowlist`.

- **`allowlist`** — hostnames the tool may send traffic to. Anything else is refused before a
  packet is sent.
- **`i_own_this`** — must be `true` to scan a non-local (public/production-looking) host. A
  deliberate speed bump; localhost/private IPs don't need it.
- **`safe_mode`** (default `true`) — no sustained load and no gratuitous writes. DoS testing is
  a small bounded burst, never a flood.

If you remember one thing: **the scope file is the safety contract.**

---

## 3. The scope file

Both the CLI and the engine are driven by a YAML scope. Copy the example and edit:

```bash
cp config/scope.example.yaml config/scope.yaml
```

```yaml
# Hosts the scanner is allowed to touch. Nothing off this list is ever contacted.
allowlist: [localhost, 127.0.0.1]

# Running app(s) to attack dynamically (DAST). Every host here must be on the allowlist.
target_urls: [http://localhost:8000]

# Local source path for static analysis (SAST). Optional — omit for black-box-only.
repo_path: /home/john/github/my_app

safe_mode: true          # keep true unless you fully understand the consequences
i_own_this: false        # set true to scan a non-local host you own
offline: false           # true = skip the supply-chain module's OSV.dev network lookups
ssrf_canary: false       # true = actively confirm SSRF via a localhost-only listener

llm_provider: claude     # claude | openai | cerebras | ollama (agent brain / injection judge)
llm_model: claude-opus-4-8

# Optional: log in so dynamic scans run as a real user (unlocks IDOR / access-control tests).
# Two identities are needed for cross-user IDOR.
# auth:
#   login_url: http://localhost:8000/auth/login
#   method: POST
#   token_json_path: token         # where the token sits in the JSON response
#   token_header: X-Session-Token   # header to send it in (or use token_cookie)
#   identities:
#     - {name: alice, body: {username: alice, password: secret1}}
#     - {name: bob,   body: {username: bob,   password: secret2}}

# Optional: fingerprints to permanently mute (accepted risk / false positive).
# suppress: [a1b2c3d4e5f6a7b8]
```

**SAST vs DAST:**
- Give `repo_path` only → static scan (read the code), no running app needed.
- Give `target_urls` only → dynamic scan (attack the live app), black-box.
- Give both → the richest scan; findings that show up statically *and* dynamically are marked
  ✅ **cross-validated** (highest confidence).

---

## 4. CLI usage

```bash
.venv/bin/python -m hacker --scope config/scope.yaml --out report.md --json report.json
```

### All flags

| Flag | Purpose |
|------|---------|
| `--scope PATH` | **(required)** the scope YAML. |
| `--out PATH` | write the Markdown report to a file (otherwise printed to stdout). |
| `--json PATH` | write the JSON report (for diffing / dashboards / CI). |
| `--fail-on {info,low,medium,high,critical}` | exit non-zero if any finding at/above this severity is present. With `--baseline`, only **new** findings count. |
| `--baseline PATH` | a previous JSON report; only findings new since then are gated. |
| `--write-baseline PATH` | save this run as the new baseline. |
| `--suppress PATH` | a file of fingerprints to mute (one per line, `#` comments allowed). |
| `--i-own-this` | confirm ownership of non-local hosts (overrides the scope file). |

### Reading the report

Findings are ranked worst-first. Each shows severity, threat class, method (static/dynamic),
location, evidence, a remediation, and a **fingerprint** — a stable id you can copy into a
suppression file or baseline.

---

## 5. The nine threat classes

| # | Class | What it checks |
|---|-------|----------------|
| 1 | Credential extraction | hardcoded secrets, committed `.env`, exposed secret files, verbose error leaks |
| 2 | Session hijacking | cookie flags (HttpOnly/Secure/SameSite), token-in-URL, JWT `alg:none` / weak secret |
| 3 | Denial of service | missing rate limiting, ReDoS, unbounded queries (bounded probe — never floods) |
| 4 | Database injection | SQLi (error + time-based, GET and POST bodies), raw string-built SQL in source |
| 5 | Prompt injection | jailbreak / system-prompt-exfil suite against LLM endpoints (LLM-judged) |
| 6 | Broken access control | IDOR across two identities, mass-assignment, vertical privilege escalation (needs `auth`) |
| 7 | SSRF / traversal / redirect | input-as-location bugs; SSRF confirmed via a localhost canary |
| 8 | Security misconfiguration | missing CSP/HSTS/headers, credentialed CORS reflection, weak/expiring TLS |
| 9 | Supply chain | vulnerable dependencies (OSV / offline DB), secrets in git **history** |

Discovery runs off `/openapi.json` **and** an HTML crawl (links + forms), so non-FastAPI apps
or apps with docs disabled are still mapped.

---

## 6. CI gating (only fail on *new* problems)

```bash
# once, to record the current state as acceptable:
.venv/bin/python -m hacker --scope config/scope.yaml --write-baseline baseline.json

# in CI, fail the build only on findings introduced since the baseline:
.venv/bin/python -m hacker --scope config/scope.yaml --baseline baseline.json --fail-on high
```

Matching uses each finding's stable **fingerprint** (it ignores line numbers, latency text,
and query-string values), so a cosmetic refactor doesn't make a fixed finding look new.

To permanently mute an accepted risk or confirmed false positive:

```bash
echo "a1b2c3d4e5f6a7b8  # accepted: internal-only endpoint" > suppress.txt
.venv/bin/python -m hacker --scope config/scope.yaml --suppress suppress.txt
```

---

## 7. Web UI

Start both the FastAPI backend and the React dev server:

```bash
scripts/start_all.sh     # backend → :8000, frontend → :5173  (Ctrl-C stops both)
```

Open **http://localhost:5173**. (API docs at http://localhost:8000/docs.)

Stop from another terminal:

```bash
scripts/stop_all.sh
```

Or run the halves independently: `scripts/start_backend.sh`, `scripts/start_frontend.sh`.

### UI walkthrough

1. **Targets** — click *Add a target*: give it a name, the target URL(s), the allowlist, and
   (optionally) a repo path; toggle safe-mode / offline / SSRF-canary / "I own this." Each
   saved target has **Run scan** and **Delete**.
2. **Run scan** — kicks off a scan in the background and drops you on its result page when done.
3. **Scan detail** — severity summary + every finding with a badge, evidence, remediation, and
   fingerprint. Hit **Suppress** on any finding (with an optional reason) to mute it everywhere;
   **Unsuppress** to bring it back.
4. **Dashboard** — totals, open findings by severity (latest scan per target), and recent scans.
5. **Suppressions** — manage every muted fingerprint in one place.

Data persists in a SQLite DB at `personal_hacker.db` (override with `PERSONAL_HACKER_DB`).

---

## 8. Common recipes

**Black-box scan of a local app:**
```yaml
allowlist: [localhost]
target_urls: [http://localhost:8000]
```

**Source-only scan (no running app):**
```yaml
allowlist: [localhost]
repo_path: /path/to/repo
offline: true   # fully offline if you also skip OSV.dev
```

**Authenticated scan to find IDOR / access-control bugs:** add the `auth:` block with two
identities (see §3).

**Scan a staging server you own:**
```yaml
allowlist: [staging.myapp.com]
target_urls: [https://staging.myapp.com]
i_own_this: true
```

**Actively confirm SSRF:** set `ssrf_canary: true` (binds a localhost-only listener; the tool
only ever asks the target to fetch *that* — never real internal hosts).

---

## 9. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `Refusing to touch <host>: not in scope allowlist` | add the host to `allowlist`. This is the safety guard working. |
| `<host> looks like a public/production host` | set `i_own_this: true` (only if you own it). |
| Scan returns almost nothing | target unreachable, or no endpoints discovered — check the URL and that the app is running. SAST needs `repo_path`. |
| Supply-chain findings differ between runs | live OSV.dev lookups vary; set `offline: true` for deterministic results. |
| Prompt-injection seems weak | no LLM configured/reachable, so it fell back to the heuristic judge. Set `llm_provider` + the relevant API key env var. |
| UI shows "Is the backend running?" | start the backend (`scripts/start_backend.sh`) or use `start_all.sh`. |
| Backend won't import | it runs as `backend.main:app` from the repo root (package-relative imports) and shares the root `.venv`. |

---

## 10. Where things live

```
hacker/          # the scanning engine (CLI: python -m hacker)
backend/         # FastAPI + SQLite persistence (REST API)
frontend/        # React + Vite UI
scripts/         # start_all / stop_all / start_backend / start_frontend
config/          # scope.example.yaml (copy to scope.yaml)
docs/            # this manual + design specs
tests/           # pytest; fixtures/ are intentionally vulnerable + hardened apps
```

See `CLAUDE.md` for a developer-oriented codebase guide, `TODO.md` for the roadmap, and
`docs/specs/` for module design specs.
