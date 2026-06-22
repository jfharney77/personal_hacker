# Spec 03 — Supply-chain module (dependency vulns + git-history secrets)

**Threat class (new):** `ThreatClass.SUPPLY_CHAIN` → `"supply_chain"`
**Style:** pure SAST — new data sources (lockfiles, git log), no target traffic
**Effort:** ~5% — one static module, enum value, two fixture additions, tests.

## Context

Two common, repo-level risks aren't covered by the current secret scan (which only reads
the working tree): (1) **known-vulnerable dependencies**, and (2) **secrets that were
committed and later "removed"** — still recoverable from git history. Both are static,
need no running app, and complement the existing `credentials` module.

## Detection

New file `hacker/modules/supplychain.py` with `run_static(repo_path)` only.
Registered in `modules/__init__.py`; `graph.py` already calls every module's static side
when `scope.repo_path` is set.

### A. Vulnerable dependencies
Parse dependency manifests under `repo_path`:
- Python: `requirements.txt`, `pyproject.toml`, `poetry.lock`.
- Node: `package.json`, `package-lock.json`.

Resolve each `(name, version)` against a vulnerability source, in priority order:
1. If `pip-audit` / `osv-scanner` is installed, shell out and parse JSON (best accuracy).
2. Else, query the **OSV.dev** batch API (`https://api.osv.dev/v1/querybatch`) — note this
   is the one place the module reaches the network, and it is a *trusted* fixed host, not
   the scan target, so it bypasses `Scope.guard()` deliberately (document this clearly).
   Make it opt-out via `scope.offline: bool = False`.
3. Else (offline), match against a small bundled `data/known_vulns.json` of high-profile
   advisories as a best-effort fallback, and emit an INFO finding that full checking needs
   network or a scanner installed.

Each vulnerable dependency → one Finding, severity mapped from the advisory
(CRITICAL/HIGH/MEDIUM), `location = "<manifest>: <pkg>==<version>"`, evidence = advisory
id (e.g. `GHSA-xxxx` / `CVE-...`), remediation = "upgrade to <fixed version>".

### B. Secrets in git history
Walk history without extra deps via `git log`:
```
git -C <repo> log -p --all -- <globs>   # or: git rev-list --all then git grep per commit
```
Run the existing secret regexes from `modules/credentials.py` (`_SECRET_PATTERNS`) over
added lines (`+` diff lines) across all commits. Report a secret that appears in history
but **not** in the current working tree as HIGH "secret committed in git history"
(location = `commit <sha>:<file>`, evidence redacted via `credentials._redact`). Reuse
the placeholder-skip logic so example keys don't trip it.

Bound the work: cap at e.g. the last 1000 commits and skip binary diffs, to keep runtime
predictable on large repos.

## Fixtures
- Dependency: add a `tests/fixtures/vulnerable_app/requirements.txt` pinning a deliberately
  old, known-vulnerable version (assert against the bundled `known_vulns.json` so the test
  is deterministic and offline). `hardened_app` pins patched versions → no findings.
- Git history: the test creates a throwaway git repo in `tmp_path`, commits a fake API key,
  then deletes it in a later commit, and asserts the module flags it from history while the
  working-tree scan alone would not.

## Tests (`tests/test_supplychain.py`)
- Vulnerable manifest → at least one HIGH/CRITICAL dependency finding (offline path).
- Patched manifest → none.
- Git-history secret: planted-then-removed secret is found; a secret only ever in the
  working tree is *not* double-reported here (that's the `credentials` module's job).
- Offline mode (`scope.offline=True`) never makes a network call (assert via monkeypatch).

## Safety / network note
This is the only module that may contact a non-target host (OSV.dev). Make it:
(a) opt-out with `scope.offline`, (b) clearly logged ("querying OSV.dev for N packages"),
and (c) never send source code — only `(name, version)` tuples. Everything else is local.

## Why it's worth it
Catches the class of incident where a key was pushed, force-pushed away, and assumed gone —
plus the steady drip of CVEs in transitive deps — neither of which any current module sees.
