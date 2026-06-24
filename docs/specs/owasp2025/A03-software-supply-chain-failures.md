# A03:2025 — Software Supply Chain Failures

**Definition**: The application is compromised through insecure dependencies, build pipelines, or third-party components, including known-vulnerable packages and secrets leaked into version history.

## Current coverage

`hacker/modules/supplychain.py` is the dedicated SAST module:

- **Vulnerable dependencies**: parses `requirements*.txt` and `package.json`, then matches versions against a bundled offline advisory DB (`hacker/data/known_vulns.json`) or the OSV.dev API unless `offline=True` (`@hacker/modules/supplychain.py:65-92`).
- **Secrets in git history**: runs `git log -p` over the last 1000 commits and reports secrets that were added but are no longer in the working tree (`@hacker/modules/supplychain.py:145-182`).
- The vulnerable fixture includes a `requirements.txt` with known-vulnerable versions; the hardened twin uses safer versions.

The module reuses secret patterns from `credentials.py` (`@hacker/modules/supplychain.py:17-18`) and redacts evidence before reporting.

## Gaps / future work

- **Dependency confusion**: no detection of private packages that could be shadowed on public registries (e.g., a package name without an internal scope).
- **Compromised packages / malicious code**: OSV.dev and the bundled DB only report known CVEs, not malware or typosquatting.
- **SBOM generation/validation**: no `sbom` or `package-lock.json` integrity checks.
- **Build pipeline integrity**: no CI/CD configuration scanning (e.g., unsigned artifacts, insecure `curl | bash` install steps, leaked secrets in `.github/workflows`).
- **Git history coverage**: the 1000-commit limit may miss older leaks; the scan also does not check uncommitted staged changes or reflog.
- **Lockfile drift**: no check that `package-lock.json` or `requirements.txt` are consistent with installed versions.

## Suggested fixture additions

- Add a vulnerable fixture `requirements.txt` containing a package known to be in the bundled DB (e.g., `pyyaml==5.3.1`) and verify the hardened twin uses a patched version.
- Add a `.github/workflows/ci.yml` that downloads a script over HTTP and passes secrets via env; the hardened twin should use pinned actions and HTTPS.

## Decomposition

This entry does **not** need decomposition. The existing module covers the core supply-chain risks well. Add dependency-confusion and CI/CD scanning as incremental extensions.
