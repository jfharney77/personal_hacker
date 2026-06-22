"""Threat class — supply chain (vulnerable dependencies + secrets in git history).

Pure SAST. Two new data sources the working-tree secret scan never sees:
  A) dependency manifests vs a vulnerability source (pip-audit/osv-scanner if present,
     else the OSV.dev API unless offline, else a small bundled advisory set), and
  B) secrets recoverable from git history even after being "removed".
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from ..models import Finding, Method, Severity, ThreatClass
from ._common import iter_source_files  # noqa: F401  (kept for parity / future use)
from .credentials import _SECRET_PATTERNS, _redact

TC = ThreatClass.SUPPLY_CHAIN
_DATA = Path(__file__).resolve().parent.parent / "data" / "known_vulns.json"
_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM, "low": Severity.LOW}
_MAX_COMMITS = 1000

# requirements.txt: "name==1.2.3" (ignore comments / unpinned / extras markers).
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)")


def run_static(repo_path: str, offline: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_dependency_findings(repo_path, offline))
    findings.extend(_git_history_secret_findings(repo_path))
    return findings


# --- A. dependencies -----------------------------------------------------------
def _load_db() -> dict:
    try:
        return json.loads(_DATA.read_text())
    except OSError:
        return {}


def _parse_requirements(path: Path) -> list[tuple[str, str]]:
    pkgs = []
    for line in path.read_text(errors="ignore").splitlines():
        m = _REQ_RE.match(line)
        if m:
            pkgs.append((m.group(1).lower(), m.group(2)))
    return pkgs


def _parse_package_json(path: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except (OSError, ValueError):
        return []
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            out.append((name.lower(), str(ver).lstrip("^~=")))
    return out


def _dependency_findings(repo_path: str, offline: bool) -> list[Finding]:
    root = Path(repo_path)
    manifests: list[tuple[Path, list[tuple[str, str]]]] = []
    for req in root.rglob("requirements*.txt"):
        if ".venv" not in req.parts and "node_modules" not in req.parts:
            manifests.append((req, _parse_requirements(req)))
    for pkg in root.rglob("package.json"):
        if "node_modules" not in pkg.parts:
            manifests.append((pkg, _parse_package_json(pkg)))

    db = _load_db()
    findings: list[Finding] = []
    for manifest_path, pkgs in manifests:
        for name, version in pkgs:
            advisories = [a for a in db.get(name, []) if version in a.get("versions", [])]
            if not advisories and not offline:
                advisories = _query_osv(name, version)
            for adv in advisories:
                sev = _SEV.get(str(adv.get("severity", "")).lower(), Severity.MEDIUM)
                fixed = adv.get("fixed")
                findings.append(Finding(
                    threat_class=TC, method=Method.STATIC, severity=sev,
                    title=f"Vulnerable dependency: {name}=={version}",
                    location=f"{manifest_path}: {name}=={version}",
                    evidence=adv.get("id", "advisory"),
                    detail=f"{name} {version} is affected by {adv.get('id', 'a known advisory')}.",
                    remediation=f"Upgrade {name} to {fixed or 'a patched version'}."))
    return findings


def _query_osv(name: str, version: str) -> list[dict]:
    """Best-effort OSV.dev lookup. Trusted fixed host (not the scan target); sends only
    (name, version). Never raises into the scan."""
    try:
        import httpx
        r = httpx.post("https://api.osv.dev/v1/query", timeout=8, json={
            "version": version, "package": {"name": name}})
        if r.status_code != 200:
            return []
        vulns = r.json().get("vulns", []) or []
        out = []
        for v in vulns:
            sev = "high"
            for s in v.get("severity", []) or []:
                if s.get("type") == "CVSS_V3":
                    sev = "critical" if "9." in str(s.get("score", "")) else "high"
            out.append({"id": v.get("id", "OSV"), "severity": sev, "fixed": None})
        return out
    except Exception:
        return []


# --- B. secrets in git history -------------------------------------------------
def _git(repo_path: str, *args: str) -> str | None:
    try:
        res = subprocess.run(["git", "-C", repo_path, *args],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout if res.returncode == 0 else None


def _working_tree_secrets(repo_path: str) -> set[str]:
    """Secrets currently present (the credentials module already reports these)."""
    present: set[str] = set()
    tracked = _git(repo_path, "ls-files")
    if tracked is None:
        return present
    for rel in tracked.splitlines():
        fp = Path(repo_path) / rel
        try:
            text = fp.read_text(errors="ignore")
        except OSError:
            continue
        for _, pat in _SECRET_PATTERNS:
            present.update(pat.findall(text) if pat.groups == 0 else
                           [m.group(0) for m in pat.finditer(text)])
    return present


def _git_history_secret_findings(repo_path: str) -> list[Finding]:
    if _git(repo_path, "rev-parse", "--git-dir") is None:
        return []  # not a git repo
    # Pathspec "." (with git's cwd set to repo_path via -C) scopes the scan to this
    # subtree, so a sub-project doesn't get attributed unrelated history.
    diff = _git(repo_path, "log", "-p", "--all", f"-n{_MAX_COMMITS}",
                "--no-color", "--unified=0", "--", ".")
    if not diff:
        return []

    present = _working_tree_secrets(repo_path)
    findings: list[Finding] = []
    seen: set[str] = set()
    current_commit = "unknown"
    for line in diff.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:10]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:]
        if re.search(r"(?i)(example|changeme|your[_-]?key|xxxx|placeholder)", added):
            continue
        for label, pat in _SECRET_PATTERNS:
            for match in pat.finditer(added):
                secret = match.group(0)
                if secret in present or secret in seen:
                    continue  # still live (credentials handles it) or already reported
                seen.add(secret)
                findings.append(Finding(
                    threat_class=TC, method=Method.STATIC, severity=Severity.HIGH,
                    title=f"Secret committed in git history ({label})",
                    location=f"commit {current_commit}", evidence=_redact(added),
                    detail="A credential was committed and later removed, but is still recoverable "
                           "from git history.",
                    remediation="Rotate the secret immediately; purge it from history "
                                "(git filter-repo) if the repo is shared."))
    return findings
