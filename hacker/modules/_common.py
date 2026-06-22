"""Helpers shared by the attack modules (static scanning + dynamic probing)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

import httpx

if TYPE_CHECKING:
    from ..config import Scope
    from ..recon import Endpoint

# Directories never worth scanning.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache"}


def iter_source_files(repo_path: str, suffixes: tuple[str, ...]) -> Iterator[Path]:
    """Yield source files under repo_path with one of the given suffixes."""
    root = Path(repo_path)
    if not root.exists():
        return
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix in suffixes:
            yield p


def send_probe(
    scope: "Scope", client: httpx.Client, ep: "Endpoint", base_url: str,
    values: dict, follow_redirects: bool = True,
) -> httpx.Response | None:
    """Send `values` to an endpoint the right way: query string for GET, JSON body for
    POST/PUT/PATCH. Returns None on transport error. Authorized via Scope.guard()."""
    url = base_url + ep.path
    try:
        if ep.in_body:
            return client.request(ep.method, scope.guard(url), json=values,
                                  follow_redirects=follow_redirects)
        return client.get(scope.guard(url), params=values, follow_redirects=follow_redirects)
    except httpx.HTTPError:
        return None


def injectable_endpoints(recon) -> list:
    """Endpoints worth fuzzing: have params, and aren't path-templated (concrete path)."""
    return [e for e in recon.endpoints
            if e.params and e.method in ("GET", "POST", "PUT", "PATCH") and "{" not in e.path]


def scan_lines(path: Path, pattern: re.Pattern[str]) -> Iterator[tuple[int, str]]:
    """Yield (line_number, line) where pattern matches. Tolerates binary/unreadable files."""
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            yield i, line.strip()
