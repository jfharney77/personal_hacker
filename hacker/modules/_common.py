"""Helpers shared by the static (SAST) side of the attack modules."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

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


def scan_lines(path: Path, pattern: re.Pattern[str]) -> Iterator[tuple[int, str]]:
    """Yield (line_number, line) where pattern matches. Tolerates binary/unreadable files."""
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            yield i, line.strip()
