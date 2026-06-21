"""Command-line entrypoint:  python -m hacker --scope config/scope.yaml"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ScopeError, load_scope
from .graph import run_scan
from .models import Severity
from .report import render_json, render_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hacker", description="An automated, safe-by-default friendly hacker.")
    parser.add_argument("--scope", required=True, help="Path to scope YAML file.")
    parser.add_argument("--out", help="Write the Markdown report to this path.")
    parser.add_argument("--json", help="Write the JSON report to this path.")
    parser.add_argument(
        "--fail-on", choices=[s.value for s in Severity], default=None,
        help="Exit non-zero if any finding at or above this severity is present (for CI).")
    parser.add_argument(
        "--i-own-this", action="store_true",
        help="Confirm ownership of non-local hosts (overrides scope file).")
    args = parser.parse_args(argv)

    try:
        scope = load_scope(args.scope)
        if args.i_own_this:
            scope.i_own_this = True
        report = run_scan(scope)
    except ScopeError as e:
        print(f"[scope error] {e}", file=sys.stderr)
        return 2

    md = render_markdown(report)
    if args.out:
        Path(args.out).write_text(md)
        print(f"Markdown report → {args.out}")
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(render_json(report))
        print(f"JSON report → {args.json}")

    if args.fail_on:
        threshold = Severity(args.fail_on).rank()
        if any(f.severity.rank() >= threshold for f in report.findings):
            print(f"\n[fail-on] findings at or above {args.fail_on} present.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
