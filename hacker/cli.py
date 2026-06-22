"""Command-line entrypoint:  python -m hacker --scope config/scope.yaml"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .baseline import load_baseline_keys, new_findings, write_baseline
from .config import ScopeError, load_scope
from .graph import run_scan
from .models import Severity
from .report import render_json, render_markdown


def _read_fingerprint_file(path: str) -> list[str]:
    """Read a suppression file: one fingerprint per line, '#' comments and blanks ignored."""
    out = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hacker", description="An automated, safe-by-default friendly hacker.")
    parser.add_argument("--scope", required=True, help="Path to scope YAML file.")
    parser.add_argument("--out", help="Write the Markdown report to this path.")
    parser.add_argument("--json", help="Write the JSON report to this path.")
    parser.add_argument(
        "--fail-on", choices=[s.value for s in Severity], default=None,
        help="Exit non-zero if a finding at or above this severity is present. With "
             "--baseline, only NEW findings count (for CI gating).")
    parser.add_argument(
        "--baseline", help="Previous report JSON; only findings new since then are gated.")
    parser.add_argument(
        "--write-baseline", help="Write this run as the new baseline JSON.")
    parser.add_argument(
        "--suppress", help="File of finding fingerprints to suppress (one per line; "
                           "'#' comments allowed). Merged with scope.suppress.")
    parser.add_argument(
        "--i-own-this", action="store_true",
        help="Confirm ownership of non-local hosts (overrides scope file).")
    args = parser.parse_args(argv)

    try:
        scope = load_scope(args.scope)
        if args.i_own_this:
            scope.i_own_this = True
        if args.suppress:
            scope.suppress = list(scope.suppress) + _read_fingerprint_file(args.suppress)
        report = run_scan(scope)
    except ScopeError as e:
        print(f"[scope error] {e}", file=sys.stderr)
        return 2

    if report.suppressed:
        print(f"({len(report.suppressed)} finding(s) suppressed by the suppression list.)")

    md = render_markdown(report)
    if args.out:
        Path(args.out).write_text(md)
        print(f"Markdown report → {args.out}")
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(render_json(report))
        print(f"JSON report → {args.json}")

    # Decide which findings the gate considers: everything, or only what's new.
    gated = report.findings
    if args.baseline is not None:
        baseline_keys = load_baseline_keys(args.baseline)
        gated = new_findings(report, baseline_keys)
        print(f"\n{len(gated)} new finding(s) since baseline "
              f"({len(report.findings) - len(gated)} pre-existing).")
        for f in gated:
            print(f"  + [{f.severity.value}] {f.title} @ {f.location or '—'}")

    if args.write_baseline:
        write_baseline(report, args.write_baseline)
        print(f"Baseline written → {args.write_baseline}")

    if args.fail_on:
        threshold = Severity(args.fail_on).rank()
        if any(f.severity.rank() >= threshold for f in gated):
            scope_word = "new " if args.baseline is not None else ""
            print(f"\n[fail-on] {scope_word}findings at or above {args.fail_on} present.",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
