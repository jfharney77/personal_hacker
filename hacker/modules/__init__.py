"""Attack modules, one per threat class.

Each module exposes some of:
    run_static(repo_path: str) -> list[Finding]
    run_dynamic(scope, recon, client) -> list[Finding]

The orchestrator (hacker.graph) calls whichever are present and cross-validates.
"""
from . import credentials, dbinjection, dos, promptinjection, sessions

# Modules in run order. Each entry: (name, has_static, has_dynamic).
ALL_MODULES = [credentials, sessions, dos, dbinjection, promptinjection]
