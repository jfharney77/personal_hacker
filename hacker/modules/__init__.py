"""Attack modules, one per threat class.

Each module exposes some of:
    run_static(repo_path: str) -> list[Finding]
    run_dynamic(scope, recon, client) -> list[Finding]

The orchestrator (hacker.graph) calls whichever are present and cross-validates.
"""
from . import accesscontrol, credentials, dbinjection, dos, promptinjection, sessions

# Modules in run order.
ALL_MODULES = [credentials, sessions, dos, dbinjection, promptinjection, accesscontrol]
