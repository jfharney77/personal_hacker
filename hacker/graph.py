"""Orchestrator — the hacker brain.

Runs recon, dispatches every module's static + dynamic probes, then triages:
cross-validates findings that appear in both SAST and DAST (raising confidence)
and assembles a ScanReport.

The pipeline is plain Python in `run_scan()` so it's trivially testable. When
LangGraph is installed, `build_graph()` exposes the same flow as a StateGraph
(recon -> attack -> triage) for visualization/streaming.
"""
from __future__ import annotations

import httpx

from .auth import authenticate_all
from .config import Scope
from .llm import make_injection_judge
from .models import Finding, Method, ScanReport, ThreatClass
from .modules import (
    accesscontrol, credentials, dbinjection, dos, inputabuse, misconfig,
    promptinjection, sessions, supplychain,
)
from .modules.inputabuse import SSRFCanary
from .recon import Recon, run_recon


def run_scan(scope: Scope, client: httpx.Client | None = None) -> ScanReport:
    """Execute the full scan and return a triaged report."""
    report = ScanReport(
        target_repo=scope.repo_path,
        target_urls=list(scope.target_urls),
        safe_mode=scope.safe_mode,
    )

    # --- Static phase (SAST): one pass over the repo, independent of any target. ---
    if scope.repo_path:
        report.add(*credentials.run_static(scope.repo_path))
        report.add(*sessions.run_static(scope.repo_path))
        report.add(*dos.run_static(scope.repo_path))
        report.add(*dbinjection.run_static(scope.repo_path))
        report.add(*inputabuse.run_static(scope.repo_path))
        report.add(*supplychain.run_static(scope.repo_path, offline=scope.offline))

    # --- Dynamic phase (DAST): per running target. ---
    judge = make_injection_judge(scope)  # LLM judge if available, else None -> heuristic
    owns_client = client is None
    client = client or httpx.Client(timeout=15.0, follow_redirects=True, verify=False)
    # Stand up the SSRF canary only if explicitly enabled (binds localhost only).
    canary_cm = SSRFCanary() if scope.ssrf_canary else None
    if canary_cm is not None:
        canary_cm.__enter__()
    try:
        # Authenticate once (if configured) and scan the rest as a logged-in user.
        sessions_ = authenticate_all(scope, client)
        primary = next((s for s in sessions_ if s.authenticated), None)
        if primary:
            client.headers.update(primary.headers)
            client.cookies.update(primary.cookies)

        for url in scope.target_urls:
            recon: Recon = run_recon(scope, url, client=client)
            if not recon.reachable:
                continue
            report.add(*credentials.run_dynamic(scope, recon, client))
            report.add(*sessions.run_dynamic(scope, recon, client))
            report.add(*dos.run_dynamic(scope, recon, client))
            report.add(*dbinjection.run_dynamic(scope, recon, client))
            report.add(*promptinjection.run_dynamic(scope, recon, client, judge=judge))
            report.add(*accesscontrol.run_dynamic(scope, recon, client, sessions=sessions_))
            report.add(*inputabuse.run_dynamic(scope, recon, client, canary=canary_cm))
            report.add(*misconfig.run_dynamic(scope, recon, client))
    finally:
        if canary_cm is not None:
            canary_cm.__exit__(None, None, None)
        if owns_client:
            client.close()

    _triage(report)
    report.apply_suppressions(set(scope.suppress))
    return report


def _triage(report: ScanReport) -> None:
    """Cross-validate: when a threat class shows up in both SAST and DAST, mark both
    findings as cross-validated (a static smell confirmed by a live exploit, or vice
    versa, is far higher confidence than either alone)."""
    classes_static = {f.threat_class for f in report.findings if f.method == Method.STATIC}
    classes_dynamic = {f.threat_class for f in report.findings if f.method == Method.DYNAMIC}
    confirmed: set[ThreatClass] = classes_static & classes_dynamic
    for f in report.findings:
        if f.threat_class in confirmed:
            f.cross_validated = True


# --- Optional LangGraph wrapper -------------------------------------------------
def build_graph():
    """Return a compiled LangGraph StateGraph mirroring run_scan, or raise if
    LangGraph isn't installed. The plain `run_scan` is the source of truth."""
    from typing import TypedDict

    from langgraph.graph import END, START, StateGraph

    class State(TypedDict):
        scope: Scope
        report: ScanReport

    def _node_scan(state: State) -> State:
        return {"scope": state["scope"], "report": run_scan(state["scope"])}

    g = StateGraph(State)
    g.add_node("scan", _node_scan)
    g.add_edge(START, "scan")
    g.add_edge("scan", END)
    return g.compile()
