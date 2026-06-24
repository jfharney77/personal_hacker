"""Threat class 6 — broken access control (IDOR + mass-assignment).

Needs authentication (see hacker/auth). With two identities it tests horizontal
IDOR: act as user A, then try to reach the same resources as user B and check
whether B receives A's data. It also probes mass-assignment on PUT (mirrors
/security-web-vulns fix #6), restoring any record it modifies.

Only runs dynamically and only when at least one authenticated session exists.
"""
from __future__ import annotations

import re

import httpx

from ..auth import Session
from ..config import Scope
from ..models import Finding, Method, Severity, ThreatClass
from ..recon import Endpoint, Recon

TC = ThreatClass.ACCESS_CONTROL

# Small id space to probe for object references.
_ID_PROBES = [1, 2, 3]
# Privileged fields an attacker would try to smuggle in via mass-assignment.
_INJECT_FIELDS = {"owner": "attacker", "role": "admin", "is_admin": True, "user_id": 9999}

_PARAM_RE = re.compile(r"\{[^}]+\}")


def _has_path_param(path: str) -> bool:
    return bool(_PARAM_RE.search(path))


def _fill(path: str, value: object) -> str:
    return _PARAM_RE.sub(str(value), path)


def _get(client: httpx.Client, scope: Scope, url: str, session: Session) -> httpx.Response | None:
    try:
        return client.get(scope.guard(url), headers=session.headers, cookies=session.cookies)
    except httpx.HTTPError:
        return None


def run_dynamic(
    scope: Scope, recon: Recon, client: httpx.Client, sessions: list[Session] | None = None
) -> list[Finding]:
    sessions = [s for s in (sessions or []) if s.authenticated]
    if not sessions:
        return []  # nothing to do without an authenticated identity

    findings: list[Finding] = []
    id_endpoints = [e for e in recon.endpoints if _has_path_param(e.path)]

    if len(sessions) >= 2:
        findings.extend(_idor(scope, recon, client, id_endpoints, sessions[0], sessions[1]))
    findings.extend(_mass_assignment(scope, recon, client, id_endpoints, sessions[0]))
    findings.extend(_vertical_privilege_escalation(scope, recon, client, sessions[0]))
    return findings


def _idor(
    scope: Scope, recon: Recon, client: httpx.Client,
    endpoints: list[Endpoint], a: Session, b: Session,
) -> list[Finding]:
    findings: list[Finding] = []
    for ep in endpoints:
        if ep.method != "GET":
            continue
        for rid in _ID_PROBES:
            url = recon.base_url + _fill(ep.path, rid)
            ra = _get(client, scope, url, a)
            if ra is None or ra.status_code != 200 or not ra.text.strip():
                continue
            rb = _get(client, scope, url, b)
            if rb is None:
                continue
            # IDOR: a second user retrieves an identical resource that the first user
            # could read. Correct scoping would return 403/404 instead.
            if rb.status_code == 200 and rb.text == ra.text:
                findings.append(Finding(
                    threat_class=TC, method=Method.DYNAMIC, severity=Severity.CRITICAL,
                    title="IDOR — cross-user object access",
                    location=url,
                    evidence=f"identity {b.name!r} read the same resource as {a.name!r} (id={rid})",
                    detail="Two different authenticated users received byte-identical data for "
                           "the same object reference — the endpoint does not scope objects to "
                           "their owner, so any user can read any record by guessing IDs.",
                    remediation="Enforce object-level authorization: verify the resource belongs "
                                "to the requesting user before returning it (return 404 otherwise).",
                ))
                break  # one demonstration per endpoint is enough
    return findings


def _mass_assignment(
    scope: Scope, recon: Recon, client: httpx.Client, endpoints: list[Endpoint], a: Session,
) -> list[Finding]:
    findings: list[Finding] = []
    for ep in endpoints:
        if ep.method not in ("PUT", "PATCH"):
            continue
        for rid in _ID_PROBES:
            url = recon.base_url + _fill(ep.path, rid)
            original = _get(client, scope, url, a)
            if original is None or original.status_code != 200:
                continue
            try:
                base_body = original.json() if "json" in original.headers.get("content-type", "") else {}
            except ValueError:
                base_body = {}

            payload = {**(base_body if isinstance(base_body, dict) else {}), **_INJECT_FIELDS}
            try:
                resp = client.request(
                    ep.method, scope.guard(url), json=payload,
                    headers=a.headers, cookies=a.cookies)
            except httpx.HTTPError:
                continue

            reflected = _reflected_privileged_fields(resp)
            if reflected:
                findings.append(Finding(
                    threat_class=TC, method=Method.DYNAMIC, severity=Severity.HIGH,
                    title="Mass-assignment via unfiltered PUT/PATCH body",
                    location=url,
                    evidence=f"injected fields accepted: {reflected}",
                    detail="The update endpoint accepted attacker-controlled privileged fields "
                           "(e.g. owner/role/is_admin) from the raw request body and applied them.",
                    remediation="Bind updates to an explicit allowlist of editable fields; never "
                                "pass a raw dict into the model. See /security-web-vulns fix #6.",
                ))
                _restore(client, scope, url, ep.method, base_body, a)  # leave staging as we found it
                break
            _restore(client, scope, url, ep.method, base_body, a)
    return findings


def _vertical_privilege_escalation(
    scope: Scope, recon: Recon, client: httpx.Client, session: Session
) -> list[Finding]:
    findings: list[Finding] = []
    admin_paths = [e for e in recon.endpoints if "admin" in e.path.lower() and e.method == "GET"]
    for ep in admin_paths:
        url = recon.base_url + ep.path
        try:
            resp = client.get(scope.guard(url), headers=session.headers, cookies=session.cookies)
        except httpx.HTTPError:
            continue
        # Admin endpoint reachable by a non-admin identity: missing role-based auth.
        if resp.status_code == 200 and resp.text.strip():
            findings.append(Finding(
                threat_class=TC, method=Method.DYNAMIC, severity=Severity.HIGH,
                title="Vertical privilege escalation — admin endpoint reachable by regular user",
                location=url,
                evidence=f"identity {session.name!r} received 200 from {ep.path}",
                detail="An endpoint whose path suggests administrative functionality returned "
                       "success for a regular authenticated identity. This indicates missing "
                       "role-based access control.",
                remediation="Enforce role-based authorization on admin endpoints and return 403 "
                            "for non-admin identities.",
            ))
            break  # one demonstration is enough
    return findings


def _reflected_privileged_fields(resp: httpx.Response) -> dict:
    if resp.status_code >= 400:
        return {}
    try:
        data = resp.json()
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in _INJECT_FIELDS.items() if str(data.get(k)) == str(v)}


def _restore(client, scope, url, method, base_body, a: Session) -> None:
    """Best-effort restore of a record we modified, keeping safe mode honest."""
    if not isinstance(base_body, dict) or not base_body:
        return
    try:
        client.request(method, scope.guard(url), json=base_body, headers=a.headers, cookies=a.cookies)
    except httpx.HTTPError:
        pass
