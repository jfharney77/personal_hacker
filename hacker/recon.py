"""Recon: map the running target before any module attacks it.

Pulls the OpenAPI/Swagger schema (FastAPI serves it at /openapi.json), enumerates
endpoints, records response headers and Set-Cookie, and guesses which endpoints
talk to an LLM (so the prompt-injection module knows where to aim).

Every outbound request is authorized through `Scope.guard()` first.
"""
from __future__ import annotations

import httpx
from pydantic import BaseModel, Field

from .config import Scope

# Endpoint path/name hints that suggest an LLM/agent is behind it.
_LLM_HINTS = ("chat", "completion", "ask", "agent", "assistant", "llm", "prompt", "generate", "rag")


class Endpoint(BaseModel):
    method: str
    path: str
    # Parameter names declared in the OpenAPI schema (query/path/body).
    params: list[str] = Field(default_factory=list)
    likely_llm: bool = False


class Recon(BaseModel):
    base_url: str
    reachable: bool = False
    server_header: str | None = None
    endpoints: list[Endpoint] = Field(default_factory=list)
    # Raw response headers + cookies from a baseline GET, for the session module.
    baseline_headers: dict[str, str] = Field(default_factory=dict)
    set_cookie: list[str] = Field(default_factory=list)

    def llm_endpoints(self) -> list[Endpoint]:
        return [e for e in self.endpoints if e.likely_llm]


def _looks_like_llm(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in _LLM_HINTS)


def run_recon(scope: Scope, base_url: str, client: httpx.Client | None = None) -> Recon:
    """Probe a single base URL. Returns a Recon even if the target is unreachable."""
    scope.guard(base_url)
    recon = Recon(base_url=base_url)
    owns_client = client is None
    client = client or httpx.Client(timeout=10.0, follow_redirects=True, verify=False)
    try:
        # Baseline request to capture server headers / cookies.
        try:
            r = client.get(scope.guard(base_url + "/"))
            recon.reachable = True
            recon.server_header = r.headers.get("server")
            recon.baseline_headers = dict(r.headers)
            recon.set_cookie = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else (
                [r.headers["set-cookie"]] if "set-cookie" in r.headers else []
            )
        except httpx.HTTPError:
            recon.reachable = False

        # OpenAPI schema (FastAPI default). Best source of endpoints + params.
        try:
            schema_url = scope.guard(base_url + "/openapi.json")
            sr = client.get(schema_url)
            if sr.status_code == 200 and "application/json" in sr.headers.get("content-type", ""):
                recon.reachable = True
                _parse_openapi(recon, sr.json())
        except (httpx.HTTPError, ValueError):
            pass

        return recon
    finally:
        if owns_client:
            client.close()


def _parse_openapi(recon: Recon, schema: dict) -> None:
    paths = schema.get("paths", {})
    for path, methods in paths.items():
        for method, spec in methods.items():
            if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            params = [p.get("name") for p in spec.get("parameters", []) if p.get("name")]
            # Pull request-body field names when present.
            body = spec.get("requestBody", {})
            for content in body.get("content", {}).values():
                ref = content.get("schema", {})
                params.extend(_schema_field_names(ref, schema))
            recon.endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    params=sorted(set(params)),
                    likely_llm=_looks_like_llm(path),
                )
            )


def _schema_field_names(node: dict, root: dict) -> list[str]:
    """Resolve a (possibly $ref) schema node to its top-level property names."""
    if "$ref" in node:
        ref = node["$ref"].lstrip("#/").split("/")
        target: dict | None = root
        for part in ref:
            target = target.get(part) if isinstance(target, dict) else None
            if target is None:
                return []
        node = target
    return list(node.get("properties", {}).keys())
