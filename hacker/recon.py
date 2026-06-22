"""Recon: map the running target before any module attacks it.

Pulls the OpenAPI/Swagger schema (FastAPI serves it at /openapi.json), enumerates
endpoints, records response headers and Set-Cookie, and guesses which endpoints
talk to an LLM (so the prompt-injection module knows where to aim).

Every outbound request is authorized through `Scope.guard()` first.
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
from pydantic import BaseModel, Field

from .config import Scope

# Endpoint path/name hints that suggest an LLM/agent is behind it.
_LLM_HINTS = ("chat", "completion", "ask", "agent", "assistant", "llm", "prompt", "generate", "rag")


class Endpoint(BaseModel):
    method: str
    path: str
    # Parameter names declared in the OpenAPI schema (query/path/body) or a crawled form.
    params: list[str] = Field(default_factory=list)
    likely_llm: bool = False
    # How we found it ("openapi" or "crawl") — useful for triage and debugging recon.
    source: str = "openapi"
    # Where params live: POST/PUT/PATCH send a JSON body, GET uses the query string.
    @property
    def in_body(self) -> bool:
        return self.method in ("POST", "PUT", "PATCH")


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

        # HTML crawl — essential when OpenAPI is absent (non-FastAPI, or docs disabled
        # in prod). Discovers links and forms so a "clean" scan can't just be silence.
        try:
            _crawl(scope, recon, client)
        except httpx.HTTPError:
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


# --- HTML crawl ----------------------------------------------------------------
class _LinkFormParser(HTMLParser):
    """Extracts anchor hrefs and forms (action/method + field names) from a page."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[tuple[str, str, list[str]]] = []
        self._form: list | None = None

    def handle_starttag(self, tag: str, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "form":
            self._form = [d.get("action", "") or "", (d.get("method") or "GET"), []]
        elif tag in ("input", "textarea", "select") and self._form is not None:
            if d.get("name"):
                self._form[2].append(d["name"])

    def handle_endtag(self, tag: str):
        if tag == "form" and self._form is not None:
            self.forms.append((self._form[0], self._form[1], self._form[2]))
            self._form = None


def _crawl(scope: Scope, recon: Recon, client: httpx.Client, max_pages: int = 8) -> None:
    base = recon.base_url
    seen: set[str] = set()
    queue: list[str] = ["/"]
    while queue and len(seen) < max_pages:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        try:
            r = client.get(scope.guard(base.rstrip("/") + path))
        except httpx.HTTPError:
            continue
        if "text/html" not in r.headers.get("content-type", ""):
            continue
        recon.reachable = True

        parser = _LinkFormParser()
        parser.feed(r.text)
        page_url = base.rstrip("/") + path

        for href in parser.links:
            rel = _same_origin_path(base, page_url, href)
            if rel is None:
                continue
            p, params = _split_path_params(rel)
            _add_endpoint(recon, "GET", p, params, "crawl")
            if p not in seen and p not in queue:
                queue.append(p)

        for action, method, names in parser.forms:
            rel = _same_origin_path(base, page_url, action or path)
            if rel is None:
                continue
            p, qparams = _split_path_params(rel)
            _add_endpoint(recon, method.upper(), p, names + qparams, "crawl")


def _same_origin_path(base: str, current_url: str, href: str) -> str | None:
    """Resolve href against the current page; return its path(+query) only if same-origin."""
    href = href.strip()
    if not href or href.startswith(("#", "mailto:", "javascript:", "tel:", "data:")):
        return None
    absu = urlsplit(urljoin(current_url, href))
    b = urlsplit(base)
    if absu.scheme not in ("http", "https"):
        return None
    if (absu.hostname, absu.port) != (b.hostname, b.port):
        return None
    path = absu.path or "/"
    return path + (f"?{absu.query}" if absu.query else "")


def _split_path_params(rel: str) -> tuple[str, list[str]]:
    s = urlsplit(rel)
    return (s.path or "/"), list(parse_qs(s.query).keys())


def _add_endpoint(recon: Recon, method: str, path: str, params: list[str], source: str) -> None:
    """Add an endpoint, or merge params into an existing (method, path) match."""
    for e in recon.endpoints:
        if e.method == method and e.path == path:
            e.params = sorted(set(e.params) | set(params))
            return
    recon.endpoints.append(Endpoint(
        method=method, path=path, params=sorted(set(params)),
        likely_llm=_looks_like_llm(path), source=source))
