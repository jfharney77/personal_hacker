"""Scope loading + the safety guardrails that gate every dynamic action.

The single most important rule in this tool: *no network request leaves this
process unless its host is on the allowlist*. `Scope.guard()` enforces that and
is called by every dynamic module before it touches a target.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, field_validator


class ScopeError(Exception):
    """Raised when a target is out of scope or the scope file is invalid."""


class Identity(BaseModel):
    """One login the tool can authenticate as. Two are needed to test IDOR."""

    name: str
    # Request body sent to the login endpoint (e.g. {"username": "...", "password": "..."}).
    body: dict = Field(default_factory=dict)


class AuthConfig(BaseModel):
    """How to authenticate against the target so scans run as a logged-in user."""

    login_url: str
    method: str = "POST"
    identities: list[Identity] = Field(default_factory=list)
    # Dotted path into the JSON login response holding the token, e.g. "token" or "data.token".
    token_json_path: str | None = None
    # Header to send the token in (header-based auth).
    token_header: str | None = "X-Session-Token"
    # Cookie name to reuse from the login response (cookie-based auth). Either this or token_*.
    token_cookie: str | None = None


# Hosts that look like production. Touching these requires explicit opt-in,
# because "friendly" hacking still sends real attack traffic.
_PROD_LIKE_SUFFIXES = (".com", ".net", ".org", ".io", ".app", ".dev", ".ai", ".co")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _host_of(url: str) -> str:
    host = urlsplit(url).hostname
    if not host:
        raise ScopeError(f"Could not parse a host from URL: {url!r}")
    return host.lower()


def _is_local(host: str) -> bool:
    if host in _LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return host.endswith(".local") or host.endswith(".localhost")


class Scope(BaseModel):
    """Validated description of *what* we are allowed to test and *how hard*."""

    # Explicit allowlist of hostnames the tool may send traffic to.
    allowlist: list[str] = Field(default_factory=list)
    # Target URLs (their hosts must all be on the allowlist).
    target_urls: list[str] = Field(default_factory=list)
    # Local path to the project source for static analysis (optional).
    repo_path: str | None = None
    # Optional authentication so dynamic scans run as a logged-in user (unlocks IDOR).
    auth: AuthConfig | None = None
    # Enable the local SSRF canary listener to actively confirm SSRF (localhost only).
    ssrf_canary: bool = False
    # Skip network calls in the supply-chain module (no OSV.dev lookups).
    offline: bool = False
    # Safe mode: no destructive writes, no sustained load. Default ON.
    safe_mode: bool = True
    # Required to test a production-looking (public) host. A deliberate speed bump.
    i_own_this: bool = False
    # LLM provider for the agent brain: ollama | cerebras | openai | claude.
    llm_provider: str = "claude"
    llm_model: str | None = None

    @field_validator("allowlist", "target_urls", mode="before")
    @classmethod
    def _ensure_list(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return v

    @property
    def allowed_hosts(self) -> set[str]:
        return {h.lower() for h in self.allowlist}

    def guard(self, url: str) -> str:
        """Authorize a single URL. Returns it unchanged, or raises ScopeError.

        Every dynamic probe MUST route through here before sending traffic.
        """
        host = _host_of(url)
        if host not in self.allowed_hosts:
            raise ScopeError(
                f"Refusing to touch {host!r}: not in scope allowlist "
                f"{sorted(self.allowed_hosts)}. Add it to scope.yaml to authorize."
            )
        if not _is_local(host) and not self.i_own_this:
            raise ScopeError(
                f"{host!r} looks like a public/production host. Set "
                f"`i_own_this: true` in scope.yaml to confirm you own it."
            )
        return url

    def validate_self(self) -> None:
        """Fail fast on an internally inconsistent scope before any work starts."""
        for url in self.target_urls:
            host = _host_of(url)
            if host not in self.allowed_hosts:
                raise ScopeError(
                    f"Target {url!r} (host {host!r}) is not on the allowlist."
                )
        if self.auth is not None:
            host = _host_of(self.auth.login_url)
            if host not in self.allowed_hosts:
                raise ScopeError(
                    f"auth.login_url host {host!r} is not on the allowlist."
                )
        if self.repo_path is not None and not Path(self.repo_path).exists():
            raise ScopeError(f"repo_path does not exist: {self.repo_path}")
        if not self.target_urls and not self.repo_path:
            raise ScopeError("Scope has neither target_urls nor repo_path — nothing to do.")


def load_scope(path: str | Path) -> Scope:
    """Load and validate a scope YAML file."""
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"Scope file not found: {p}")
    data = yaml.safe_load(p.read_text()) or {}
    scope = Scope(**data)
    scope.validate_self()
    return scope
