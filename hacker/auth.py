"""Authentication: log in as each configured identity and produce the headers/
cookies needed to make authenticated requests.

Two identities unlock IDOR testing (act as A, try to reach B's resources).
"""
from __future__ import annotations

import httpx
from pydantic import BaseModel, Field

from .config import AuthConfig, Identity, Scope


class Session(BaseModel):
    """An authenticated session for one identity."""

    name: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    token: str | None = None
    authenticated: bool = False


def _dig(data: object, dotted: str) -> str | None:
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return str(cur) if isinstance(cur, (str, int)) else None


def login(scope: Scope, auth: AuthConfig, identity: Identity, client: httpx.Client) -> Session:
    """Authenticate one identity. Returns a Session (authenticated=False on failure)."""
    session = Session(name=identity.name)
    try:
        r = client.request(auth.method, scope.guard(auth.login_url), json=identity.body)
    except httpx.HTTPError:
        return session
    if r.status_code >= 400:
        return session

    if auth.token_cookie:
        # Reuse the cookie the server set.
        val = r.cookies.get(auth.token_cookie)
        if val:
            session.cookies[auth.token_cookie] = val
            session.token = val
            session.authenticated = True
    if auth.token_json_path:
        try:
            token = _dig(r.json(), auth.token_json_path)
        except ValueError:
            token = None
        if token:
            session.token = token
            if auth.token_header:
                session.headers[auth.token_header] = token
            session.authenticated = True
    return session


def authenticate_all(scope: Scope, client: httpx.Client) -> list[Session]:
    """Log in as every configured identity. Empty list if no auth configured."""
    if scope.auth is None:
        return []
    return [login(scope, scope.auth, ident, client) for ident in scope.auth.identities]
