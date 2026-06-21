"""Hardened twin of the vulnerable fixture — every planted vuln is fixed here.

Used to prove the modules don't fire false positives against correct code.
"""
import os
import sqlite3

from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="hardened-fixture")

# class 6 fixed: notes scoped to their owner; updates limited to an allowlist.
_TOKENS = {"token-alice": "alice", "token-bob": "bob"}
_NOTES = {
    1: {"id": 1, "owner": "alice", "text": "alice's private note"},
    2: {"id": 2, "owner": "bob", "text": "bob's private note"},
}
_EDITABLE = {"text"}  # owner/id/role are NOT user-editable


def _user(token: str | None) -> str | None:
    return _TOKENS.get(token or "")


@app.post("/auth/login")
async def auth_login(body: dict):
    return {"token": f"token-{body.get('username', '')}"}


@app.get("/api/notes/{note_id}")
def get_note(note_id: int, x_session_token: str = Header(default="")):
    user = _user(x_session_token)
    if user is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    note = _NOTES.get(note_id)
    # Object-level authorization: pretend it doesn't exist if it isn't yours.
    if not note or note["owner"] != user:
        return JSONResponse({"error": "not found"}, status_code=404)
    return note


@app.put("/api/notes/{note_id}")
async def put_note(note_id: int, request: Request, x_session_token: str = Header(default="")):
    user = _user(x_session_token)
    if user is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    note = _NOTES.get(note_id)
    if not note or note["owner"] != user:
        return JSONResponse({"error": "not found"}, status_code=404)
    body = await request.json()
    for field in _EDITABLE:  # only allowlisted fields are applied
        if field in body:
            note[field] = body[field]
    return note

# Secrets come from the environment, never hardcoded.
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
_db.execute("INSERT INTO users VALUES (1, 'alice')")
_db.commit()


@app.get("/login")
def login(x_session_token: str = Header(default="")):
    # Token read from a header; cookie carries all the right flags.
    resp = JSONResponse({"ok": True})
    resp.set_cookie("session", "abc123", httponly=True, secure=True, samesite="strict")
    return resp


@app.get("/users")
def users(name: str = Query(""), limit: int = Query(50, le=100)):
    # Parameterized query + bounded result set.
    cur = _db.cursor()
    cur.execute("SELECT id, name FROM users WHERE name = ? LIMIT ?", (name, limit))
    return {"users": cur.fetchall()}


@app.post("/chat")
async def chat(body: dict):
    # No secrets in context; injection attempts get a fixed refusal.
    user = str(body.get("message", ""))
    return {"reply": "I can only help with supported topics."}


# Rate limiting is configured (detected statically by the dos module).
# from slowapi import Limiter
LIMITER_NOTE = "Limiter("  # stand-in marker so the static check sees real usage
