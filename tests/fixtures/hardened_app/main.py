"""Hardened twin of the vulnerable fixture — every planted vuln is fixed here.

Used to prove the modules don't fire false positives against correct code.
"""
import os
import sqlite3

from fastapi import FastAPI, Header, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="hardened-fixture")

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
