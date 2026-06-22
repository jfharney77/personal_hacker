"""SQLite engine + session helpers."""
from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

# DB lives next to the repo root by default; override with PERSONAL_HACKER_DB.
_DEFAULT_DB = Path(__file__).resolve().parent.parent / "personal_hacker.db"
DB_PATH = os.environ.get("PERSONAL_HACKER_DB", str(_DEFAULT_DB))

_engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},  # FastAPI uses threads
)


def get_engine():
    return _engine


def init_db() -> None:
    """Create tables if they don't exist. Import models first so they're registered."""
    from . import models  # noqa: F401  (registers tables on SQLModel.metadata)

    SQLModel.metadata.create_all(_engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a session."""
    with Session(_engine) as session:
        yield session
