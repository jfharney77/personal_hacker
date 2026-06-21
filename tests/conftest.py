"""Shared test fixtures: an in-process httpx client wired to the vulnerable app."""
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "vulnerable_app"))


@pytest.fixture
def vuln_app():
    from tests.fixtures.vulnerable_app.main import app
    return app


@pytest.fixture
def vuln_client(vuln_app):
    """httpx client that drives the vulnerable app in-process (no network).

    Starlette's TestClient is itself an httpx.Client subclass, so the recon /
    module code can treat it exactly like a real network client.
    """
    from starlette.testclient import TestClient

    with TestClient(vuln_app, base_url="http://localhost") as c:
        yield c


@pytest.fixture
def local_scope():
    from hacker.config import Scope
    return Scope(allowlist=["localhost"], target_urls=["http://localhost"])


@pytest.fixture
def hardened_client():
    from starlette.testclient import TestClient
    from tests.fixtures.hardened_app.main import app
    with TestClient(app, base_url="http://localhost") as c:
        yield c
