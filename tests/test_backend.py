"""Backend API: target CRUD, scan persistence, suppression, stats."""
from pathlib import Path

import pytest
from sqlmodel import create_engine

VULN_REPO = str(Path(__file__).parent / "fixtures" / "vulnerable_app")


@pytest.fixture
def client(tmp_path, monkeypatch):
    from backend import db

    eng = create_engine(f"sqlite:///{tmp_path / 'test.db'}",
                        connect_args={"check_same_thread": False})
    monkeypatch.setattr(db, "_engine", eng)

    from starlette.testclient import TestClient

    from backend.main import app
    with TestClient(app) as c:  # startup event creates tables on the patched engine
        yield c


def _make_target(client):
    # SAST-only target (repo_path, no target_urls) → deterministic, no live server needed.
    r = client.post("/api/targets", json={
        "name": "fixture", "repo_path": VULN_REPO, "offline": True})
    assert r.status_code == 201
    return r.json()["id"]


def test_target_crud(client):
    tid = _make_target(client)
    assert client.get(f"/api/targets/{tid}").json()["name"] == "fixture"
    assert any(t["id"] == tid for t in client.get("/api/targets").json())
    assert client.delete(f"/api/targets/{tid}").status_code == 204
    assert client.get(f"/api/targets/{tid}").status_code == 404


def test_scan_persists_findings(client):
    tid = _make_target(client)
    r = client.post(f"/api/targets/{tid}/scan")
    assert r.status_code == 202
    scan_id = r.json()["id"]

    # TestClient runs the background task before returning, so the scan is done.
    data = client.get(f"/api/scans/{scan_id}").json()
    assert data["scan"]["status"] == "done"
    assert data["scan"]["total"] > 0
    assert len(data["findings"]) > 0
    assert any(f["severity"] in ("critical", "high") for f in data["findings"])


def test_suppression_round_trip(client):
    tid = _make_target(client)
    scan_id = client.post(f"/api/targets/{tid}/scan").json()["id"]
    findings = client.get(f"/api/scans/{scan_id}").json()["findings"]
    fp = findings[0]["fingerprint"]

    assert client.post("/api/suppressions", json={"fingerprint": fp, "reason": "accepted"}).status_code == 201
    after = client.get(f"/api/scans/{scan_id}").json()["findings"]
    assert any(f["fingerprint"] == fp and f["suppressed"] for f in after)

    assert client.delete(f"/api/suppressions/{fp}").status_code == 204
    after2 = client.get(f"/api/scans/{scan_id}").json()["findings"]
    assert all(not f["suppressed"] for f in after2 if f["fingerprint"] == fp)


def test_stats_and_trend(client):
    tid = _make_target(client)
    client.post(f"/api/targets/{tid}/scan")
    stats = client.get("/api/stats").json()
    assert stats["targets"] == 1
    assert stats["open_total"] >= 1

    trend = client.get(f"/api/targets/{tid}/trend").json()
    assert len(trend) == 1
    assert trend[0]["total"] >= 1
