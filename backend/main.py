"""FastAPI app exposing the scanner over a REST API for the React UI."""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlmodel import Session, select

from .db import get_session, init_db
from .models import Finding, Scan, Suppression, Target
from .services import run_scan_for


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="personal_hacker API", lifespan=lifespan)

# Dev convenience: the Vite dev server runs on a different port.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# --- request/response schemas --------------------------------------------------
class TargetIn(BaseModel):
    name: str
    allowlist: list[str] = []
    target_urls: list[str] = []
    repo_path: str | None = None
    safe_mode: bool = True
    offline: bool = False
    ssrf_canary: bool = False
    i_own_this: bool = False
    llm_provider: str = "claude"
    llm_model: str | None = None
    auth: dict | None = None


class SuppressionIn(BaseModel):
    fingerprint: str
    reason: str = ""


# --- targets -------------------------------------------------------------------
@app.get("/api/targets", response_model=list[Target])
def list_targets(session: Session = Depends(get_session)):
    return session.exec(select(Target).order_by(Target.created_at.desc())).all()


@app.post("/api/targets", response_model=Target, status_code=201)
def create_target(body: TargetIn, session: Session = Depends(get_session)):
    target = Target(**body.model_dump())
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@app.get("/api/targets/{target_id}", response_model=Target)
def get_target(target_id: int, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    return target


@app.delete("/api/targets/{target_id}", status_code=204)
def delete_target(target_id: int, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    session.delete(target)
    session.commit()


# --- scans ---------------------------------------------------------------------
@app.post("/api/targets/{target_id}/scan", response_model=Scan, status_code=202)
def trigger_scan(target_id: int, background: BackgroundTasks,
                 session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    scan = Scan(target_id=target_id, status="pending")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    background.add_task(run_scan_for, scan.id)
    return scan


@app.get("/api/scans", response_model=list[Scan])
def list_scans(target_id: int | None = None, limit: int = 50,
               session: Session = Depends(get_session)):
    q = select(Scan).order_by(Scan.started_at.desc()).limit(limit)
    if target_id is not None:
        q = q.where(Scan.target_id == target_id)
    return session.exec(q).all()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    findings = session.exec(
        select(Finding).where(Finding.scan_id == scan_id)).all()
    # Rank worst-first; suppressed sink to the bottom.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (f.suppressed, order.get(f.severity, 9), f.threat_class))
    return {"scan": scan, "findings": findings}


# --- suppressions --------------------------------------------------------------
@app.get("/api/suppressions", response_model=list[Suppression])
def list_suppressions(session: Session = Depends(get_session)):
    return session.exec(select(Suppression).order_by(Suppression.created_at.desc())).all()


@app.post("/api/suppressions", response_model=Suppression, status_code=201)
def add_suppression(body: SuppressionIn, session: Session = Depends(get_session)):
    existing = session.exec(
        select(Suppression).where(Suppression.fingerprint == body.fingerprint)).first()
    if existing:
        existing.reason = body.reason
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing
    sup = Suppression(fingerprint=body.fingerprint, reason=body.reason)
    session.add(sup)
    session.commit()
    session.refresh(sup)
    # Reflect immediately on already-stored findings of that fingerprint.
    for f in session.exec(select(Finding).where(Finding.fingerprint == body.fingerprint)).all():
        f.suppressed = True
        session.add(f)
    session.commit()
    return sup


@app.delete("/api/suppressions/{fingerprint}", status_code=204)
def delete_suppression(fingerprint: str, session: Session = Depends(get_session)):
    sup = session.exec(
        select(Suppression).where(Suppression.fingerprint == fingerprint)).first()
    if not sup:
        raise HTTPException(404, "suppression not found")
    session.delete(sup)
    for f in session.exec(select(Finding).where(Finding.fingerprint == fingerprint)).all():
        f.suppressed = False
        session.add(f)
    session.commit()


# --- dashboard -----------------------------------------------------------------
@app.get("/api/stats")
def stats(session: Session = Depends(get_session)):
    targets = session.exec(select(Target)).all()
    scans = session.exec(select(Scan).where(Scan.status == "done")).all()
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    # Latest scan per target drives the "current posture" numbers.
    latest: dict[int, Scan] = {}
    for s in sorted(scans, key=lambda x: x.started_at):
        latest[s.target_id] = s
    for s in latest.values():
        for k in totals:
            totals[k] += getattr(s, k)
    return {
        "targets": len(targets),
        "scans": len(scans),
        "open_by_severity": totals,
        "open_total": sum(totals.values()),
    }


@app.get("/api/targets/{target_id}/trend")
def trend(target_id: int, limit: int = 20, session: Session = Depends(get_session)):
    scans = session.exec(
        select(Scan).where(Scan.target_id == target_id, Scan.status == "done")
        .order_by(Scan.started_at.desc()).limit(limit)).all()
    return [
        {"scan_id": s.id, "started_at": s.started_at,
         "critical": s.critical, "high": s.high, "medium": s.medium,
         "low": s.low, "info": s.info, "total": s.total}
        for s in reversed(scans)
    ]


@app.get("/api/health")
def health():
    return {"ok": True, "time": datetime.now(timezone.utc)}
