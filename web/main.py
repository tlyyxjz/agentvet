"""AgentVet Web API — FastAPI backend.

Exposes scan, report, and history endpoints.
Runs on Railway/Render in production, localhost in dev.
"""

import json
import logging
import os
import sqlite3
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from scanner import __version__
from scanner.engine import ScanEngine
from scanner.findings import ScanReport

app = FastAPI(
    title="AgentVet API",
    version=__version__,
    description="AI Agent Security Scanner — detect prompt injection, tool auth bypass, data leaks",
)

_default_origins = ["http://localhost:5173", "http://localhost:3000"]
_env_origins = os.environ.get("ALLOWED_ORIGINS", "")
_allow_origins = _env_origins.split(",") if _env_origins else _default_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── database init ──────────────────────────────────────────────

DB_PATH = os.environ.get("AGENTVET_DB", str(Path(__file__).parent.parent / "agentvet.db"))


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            score TEXT,
            total_checks INTEGER DEFAULT 0,
            duration_ms REAL DEFAULT 0,
            findings_json TEXT DEFAULT '[]',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
    """)
    conn.commit()
    conn.close()


init_db()

# ── request/response models ─────────────────────────────────────


class ScanResponse(BaseModel):
    id: str
    target: str
    score: str
    total_checks: int
    duration_ms: float
    summary: dict
    findings: list[dict]
    attack_chain: Optional[dict] = None
    owasp_coverage: Optional[dict] = None
    tiers: dict = {}


class ScanHistoryItem(BaseModel):
    id: str
    target: str
    score: str
    total_checks: int
    duration_ms: float
    finding_count: int
    created_at: str


# ── routes ──────────────────────────────────────────────────────


@app.get("/")
def root():
    return {"service": "AgentVet API", "version": __version__, "docs": "/docs"}


@app.post("/scan", response_model=ScanResponse)
def scan_target(target: str, depth: int = 3):
    """Scan a local directory or file path.

    depth: 1=L1 only, 2=L1+L2, 3=L1+L2+L3 (default)
    """
    if not target or not Path(target).exists():
        raise HTTPException(status_code=400, detail=f"Target not found: {target}")

    engine = ScanEngine(
        use_l2=depth >= 2,
        use_l3=depth >= 3,
        use_l4=depth >= 3,
    )
    report = engine.scan(target)
    return _save_and_respond(report)


@app.post("/api/upload-scan", response_model=ScanResponse)
async def upload_and_scan(file: UploadFile = File(...)):
    """Upload a single agent file and scan it."""
    content = await file.read()
    tmp_path = Path(tempfile.gettempdir()) / f"agentvet_upload_{uuid.uuid4().hex[:8]}.py"
    tmp_path.write_bytes(content)

    engine = ScanEngine(use_l4=False)  # single-file upload; chain analysis needs full project
    report = engine.scan(str(tmp_path))

    # Clean up
    try:
        tmp_path.unlink()
    except Exception:
        logger.warning("Could not remove temp upload file %s", tmp_path, exc_info=True)

    return _save_and_respond(report)


@app.get("/api/history")
def scan_history(limit: int = 20, offset: int = 0):
    """Get scan history."""
    conn = get_db()
    rows = conn.execute(
        "SELECT id, target, score, total_checks, duration_ms, findings_json, created_at "
        "FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()

    return [
        {
            "id": r["id"],
            "target": r["target"],
            "score": r["score"],
            "total_checks": r["total_checks"],
            "duration_ms": r["duration_ms"],
            "finding_count": len(json.loads(r["findings_json"])),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str):
    """Get a full scan report by ID."""
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Report not found")

    findings = json.loads(row["findings_json"])
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    # Compute tiers from finding data (forward-compat with old scan records)
    l3_audited = sum(1 for f in findings if f.get("attack_demo"))
    l3_model = "deepseek-chat" if l3_audited > 0 else ""

    return {
        "id": row["id"],
        "target": row["target"],
        "score": row["score"],
        "total_checks": row["total_checks"],
        "duration_ms": row["duration_ms"],
        "created_at": row["created_at"],
        "summary": severity_counts,
        "findings": findings,
        "tiers": {
            "l1_findings": len(findings),
            "l2_dropped": 0,
            "l2_model": "",
            "l2_duration_ms": 0,
            "l3_audited": l3_audited,
            "l3_model": l3_model,
            "l3_duration_ms": 0,
        },
    }


@app.get("/api/stats")
def stats():
    """Get aggregate statistics."""
    conn = get_db()
    row = conn.execute(
        "SELECT COUNT(*) as total_scans, "
        "COALESCE(AVG(duration_ms),0) as avg_duration, "
        "COALESCE(SUM(CASE WHEN score IN ('A+','A') THEN 1 ELSE 0 END),0) as clean_scans "
        "FROM scans"
    ).fetchone()
    conn.close()

    return {
        "total_scans": row["total_scans"],
        "avg_duration_ms": round(row["avg_duration"], 1),
        "clean_scans": row["clean_scans"],
    }


# ── helpers ─────────────────────────────────────────────────────


def _save_and_respond(report: ScanReport) -> dict:
    scan_id = f"av_{uuid.uuid4().hex[:12]}"
    conn = get_db()
    conn.execute(
        "INSERT INTO scans (id, target, score, total_checks, duration_ms, findings_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            report.target,
            report.score,
            report.total_checks,
            round(report.duration_ms, 1),
            json.dumps([f.to_dict() for f in report.findings], ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()

    return {
        "id": scan_id,
        "target": report.target,
        "score": report.score,
        "total_checks": report.total_checks,
        "duration_ms": round(report.duration_ms, 1),
        "summary": {
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "total": len(report.findings),
        },
        "findings": [f.to_dict() for f in report.findings],
        "attack_chain": report._chain_to_dict() if hasattr(report, '_chain_to_dict') else None,
        "owasp_coverage": report.owasp_coverage,
        "tiers": {
            "l1_findings": len(report.findings) + report.l2_filtered_count,
            "l2_dropped": report.l2_filtered_count,
            "l2_model": report.l2_model,
            "l2_duration_ms": round(report.l2_duration_ms, 0),
            "l3_audited": report.l3_audited_count,
            "l3_model": report.l3_model,
            "l3_duration_ms": round(report.l3_duration_ms, 0),
            "l4_chain": report.chain is not None,
        },
    }
