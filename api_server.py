"""
api_server.py
FastAPI server — bridges the registry collector and the frontend.
Run: uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload
"""

import json
import os
import sys
from datetime import datetime
from typing import Optional

# Add collector to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "collector"))

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Import our collector (no Windows dependency check here — API layer)
try:
    from registry_collector import RegistryCollector
    COLLECTOR_AVAILABLE = True
except ImportError as e:
    COLLECTOR_AVAILABLE = False
    print(f"[!] Collector import error: {e}")

app = FastAPI(
    title="RegHunt API",
    description="Registry Persistence Hunter — REST API",
    version="1.0.0"
)

# Allow the frontend (served from any origin during dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.environ.get("REGHUNT_DB", "reghunt.db")

def get_collector() -> "RegistryCollector":
    if not COLLECTOR_AVAILABLE:
        raise HTTPException(status_code=503, detail="Collector not available on this platform")
    return RegistryCollector(db_path=DB_PATH)


# ── MODELS ────────────────────────────────────────────────
class ScanRequest(BaseModel):
    extended: bool = False

class EventsRequest(BaseModel):
    hours_back: int = 24


# ── ROUTES ────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "RegHunt API", "version": "1.0.0"}


@app.get("/api/stats")
def get_stats():
    """Summary stats for the dashboard header."""
    col = get_collector()
    try:
        return col.get_stats()
    finally:
        col.close()


@app.get("/api/entries")
def list_entries(
    hive: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100
):
    """
    List all registry persistence entries.
    Filter by hive (e.g. 'HKLM') or severity ('critical','high','medium','low').
    """
    col = get_collector()
    try:
        entries = col.get_all_entries()

        if hive:
            entries = [e for e in entries if hive.upper() in e["hive"].upper()]
        if severity:
            entries = [e for e in entries if e["severity"] == severity.lower()]

        return {"entries": entries[:limit], "total": len(entries)}
    finally:
        col.close()


@app.get("/api/entries/{entry_id}")
def get_entry(entry_id: int):
    """Get a single registry entry by ID."""
    col = get_collector()
    try:
        entry = col.get_entry(entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail=f"Entry {entry_id} not found")
        return entry
    finally:
        col.close()


@app.get("/api/entries/{entry_id}/chain")
def get_attack_chain(entry_id: int):
    """
    Get (or build) the attack chain for a registry entry.
    Returns ordered list of process nodes from root to the writer process.
    """
    col = get_collector()
    try:
        entry = col.get_entry(entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail=f"Entry {entry_id} not found")

        chain = col.get_chain(entry_id)
        return {
            "entry_id":   entry_id,
            "entry_name": entry["name"],
            "hive":       entry["hive"],
            "chain":      chain,
            "depth":      len(chain)
        }
    finally:
        col.close()


@app.post("/api/scan")
def trigger_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Trigger a registry scan in the background.
    Returns immediately; poll /api/stats to see results.
    """
    def run_scan():
        col = RegistryCollector(db_path=DB_PATH)
        try:
            col.collect_registry(extended=req.extended)
        finally:
            col.close()

    background_tasks.add_task(run_scan)
    return {"status": "scan_started", "extended": req.extended}


@app.post("/api/collect-events")
def collect_events(req: EventsRequest, background_tasks: BackgroundTasks):
    """
    Collect Event ID 4688 process creation events.
    Requires admin rights and audit policy enabled.
    """
    def run_collect():
        col = RegistryCollector(db_path=DB_PATH)
        try:
            col.collect_process_events(hours_back=req.hours_back)
        finally:
            col.close()

    background_tasks.add_task(run_collect)
    return {"status": "collection_started", "hours_back": req.hours_back}


@app.post("/api/rebuild-chain/{entry_id}")
def rebuild_chain(entry_id: int):
    """Force-rebuild the attack chain for an entry (re-queries process events)."""
    col = get_collector()
    try:
        entry = col.get_entry(entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail=f"Entry {entry_id} not found")
        chain = col.build_attack_chain(entry_id)
        return {"entry_id": entry_id, "chain": chain, "depth": len(chain)}
    finally:
        col.close()


@app.get("/api/processes")
def list_processes(
    name: Optional[str] = None,
    pid: Optional[int] = None,
    limit: int = 200
):
    """List stored process creation events (from Event ID 4688)."""
    col = get_collector()
    try:
        query = "SELECT * FROM process_events"
        params = []
        filters = []

        if name:
            filters.append("process_name LIKE ?")
            params.append(f"%{name}%")
        if pid:
            filters.append("pid = ?")
            params.append(pid)

        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += f" ORDER BY event_time DESC LIMIT {limit}"

        rows = col.conn.execute(query, params).fetchall()
        return {"processes": [dict(r) for r in rows]}
    finally:
        col.close()


# ── SERVE FRONTEND ─────────────────────────────────────────
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/app", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    @app.get("/ui")
    def serve_ui():
        return FileResponse(os.path.join(frontend_dir, "index.html"))


# ── RUN ───────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
