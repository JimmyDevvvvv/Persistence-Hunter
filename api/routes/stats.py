"""api/routes/stats.py — /api/health and /api/stats"""

import sqlite3
from datetime import datetime, timezone
from fastapi import APIRouter
from api.dependencies import DB_PATH

router = APIRouter()


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@router.get("/health")
def health():
    try:
        conn = _conn()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status":  "ok" if db_ok else "degraded",
        "db":      "connected" if db_ok else "error",
        "db_path": DB_PATH,
        "version": "2.0.0",
    }


@router.get("/stats")
def get_stats():
    conn = _conn()
    try:
        def count(table, where=None, params=()):
            q = f"SELECT COUNT(*) FROM {table}"
            if where:
                q += f" WHERE {where}"
            try:
                return conn.execute(q, params).fetchone()[0]
            except Exception:
                return 0

        def sev_counts(table):
            return {s: count(table, "severity=?", (s,))
                    for s in ("critical", "high", "medium", "low")}

        reg = sev_counts("registry_entries")
        tsk = sev_counts("task_entries")
        svc = sev_counts("service_entries")

        chains   = count("attack_chains")
        sysmon   = count("sysmon_process_events") + count("sysmon_registry_events")
        proc4688 = count("process_events")

        bl_row = conn.execute(
            "SELECT id FROM baselines ORDER BY id DESC LIMIT 1"
        ).fetchone()
        bl_id = bl_row[0] if bl_row else None

        def new_count(table, et):
            if bl_id is None:
                return 0
            try:
                return conn.execute(f"""
                    SELECT COUNT(*) FROM {table} t
                    WHERE t.severity IN ('critical','high')
                    AND NOT EXISTS (
                        SELECT 1 FROM baseline_entries be
                        WHERE be.baseline_id=? AND be.entry_type=? AND be.hash_id=t.hash_id
                    )
                """, (bl_id, et)).fetchone()[0]
            except Exception:
                return 0

        new_reg = new_count("registry_entries", "registry")
        new_tsk = new_count("task_entries", "task")
        new_svc = new_count("service_entries", "service")

        try:
            top_score    = conn.execute("SELECT MAX(score) FROM threat_scores").fetchone()[0] or 0
            scored_count = count("threat_scores")
        except Exception:
            top_score = 0
            scored_count = 0

        return {
            "registry": reg,
            "tasks":    tsk,
            "services": svc,
            "totals": {
                "registry": count("registry_entries"),
                "tasks":    count("task_entries"),
                "services": count("service_entries"),
                "critical": reg["critical"] + tsk["critical"] + svc["critical"],
                "high":     reg["high"]     + tsk["high"]     + svc["high"],
            },
            "new_since_baseline": {
                "registry": new_reg,
                "tasks":    new_tsk,
                "services": new_svc,
                "total":    new_reg + new_tsk + new_svc,
            },
            "event_log": {
                "process_events": proc4688,
                "sysmon_events":  sysmon,
            },
            "enrichment": {
                "chains_built":     chains,
                "enriched_entries": scored_count,
                "top_score":        round(top_score, 1) if top_score else 0,
            },
            "recent_24h":  count("registry_entries", "last_seen >= datetime('now','-24 hours')"),
            "last_updated": datetime.now(tz=timezone.utc).isoformat(),
        }
    finally:
        conn.close()