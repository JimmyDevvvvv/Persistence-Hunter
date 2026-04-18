"""api/routes/stats.py — /api/health and /api/stats"""

from datetime import datetime, timezone
from fastapi import APIRouter
from api.dependencies import get_db, DB_PATH

router = APIRouter()


@router.get("/health")
def health():
    """Service and DB health check."""
    try:
        conn = get_db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "status":  "ok" if db_ok else "degraded",
        "db":      "connected" if db_ok else "error",
        "db_path": DB_PATH,
        "version": "1.0.0",
    }


@router.get("/stats")
def get_stats():
    """Aggregated dashboard numbers across all persistence types."""
    conn = get_db()
    try:
        def count(table: str, severity: str = None) -> int:
            if severity:
                return conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE severity=?",
                    (severity,),
                ).fetchone()[0]
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

        def sev_counts(table: str) -> dict:
            return {s: count(table, s) for s in ("critical", "high", "medium", "low")}

        recent_24h = conn.execute("""
            SELECT COUNT(*) FROM registry_entries
            WHERE last_seen >= datetime('now', '-24 hours')
        """).fetchone()[0]

        enriched = conn.execute(
            "SELECT COUNT(*) FROM enrichment_results"
        ).fetchone()[0]

        chains = conn.execute(
            "SELECT COUNT(*) FROM attack_chains"
        ).fetchone()[0]

        reg  = sev_counts("registry_entries")
        tsk  = sev_counts("task_entries")
        svc  = sev_counts("service_entries")

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
            "event_log": {
                "process_events": count("process_events"),
                "sysmon_events":  (count("sysmon_registry_events") +
                                   count("sysmon_process_events")),
            },
            "enrichment": {
                "enriched_entries": enriched,
                "chains_built":     chains,
            },
            "recent_24h":  recent_24h,
            "last_updated": datetime.now(tz=timezone.utc).isoformat(),
        }
    finally:
        conn.close()
