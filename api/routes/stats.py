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

@router.get("/status")
def get_status():
    conn = _conn()
    try:
        # Check if threat_scores table exists yet
        has_scores = conn.execute("""
            SELECT COUNT(*) FROM sqlite_master 
            WHERE type='table' AND name='threat_scores'
        """).fetchone()[0] > 0

        if has_scores:
            def score_count(min_s, max_s):
                return conn.execute(
                    "SELECT COUNT(*) FROM threat_scores WHERE score >= ? AND score < ?",
                    (min_s, max_s)
                ).fetchone()[0]
            counts = {
                "critical": score_count(80, 101),
                "high":     score_count(60, 80),
                "medium":   score_count(35, 60),
                "low":      score_count(0,  35),
            }
            last_scan = conn.execute(
                "SELECT MAX(scored_at) FROM threat_scores"
            ).fetchone()[0]
        else:
            # No scan run yet — fall back to static severity from entry tables
            def sev(s):
                total = 0
                for t in ("registry_entries", "task_entries", "service_entries"):
                    try:
                        total += conn.execute(
                            f"SELECT COUNT(*) FROM {t} WHERE severity=?", (s,)
                        ).fetchone()[0]
                    except Exception:
                        pass
                return total
            counts   = {s: sev(s) for s in ("critical", "high", "medium", "low")}
            last_scan = None

    finally:
        conn.close()

    if counts["critical"] > 0:
        n = counts["critical"]
        status, msg = "danger", f"{n} critical threat{'s' if n > 1 else ''} detected."
    elif counts["high"] > 0:
        n = counts["high"]
        status, msg = "warning", f"{n} suspicious item{'s' if n > 1 else ''} found."
    elif counts["medium"] > 0:
        n = counts["medium"]
        status, msg = "notice", f"{n} unusual item{'s' if n > 1 else ''} worth reviewing."
    else:
        status, msg = "clean", "No threats detected. Your system looks clean."

    return {
        "status":         status,
        "status_message": msg,
        "scanning":       False,
        "counts":         counts,
        "last_scan":      last_scan,
        "rules_version":  "v1.0",
    }        