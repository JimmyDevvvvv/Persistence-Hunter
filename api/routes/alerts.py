"""api/routes/alerts.py — /api/alerts"""

import json

from fastapi import APIRouter, Query
from api.dependencies import get_db, row_to_dict

router = APIRouter()

_CREATE_REALTIME = """
CREATE TABLE IF NOT EXISTS realtime_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT,
    rule_name    TEXT,
    severity     TEXT,
    threat_score INTEGER DEFAULT 0,
    triggered_at TEXT    DEFAULT (datetime('now')),
    events_json  TEXT    DEFAULT '[]',
    mitre_json   TEXT    DEFAULT '[]',
    detail       TEXT    DEFAULT ''
)
"""

_SEV_CASE = "CASE {t}.severity WHEN 'critical' THEN 0 ELSE 1 END"


@router.get("")
def get_alerts(limit: int = Query(default=100, le=500)):
    """
    Return all high/critical persistence entries across all types,
    joined with any available enrichment data.
    Sorted: critical first, then by last_seen descending.
    """
    conn = get_db()
    try:
        alerts = []

        queries = [
            ("registry_entries", "r", "registry",
             "r.name, r.value_data, r.hive, r.reg_path"),
            ("task_entries",     "t", "task",
             "t.task_name as name, t.command as value_data, NULL as hive, t.task_path as reg_path"),
            ("service_entries",  "s", "service",
             "s.service_name as name, s.binary_path as value_data, NULL as hive, NULL as reg_path"),
        ]

        for table, alias, etype, cols in queries:
            rows = conn.execute(f"""
                SELECT {alias}.id,
                       {alias}.severity,
                       {alias}.ioc_notes,
                       {alias}.techniques,
                       {alias}.first_seen,
                       {alias}.last_seen,
                       {cols},
                       '{etype}' as entry_type,
                       e.vt_malicious,
                       e.vt_total,
                       e.pe_signed,
                       e.pe_compile_suspicious,
                       e.overall_verdict,
                       e.risk_indicators as enrich_indicators
                FROM {table} {alias}
                LEFT JOIN enrichment_results e
                       ON e.entry_type = '{etype}' AND e.entry_id = {alias}.id
                WHERE {alias}.severity IN ('critical', 'high')
                ORDER BY {_SEV_CASE.format(t=alias)}, {alias}.last_seen DESC
                LIMIT ?
            """, (limit,)).fetchall()
            alerts += [row_to_dict(r) for r in rows]

        # Re-sort combined results
        sev_key = {"critical": 0, "high": 1}
        alerts.sort(key=lambda x: sev_key.get(x.get("severity"), 2))

        return {"alerts": alerts, "count": len(alerts)}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Real-time correlated alerts from the ETW monitor
# ---------------------------------------------------------------------------

@router.post("/realtime")
def post_realtime_alert(payload: dict):
    """
    Receive a correlated behavioral alert from the ETW monitor and persist it.
    Called by monitors/etw_monitor.py whenever a behavior rule fires.
    """
    conn = get_db()
    try:
        conn.execute(_CREATE_REALTIME)
        conn.execute(
            """
            INSERT INTO realtime_alerts
                (rule_id, rule_name, severity, threat_score,
                 events_json, mitre_json, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("id", ""),
                payload.get("name", ""),
                payload.get("severity", "critical"),
                int(payload.get("threat_score", 0)),
                json.dumps(payload.get("matched_events", [])),
                json.dumps(payload.get("mitre", [])),
                payload.get("description", ""),
            ),
        )
        conn.commit()
        row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {"status": "stored", "id": row_id}
    finally:
        conn.close()


@router.get("/realtime")
def get_realtime_alerts(limit: int = Query(default=50, le=200)):
    """Return correlated real-time alerts from the ETW monitor, newest first."""
    conn = get_db()
    try:
        conn.execute(_CREATE_REALTIME)
        rows = conn.execute(
            "SELECT * FROM realtime_alerts ORDER BY triggered_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        alerts = []
        for row in rows:
            d = row_to_dict(row)
            for field in ("events_json", "mitre_json"):
                try:
                    d[field.replace("_json", "")] = json.loads(d.pop(field) or "[]")
                except Exception:
                    d[field.replace("_json", "")] = []
            alerts.append(d)
        return {"alerts": alerts, "count": len(alerts)}
    except Exception:
        return {"alerts": [], "count": 0}
    finally:
        conn.close()
