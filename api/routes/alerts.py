"""api/routes/alerts.py — /api/alerts"""

import sys
import os
import json

from fastapi import APIRouter, Query
from api.dependencies import get_db, DB_PATH, row_to_dict

# Ensure repo root is on path so core.alert_translator is importable
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

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

_ENTRY_TABLES = [
    ("registry", "registry_entries", "name",         "value_data"),
    ("task",     "task_entries",     "task_name",    "command"),
    ("service",  "service_entries",  "service_name", "binary_path"),
]


@router.get("")
def get_alerts(limit: int = Query(default=100, le=500)):
    """
    Return translated (plain-English) alerts for the consumer dashboard.

    Flow:
      1. Join each entry table with threat_scores.
      2. Skip entries with score=0 or an 'excluded' factor in their breakdown.
      3. Translate each entry+score through alert_translator.translate_alert().
      4. Sort critical first, return as a plain array.
    """
    from core.alert_translator import translate_alert

    conn = get_db()
    try:
        alerts = []

        for etype, table, name_col, val_col in _ENTRY_TABLES:
            try:
                rows = conn.execute(f"""
                    SELECT e.*, ts.score, ts.breakdown_json, ts.apt_json, ts.risk_json
                    FROM   {table} e
                    JOIN   threat_scores ts
                           ON ts.entry_type = ? AND ts.entry_id = e.id
                    WHERE  ts.score > 0
                    ORDER  BY ts.score DESC
                """, (etype,)).fetchall()
            except Exception:
                continue

            for row in rows:
                d         = dict(row)
                breakdown = json.loads(d.get("breakdown_json") or "[]")

                # Drop entries silenced by the exclusion engine
                if any(b.get("factor") == "excluded" for b in breakdown):
                    continue

                entry = {k: v for k, v in d.items()
                         if k not in ("score", "breakdown_json", "apt_json", "risk_json")}
                entry["entry_type"] = etype

                score_result = {
                    "score":           d["score"],
                    "breakdown":       breakdown,
                    "apt_matches":     json.loads(d.get("apt_json")  or "[]"),
                    "risk_indicators": json.loads(d.get("risk_json") or "[]"),
                }

                alerts.append(translate_alert(entry, score_result, etype))

        _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts.sort(key=lambda a: _sev.get(a.get("severity"), 4))

        return alerts[:limit]

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
