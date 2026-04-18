"""api/routes/alerts.py — /api/alerts"""

from fastapi import APIRouter, Query
from api.dependencies import get_db, row_to_dict

router = APIRouter()

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
