"""api/routes/entries.py — /api/entries"""

import json
from typing import Optional, Literal
from fastapi import APIRouter, HTTPException, Query
from api.dependencies import get_db, row_to_dict

router = APIRouter()

_SEV_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"


def _query_table(conn, table: str, name_col: str, value_col: str,
                 etype: str, severity: str, search: str,
                 limit: int, offset: int) -> list[dict]:
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if search:
        s = f"%{search.lower()}%"
        clauses.append(f"(LOWER({name_col}) LIKE ? OR LOWER({value_col}) LIKE ?)")
        params += [s, s]

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]

    rows = conn.execute(f"""
        SELECT *, '{etype}' as entry_type FROM {table}
        {where}
        ORDER BY {_SEV_ORDER}, last_seen DESC
        LIMIT ? OFFSET ?
    """, params).fetchall()
    return [row_to_dict(r) for r in rows]


@router.get("")
def get_entries(
    entry_type: Literal["all", "registry", "task", "service"] = "all",
    severity:   Optional[str]  = None,
    search:     Optional[str]  = None,
    limit:      int = Query(default=500, le=2000),
    offset:     int = 0,
):
    """List persistence entries with optional filtering and search."""
    conn = get_db()
    try:
        results = []
        types   = (["registry", "task", "service"]
                   if entry_type == "all" else [entry_type])

        table_map = {
            "registry": ("registry_entries", "name",         "value_data"),
            "task":     ("task_entries",     "task_name",    "command"),
            "service":  ("service_entries",  "service_name", "binary_path"),
        }

        for etype in types:
            table, name_col, val_col = table_map[etype]
            results += _query_table(
                conn, table, name_col, val_col,
                etype, severity, search, limit, offset,
            )

        # Re-sort combined result set by severity
        sev_key = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: sev_key.get(x.get("severity", "low"), 4))

        return {"entries": results, "count": len(results)}
    finally:
        conn.close()


@router.get("/{entry_type}/{entry_id}")
def get_entry(entry_type: str, entry_id: int):
    """Get a single persistence entry, including any stored enrichment."""
    table_map = {
        "registry": "registry_entries",
        "task":     "task_entries",
        "service":  "service_entries",
    }
    table = table_map.get(entry_type)
    if not table:
        raise HTTPException(status_code=400,
                            detail=f"Unknown entry type: {entry_type}")

    conn = get_db()
    try:
        row = conn.execute(
            f"SELECT * FROM {table} WHERE id=?", (entry_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Entry not found")

        entry             = row_to_dict(row)
        entry["entry_type"] = entry_type

        # Attach enrichment if available
        enrich_row = conn.execute("""
            SELECT * FROM enrichment_results
            WHERE entry_type=? AND entry_id=?
        """, (entry_type, entry_id)).fetchone()

        if enrich_row:
            e = row_to_dict(enrich_row)
            e["risk_indicators"] = json.loads(
                enrich_row["risk_indicators"] or "[]"
            )
            entry["enrichment"] = e
        else:
            entry["enrichment"] = None

        return entry
    finally:
        conn.close()
