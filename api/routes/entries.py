"""api/routes/entries.py — /api/entries"""

import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import json
from typing import Optional, Literal
from fastapi import APIRouter, HTTPException, Query
from api.dependencies import get_db, DB_PATH, row_to_dict

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


# ---------------------------------------------------------------------------
# Trust endpoint — "Trust this" consumer UI button
# ---------------------------------------------------------------------------

_TABLE_MAP_TRUST = {
    "registry": ("registry_entries", "name",         "value_data"),
    "task":     ("task_entries",     "task_name",    "command"),
    "service":  ("service_entries",  "service_name", "binary_path"),
}


@router.post("/{entry_type}/{entry_name}/trust")
def trust_entry(entry_type: str, entry_name: str):
    """
    Mark an entry as trusted by adding a hash exclusion for its binary.
    If the binary cannot be resolved or hashed, falls back to a process-name
    exclusion so the entry is still suppressed on the next scoring run.
    """
    spec = _TABLE_MAP_TRUST.get(entry_type)
    if not spec:
        raise HTTPException(status_code=400,
                            detail=f"Unknown entry type: {entry_type}")
    table, name_col, value_col = spec

    conn = get_db()
    try:
        row = conn.execute(
            f"SELECT * FROM {table} WHERE {name_col}=? LIMIT 1",
            (entry_name,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404,
                            detail=f"Entry '{entry_name}' not found")

    value     = row[value_col] or ""
    excl_type = "process"
    excl_value = entry_name
    method     = "process-name"

    # Try to resolve a binary hash — gives a stronger, rename-proof exclusion
    try:
        from enrichment.local import _extract_exe_path, _file_sha256
        exe_path = _extract_exe_path(value)
        if exe_path:
            fhash = _file_sha256(exe_path)
            if fhash:
                excl_type  = "hash"
                excl_value = fhash
                method     = f"hash:{exe_path}"
    except Exception:
        pass

    from core.exclusion_engine import add_exclusion
    new_id = add_exclusion(
        excl_type=excl_type,
        value=excl_value,
        label=entry_name,
        expires_minutes=None,   # permanent
        db_path=DB_PATH,
    )
    return {
        "id":     new_id,
        "label":  entry_name,
        "method": method,
        "status": "trusted",
    }
