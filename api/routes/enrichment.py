"""api/routes/enrichment.py — /api/enrich"""

import json
import os
from typing import Optional
from fastapi import APIRouter, HTTPException
from api.dependencies import get_db, row_to_dict, DB_PATH

router = APIRouter()


def _get_entry(conn, entry_type: str, entry_id: int) -> dict:
    table_map = {
        "registry": "registry_entries",
        "task":     "task_entries",
        "service":  "service_entries",
    }
    table = table_map.get(entry_type)
    if not table:
        raise HTTPException(status_code=400,
                            detail=f"Unknown entry type: {entry_type}")
    row = conn.execute(
        f"SELECT * FROM {table} WHERE id=?", (entry_id,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Entry not found")
    entry      = row_to_dict(row)
    entry["id"] = entry_id
    return entry


@router.get("/{entry_type}/{entry_id}")
def get_enrichment(entry_type: str, entry_id: int):
    """Retrieve stored enrichment results for a single entry."""
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT * FROM enrichment_results
            WHERE entry_type=? AND entry_id=?
        """, (entry_type, entry_id)).fetchone()
        if not row:
            raise HTTPException(
                status_code=404,
                detail="No enrichment data — POST to /api/enrich/{type}/{id} first",
            )
        result = row_to_dict(row)
        result["risk_indicators"] = json.loads(
            row["risk_indicators"] or "[]"
        )
        return result
    finally:
        conn.close()


@router.post("/{entry_type}/{entry_id}")
def enrich_entry(
    entry_type: str,
    entry_id:   int,
    vt_api_key: Optional[str] = None,
    mb_api_key: Optional[str] = None,
):
    """
    Trigger on-demand enrichment for a single persistence entry.
    Returns full enrichment result including file hashes, PE metadata,
    signature status, and threat intel.
    """
    conn = get_db()
    try:
        entry = _get_entry(conn, entry_type, entry_id)
    finally:
        conn.close()

    from enrichment.enrichment_manager import EnrichmentManager
    mgr    = EnrichmentManager(
        db_path=DB_PATH,
        vt_api_key=vt_api_key or os.environ.get("VT_API_KEY"),
        mb_api_key=mb_api_key or os.environ.get("MB_API_KEY"),
    )
    return mgr.enrich_entry(entry, entry_type, run_intel=True)
