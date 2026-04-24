"""api/routes/baseline.py — /api/baseline"""

import sqlite3
import json
from datetime import datetime
from typing import Optional, Literal
from fastapi import APIRouter, HTTPException
from api.dependencies import DB_PATH

router = APIRouter()


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── helpers ────────────────────────────────────────────────────────────────

def _list_baselines(conn) -> list:
    rows = conn.execute(
        "SELECT * FROM baselines ORDER BY id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def _get_new_entries(conn, entry_type: str, baseline_id: int) -> list:
    """Entries not present in the given baseline."""
    table_map = {
        "registry": ("registry_entries", "name",         "value_data"),
        "task":     ("task_entries",     "task_name",     "command"),
        "service":  ("service_entries",  "service_name",  "binary_path"),
    }
    if entry_type not in table_map:
        return []
    table, name_col, val_col = table_map[entry_type]
    rows = conn.execute(f"""
        SELECT t.* FROM {table} t
        WHERE t.severity IN ('critical','high')
        AND NOT EXISTS (
            SELECT 1 FROM baseline_entries be
            WHERE be.baseline_id = ?
            AND be.entry_type = ?
            AND be.hash_id = t.hash_id
        )
        ORDER BY t.severity DESC
    """, (baseline_id, entry_type)).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["entry_type"] = entry_type
        d["display_name"] = d.get(name_col, "?")
        d["display_value"] = d.get(val_col, "")
        # decode techniques
        techs = d.get("techniques") or "[]"
        if isinstance(techs, str):
            try:
                techs = json.loads(techs)
            except Exception:
                techs = []
        d["techniques"] = [
            t.get("id") if isinstance(t, dict) else str(t)
            for t in techs
        ]
        results.append(d)
    return results


# ── routes ─────────────────────────────────────────────────────────────────

@router.get("")
def list_baselines():
    """List all stored baselines, most recent first."""
    conn = _conn()
    try:
        baselines = _list_baselines(conn)
        return {
            "baselines": baselines,
            "latest":    baselines[0] if baselines else None,
            "count":     len(baselines),
        }
    finally:
        conn.close()


@router.post("")
def create_baseline(
    name:       str = "default",
    entry_type: Literal["all", "registry", "task", "service"] = "all",
):
    """Snapshot all current High/Critical entries as a new baseline."""
    conn = _conn()
    try:
        now = datetime.now().isoformat()
        cur = conn.execute(
            "INSERT INTO baselines (name, created_at) VALUES (?, ?)",
            (name, now)
        )
        bid = cur.lastrowid

        type_map = {
            "registry": ("registry_entries", "registry"),
            "task":     ("task_entries",     "task"),
            "service":  ("service_entries",  "service"),
        }
        types = (
            list(type_map.items())
            if entry_type == "all"
            else [(entry_type, type_map[entry_type][1])]
            if entry_type in type_map
            else []
        )

        count = 0
        for et, (table, etype) in [
            (k, (type_map[k][0], type_map[k][1]))
            for k in (type_map if entry_type == "all" else [entry_type])
            if k in type_map
        ]:
            rows = conn.execute(
                f"SELECT hash_id FROM {table} WHERE hash_id IS NOT NULL"
            ).fetchall()
            for row in rows:
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO baseline_entries "
                        "(baseline_id, entry_type, hash_id) VALUES (?,?,?)",
                        (bid, etype, row["hash_id"])
                    )
                    count += 1
                except Exception:
                    pass

        conn.commit()
        baselines = _list_baselines(conn)
        created = next((b for b in baselines if b["id"] == bid), None)
        return {
            "message":     "Baseline created",
            "baseline_id": bid,
            "entries":     count,
            "baseline":    created,
        }
    finally:
        conn.close()


@router.delete("/{baseline_id}")
def delete_baseline(baseline_id: int):
    """Delete a baseline and its entries by ID."""
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT id FROM baselines WHERE id=?", (baseline_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404,
                                detail=f"Baseline {baseline_id} not found")
        conn.execute(
            "DELETE FROM baseline_entries WHERE baseline_id=?", (baseline_id,)
        )
        conn.execute("DELETE FROM baselines WHERE id=?", (baseline_id,))
        conn.commit()
        return {"message": f"Baseline {baseline_id} deleted"}
    finally:
        conn.close()


@router.get("/diff")
def get_diff(
    entry_type:  Literal["all", "registry", "task", "service"] = "all",
    baseline_id: Optional[int] = None,
):
    """
    New High/Critical entries since the last (or specified) baseline.
    This is the core alert feed.
    """
    conn = _conn()
    try:
        # Resolve baseline
        if baseline_id:
            bl = conn.execute(
                "SELECT * FROM baselines WHERE id=?", (baseline_id,)
            ).fetchone()
        else:
            bl = conn.execute(
                "SELECT * FROM baselines ORDER BY id DESC LIMIT 1"
            ).fetchone()

        if not bl:
            return {
                "baseline": None,
                "new_entries": [],
                "total": 0,
                "message": "No baseline found — run a baseline scan first",
            }

        bl = dict(bl)
        types = (
            ["registry", "task", "service"]
            if entry_type == "all"
            else [entry_type]
        )

        new_entries = []
        for et in types:
            new_entries.extend(_get_new_entries(conn, et, bl["id"]))

        return {
            "baseline":    bl,
            "new_entries": new_entries,
            "total":       len(new_entries),
            "by_severity": {
                "critical": sum(1 for e in new_entries if e.get("severity") == "critical"),
                "high":     sum(1 for e in new_entries if e.get("severity") == "high"),
            },
        }
    finally:
        conn.close()