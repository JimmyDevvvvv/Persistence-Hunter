"""api/routes/summary.py — /api/summary"""

import json
import sqlite3
from fastapi import APIRouter
from api.dependencies import DB_PATH

router = APIRouter()


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _decode_ps(cmdline: str):
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        from ps_decode import decode_ps_command, format_decoded
        decoded = decode_ps_command(cmdline or "")
        return format_decoded(decoded, max_len=200) if decoded else None
    except Exception:
        return None


def _parse_techniques(raw):
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            return []
    tags = []
    for t in raw:
        if isinstance(t, dict):
            tid = t.get("id") or t.get("technique_id") or ""
            tags.append(tid if tid else str(t))
        else:
            tags.append(str(t))
    return tags


def _get_chain(conn, entry_type: str, entry_id: int) -> list:
    row = conn.execute(
        "SELECT chain_json FROM attack_chains WHERE entry_type=? AND entry_id=?",
        (entry_type, entry_id)
    ).fetchone()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            return []
    return []


def _get_new_entries(conn, entry_type: str, table: str,
                     name_col: str, val_col: str,
                     baseline_id: int | None, include_all: bool) -> list:
    if include_all:
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE severity IN ('critical','high') "
            f"ORDER BY severity DESC, {name_col}"
        ).fetchall()
    elif baseline_id is None:
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE severity IN ('critical','high') "
            f"ORDER BY severity DESC, {name_col}"
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT t.* FROM {table} t "
            f"WHERE NOT EXISTS ("
            f"  SELECT 1 FROM baseline_entries be "
            f"  WHERE be.baseline_id=? AND be.entry_type=? AND be.hash_id=t.hash_id"
            f") AND t.severity IN ('critical','high') "
            f"ORDER BY t.severity DESC, t.{name_col}",
            (baseline_id, entry_type)
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("")
def get_summary(include_all: bool = False, include_chains: bool = False):
    """
    Cross-collector scan summary.
    Returns new High/Critical entries since last baseline across all categories.
    Set include_all=true to ignore baseline and return all High/Critical.
    Set include_chains=true to include attack chain per entry.
    """
    conn = _conn()
    try:
        # Baseline
        bl_row = conn.execute(
            "SELECT * FROM baselines ORDER BY id DESC LIMIT 1"
        ).fetchone()
        bl = dict(bl_row) if bl_row else None
        bl_id = bl["id"] if bl else None

        type_map = [
            ("registry", "registry_entries", "name",         "value_data"),
            ("task",     "task_entries",     "task_name",     "command"),
            ("service",  "service_entries",  "service_name",  "binary_path"),
        ]

        all_entries = []
        by_type = {}

        for et, table, name_col, val_col in type_map:
            entries = _get_new_entries(
                conn, et, table, name_col, val_col, bl_id, include_all
            )
            enriched = []
            for e in entries:
                e["entry_type"]   = et
                e["display_name"] = e.get(name_col, "?")
                e["display_value"]= e.get(val_col, "")
                e["techniques"]   = _parse_techniques(e.get("techniques"))
                decoded = _decode_ps(e.get(val_col, ""))
                if decoded:
                    e["decoded_command"] = decoded
                if include_chains:
                    e["chain"] = _get_chain(conn, et, e["id"])
                enriched.append(e)
            by_type[et] = enriched
            all_entries.extend(enriched)

        critical = [e for e in all_entries if e.get("severity") == "critical"]
        high     = [e for e in all_entries if e.get("severity") == "high"]

        return {
            "baseline":       bl,
            "showing":        "all" if include_all else "new_since_baseline",
            "total":          len(all_entries),
            "critical":       len(critical),
            "high":           len(high),
            "registry":       by_type["registry"],
            "tasks":          by_type["task"],
            "services":       by_type["service"],
            "clean":          len(all_entries) == 0,
        }
    finally:
        conn.close()


@router.get("/stats")
def get_stats():
    """Quick counts — used by dashboard header cards."""
    conn = _conn()
    try:
        bl_row = conn.execute(
            "SELECT id FROM baselines ORDER BY id DESC LIMIT 1"
        ).fetchone()
        bl_id = bl_row[0] if bl_row else None

        stats = {}
        for et, table in [
            ("registry", "registry_entries"),
            ("task",     "task_entries"),
            ("service",  "service_entries"),
        ]:
            total = conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            critical = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE severity='critical'"
            ).fetchone()[0]
            high = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE severity='high'"
            ).fetchone()[0]

            new = 0
            if bl_id:
                new = conn.execute(
                    f"SELECT COUNT(*) FROM {table} t "
                    f"WHERE t.severity IN ('critical','high') "
                    f"AND NOT EXISTS ("
                    f"  SELECT 1 FROM baseline_entries be "
                    f"  WHERE be.baseline_id=? AND be.entry_type=? AND be.hash_id=t.hash_id"
                    f")", (bl_id, et)
                ).fetchone()[0]

            stats[et] = {
                "total": total, "critical": critical,
                "high": high, "new": new
            }

        total_new = sum(v["new"] for v in stats.values())
        total_critical = sum(v["critical"] for v in stats.values())

        return {
            "baseline_date": bl_row and conn.execute(
                "SELECT created_at FROM baselines WHERE id=?", (bl_id,)
            ).fetchone()[0],
            "total_new":      total_new,
            "total_critical": total_critical,
            "registry":       stats["registry"],
            "tasks":          stats["task"],
            "services":       stats["service"],
            "clean":          total_new == 0,
        }
    finally:
        conn.close()