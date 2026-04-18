"""api/routes/search.py — /api/search (hunter mode)"""

from typing import Literal
from fastapi import APIRouter, Query
from api.dependencies import get_db, row_to_dict

router = APIRouter()


@router.get("")
def search(
    q:          str,
    entry_type: Literal["all", "registry", "task", "service"] = "all",
    limit:      int = Query(default=100, le=500),
):
    """
    Full-text search across all persistence data.

    Searches:
    - Registry: name, value_data
    - Tasks: task_name, command, arguments
    - Services: service_name, binary_path, display_name
    - Process events: process_name, command_line (for chain hunting)

    Returns persistence matches + matching process event command lines,
    giving you a cross-telemetry pivot from a single query.
    """
    conn = get_db()
    try:
        term    = f"%{q.lower()}%"
        results = []

        if entry_type in ("all", "registry"):
            rows = conn.execute("""
                SELECT id, 'registry' as entry_type,
                       name, value_data as value,
                       severity, last_seen, ioc_notes
                FROM registry_entries
                WHERE LOWER(name) LIKE ? OR LOWER(value_data) LIKE ?
                ORDER BY CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium'   THEN 2 ELSE 3 END
                LIMIT ?
            """, (term, term, limit)).fetchall()
            results += [row_to_dict(r) for r in rows]

        if entry_type in ("all", "task"):
            rows = conn.execute("""
                SELECT id, 'task' as entry_type,
                       task_name as name,
                       command as value,
                       severity, last_seen, ioc_notes
                FROM task_entries
                WHERE LOWER(task_name) LIKE ?
                   OR LOWER(command)   LIKE ?
                   OR LOWER(COALESCE(arguments,'')) LIKE ?
                ORDER BY CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium'   THEN 2 ELSE 3 END
                LIMIT ?
            """, (term, term, term, limit)).fetchall()
            results += [row_to_dict(r) for r in rows]

        if entry_type in ("all", "service"):
            rows = conn.execute("""
                SELECT id, 'service' as entry_type,
                       service_name as name,
                       binary_path as value,
                       severity, last_seen, ioc_notes
                FROM service_entries
                WHERE LOWER(service_name)  LIKE ?
                   OR LOWER(binary_path)   LIKE ?
                   OR LOWER(COALESCE(display_name,'')) LIKE ?
                ORDER BY CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium'   THEN 2 ELSE 3 END
                LIMIT ?
            """, (term, term, term, limit)).fetchall()
            results += [row_to_dict(r) for r in rows]

        # Process event command-line pivot (cross-telemetry hunting)
        proc_hits = conn.execute("""
            SELECT pid, process_name, command_line, event_time, user_name
            FROM sysmon_process_events
            WHERE LOWER(command_line)  LIKE ?
               OR LOWER(process_name) LIKE ?
            ORDER BY event_time DESC
            LIMIT 50
        """, (term, term)).fetchall()

        # Re-sort combined persistence results by severity
        sev_key = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: sev_key.get(x.get("severity", "low"), 4))

        return {
            "query":       q,
            "results":     results,
            "count":       len(results),
            "proc_hits":   [row_to_dict(r) for r in proc_hits],
            "proc_count":  len(proc_hits),
        }
    finally:
        conn.close()
