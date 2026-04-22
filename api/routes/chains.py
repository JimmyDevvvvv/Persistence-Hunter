"""api/routes/chains.py — /api/chains"""

import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from api.dependencies import get_db, DB_PATH

router = APIRouter()

def _attach_sysmon_hashes(conn, chain: list[dict]) -> list[dict]:
    """
    Fallback enrichment: only fills in hashes/integrity_level on nodes that
    don't already have them (e.g. chains built before the base_collector fix,
    or nodes sourced from the 4688 table which has no hash data).
    New chains built via base_collector._enrich_process_node will already
    have these fields and will be skipped.
    """
    if not chain:
        return chain

    for node in chain:
        # Skip if already enriched natively during chain build
        if node.get("hashes") and node.get("integrity_level"):
            continue

        pid = node.get("pid")
        event_time = node.get("event_time")
        if not pid or not event_time:
            continue

        row = conn.execute("""
            SELECT hashes, integrity_level
            FROM sysmon_process_events
            WHERE pid = ? AND event_time <= ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (pid, event_time)).fetchone()

        if not row:
            continue

        if not node.get("hashes") and row["hashes"]:
            hashes_dict = {}
            for part in str(row["hashes"]).split(","):
                part = part.strip()
                if "=" in part:
                    algo, val = part.split("=", 1)
                    hashes_dict[algo.upper()] = val.lower()
            if hashes_dict:
                node["hashes"] = hashes_dict

        if not node.get("integrity_level") and row["integrity_level"]:
            node["integrity_level"] = row["integrity_level"]

    return chain


@router.get("/{entry_type}/{entry_id}")
def get_chain(entry_type: str, entry_id: int, rebuild: bool = False):
    """
    Return the attack chain for a persistence entry.
    Pass rebuild=true to force a fresh chain build (ignores cache).
    """
    conn = get_db()
    try:
        # Serve cached chain unless rebuild requested
        if not rebuild:
            row = conn.execute("""
                SELECT chain_json, built_at FROM attack_chains
                WHERE entry_type=? AND entry_id=?
            """, (entry_type, entry_id)).fetchone()
            if row:
                chain = json.loads(row["chain_json"])
                chain = _attach_sysmon_hashes(conn, chain)
                return {
                    "entry_type": entry_type,
                    "entry_id":   entry_id,
                    "chain":      chain,
                    "built_at":   row["built_at"],
                    "cached":     True,
                }
    finally:
        conn.close()

    # Build fresh chain
    collector_map = {
        "registry": ("collector.registry_collector", "RegistryCollector"),
        "task":     ("collector.task_collector",     "TaskCollector"),
        "service":  ("collector.service_collector",  "ServiceCollector"),
    }
    if entry_type not in collector_map:
        raise HTTPException(status_code=400,
                            detail=f"Unknown entry type: {entry_type}")

    module_name, class_name = collector_map[entry_type]
    import importlib
    module    = importlib.import_module(module_name)
    collector = getattr(module, class_name)(db_path=DB_PATH)
    try:
        chain = collector.build_attack_chain(entry_id)
    finally:
        collector.close()

    # Fallback: attach sysmon data to any nodes that missed it (e.g. 4688-sourced)
    conn = get_db()
    try:
        chain = _attach_sysmon_hashes(conn, chain)
    finally:
        conn.close()

    return {
        "entry_type": entry_type,
        "entry_id":   entry_id,
        "chain":      chain,
        "built_at":   datetime.now(tz=timezone.utc).isoformat(),
        "cached":     False,
    }