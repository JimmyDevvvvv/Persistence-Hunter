"""api/routes/chains.py — /api/chains"""

import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from api.dependencies import get_db, DB_PATH

router = APIRouter()


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
                return {
                    "entry_type": entry_type,
                    "entry_id":   entry_id,
                    "chain":      json.loads(row["chain_json"]),
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

    return {
        "entry_type": entry_type,
        "entry_id":   entry_id,
        "chain":      chain,
        "built_at":   datetime.now(tz=timezone.utc).isoformat(),
        "cached":     False,
    }
