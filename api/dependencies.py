"""
api/dependencies.py
-------------------
Shared dependencies injected into route handlers.
Single source of truth for DB path, connection factory, and helpers.
"""

import os
import sys
import json
import sqlite3

# ---------------------------------------------------------------------------
# Path setup — ensure collector + enrichment packages are importable
# ---------------------------------------------------------------------------

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT,
           os.path.join(ROOT, "collector"),
           os.path.join(ROOT, "enrichment")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# DB path (override with env var REGHUNT_DB)
# ---------------------------------------------------------------------------

DB_PATH: str = os.environ.get(
    "REGHUNT_DB",
    os.path.join(ROOT, "reghunt.db"),
)

# ---------------------------------------------------------------------------
# DB factory
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """Open and return a SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

_JSON_FIELDS = ("techniques", "risk_indicators", "enrich_indicators")

def row_to_dict(row) -> dict:
    """Convert a sqlite3.Row to a plain dict, parsing known JSON string fields."""
    if row is None:
        return {}
    d = dict(row)
    for key in _JSON_FIELDS:
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except Exception:
                d[key] = []
    return d
