"""
enrichment/baseline.py
----------------------
Baseline diffing engine for Persistence-Hunter.

On first run: snapshots all current entries as "known good".
On subsequent runs: compares against baseline, reports only NEW entries.

This is the feature that turns a noisy 700-entry service list into
"3 new things since yesterday" — the most operationally useful feature.
"""

import json
import sqlite3
import hashlib
from datetime import datetime, timezone


class BaselineManager:
    """
    Manages persistence baselines across all entry types.
    A baseline is a snapshot of all hash_ids at a point in time.
    New entries = current hash_ids NOT in the baseline.
    """

    def __init__(self, db_path: str = "reghunt.db"):
        self.db_path = db_path
        self._init_tables()

    def _init_tables(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS baselines (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL,
                entry_type   TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                entry_count  INTEGER DEFAULT 0,
                notes        TEXT
            );
            CREATE TABLE IF NOT EXISTS baseline_entries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                baseline_id  INTEGER NOT NULL,
                hash_id      TEXT NOT NULL,
                entry_name   TEXT,
                entry_value  TEXT,
                FOREIGN KEY(baseline_id) REFERENCES baselines(id),
                UNIQUE(baseline_id, hash_id)
            );
            CREATE INDEX IF NOT EXISTS idx_baseline_entries_bid
                ON baseline_entries(baseline_id);
            CREATE INDEX IF NOT EXISTS idx_baseline_entries_hash
                ON baseline_entries(hash_id);
        """)
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Snapshot creation
    # ------------------------------------------------------------------

    def create_baseline(self, entry_type: str = "all",
                        name: str = None) -> int:
        """
        Snapshot the current state of persistence entries.
        entry_type: 'registry', 'task', 'service', or 'all'
        Returns the baseline ID.
        """
        name = name or f"baseline_{datetime.now(tz=timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            tables = self._get_tables(entry_type)
            all_entries = []
            for table, etype in tables:
                rows = conn.execute(
                    f"SELECT hash_id, name, value_data FROM {table}"
                    if table == "registry_entries" else
                    f"SELECT hash_id, task_name as name, command as value_data FROM {table}"
                    if table == "task_entries" else
                    f"SELECT hash_id, service_name as name, binary_path as value_data FROM {table}"
                ).fetchall()
                for row in rows:
                    all_entries.append({
                        "hash_id":     row["hash_id"],
                        "entry_name":  row["name"] or "",
                        "entry_value": (row["value_data"] or "")[:200],
                        "entry_type":  etype,
                    })

            # Create baseline record
            cur = conn.execute("""
                INSERT INTO baselines (name, entry_type, created_at, entry_count)
                VALUES (?, ?, ?, ?)
            """, (name, entry_type,
                  datetime.now(tz=timezone.utc).isoformat(),
                  len(all_entries)))
            baseline_id = cur.lastrowid

            # Insert entries
            conn.executemany("""
                INSERT OR IGNORE INTO baseline_entries
                    (baseline_id, hash_id, entry_name, entry_value)
                VALUES (?, ?, ?, ?)
            """, [(baseline_id, e["hash_id"], e["entry_name"], e["entry_value"])
                  for e in all_entries])

            conn.commit()
            return baseline_id

        finally:
            conn.close()

    def _get_tables(self, entry_type: str) -> list[tuple]:
        if entry_type == "registry":
            return [("registry_entries", "registry")]
        if entry_type == "task":
            return [("task_entries", "task")]
        if entry_type == "service":
            return [("service_entries", "service")]
        return [
            ("registry_entries", "registry"),
            ("task_entries",     "task"),
            ("service_entries",  "service"),
        ]

    # ------------------------------------------------------------------
    # Diffing
    # ------------------------------------------------------------------

    def get_latest_baseline(self, entry_type: str = "all") -> dict | None:
        """Return the most recent baseline for a given entry type."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("""
                SELECT * FROM baselines
                WHERE entry_type = ?
                ORDER BY created_at DESC LIMIT 1
            """, (entry_type,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def diff(self, entry_type: str = "all",
             baseline_id: int = None) -> dict:
        """
        Compare current entries against a baseline.
        Returns: { new: [...], removed: [...], baseline_info: {...} }
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            # Get baseline
            if baseline_id:
                baseline = conn.execute(
                    "SELECT * FROM baselines WHERE id=?", (baseline_id,)
                ).fetchone()
            else:
                baseline = conn.execute("""
                    SELECT * FROM baselines WHERE entry_type=?
                    ORDER BY created_at DESC LIMIT 1
                """, (entry_type,)).fetchone()

            if not baseline:
                return {
                    "error":         "No baseline found — run --baseline first",
                    "new":           [],
                    "removed":       [],
                    "baseline_info": None,
                }

            baseline_id = baseline["id"]

            # Get baseline hash_ids
            baseline_hashes = set(
                row["hash_id"] for row in conn.execute(
                    "SELECT hash_id FROM baseline_entries WHERE baseline_id=?",
                    (baseline_id,)
                ).fetchall()
            )

            # Get current hash_ids + full entry data
            tables = self._get_tables(entry_type)
            current_entries = {}
            for table, etype in tables:
                if table == "registry_entries":
                    rows = conn.execute(
                        "SELECT id, hash_id, name, value_data, severity, "
                        "ioc_notes, first_seen FROM registry_entries"
                    ).fetchall()
                    for row in rows:
                        current_entries[row["hash_id"]] = {
                            "id":         row["id"],
                            "type":       etype,
                            "name":       row["name"],
                            "value":      row["value_data"],
                            "severity":   row["severity"],
                            "ioc_notes":  row["ioc_notes"],
                            "first_seen": row["first_seen"],
                        }
                elif table == "task_entries":
                    rows = conn.execute(
                        "SELECT id, hash_id, task_name, command, severity, "
                        "ioc_notes, first_seen FROM task_entries"
                    ).fetchall()
                    for row in rows:
                        current_entries[row["hash_id"]] = {
                            "id":         row["id"],
                            "type":       etype,
                            "name":       row["task_name"],
                            "value":      row["command"],
                            "severity":   row["severity"],
                            "ioc_notes":  row["ioc_notes"],
                            "first_seen": row["first_seen"],
                        }
                elif table == "service_entries":
                    rows = conn.execute(
                        "SELECT id, hash_id, service_name, binary_path, severity, "
                        "ioc_notes, first_seen FROM service_entries"
                    ).fetchall()
                    for row in rows:
                        current_entries[row["hash_id"]] = {
                            "id":         row["id"],
                            "type":       etype,
                            "name":       row["service_name"],
                            "value":      row["binary_path"],
                            "severity":   row["severity"],
                            "ioc_notes":  row["ioc_notes"],
                            "first_seen": row["first_seen"],
                        }

            current_hashes = set(current_entries.keys())

            # New = in current but not in baseline
            new_hashes     = current_hashes - baseline_hashes
            # Removed = in baseline but not in current
            removed_hashes = baseline_hashes - current_hashes

            new_entries = [current_entries[h] for h in new_hashes]
            new_entries.sort(key=lambda x: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                    x.get("severity", "medium"), 2)
            ))

            # Get removed entry names from baseline_entries table
            removed_entries = []
            for h in removed_hashes:
                row = conn.execute(
                    "SELECT entry_name, entry_value FROM baseline_entries "
                    "WHERE baseline_id=? AND hash_id=?",
                    (baseline_id, h)
                ).fetchone()
                if row:
                    removed_entries.append({
                        "hash_id": h,
                        "name":    row["entry_name"],
                        "value":   row["entry_value"],
                    })

            return {
                "baseline_info": {
                    "id":          baseline_id,
                    "name":        baseline["name"],
                    "created_at":  baseline["created_at"],
                    "entry_count": baseline["entry_count"],
                },
                "current_count":  len(current_hashes),
                "new":            new_entries,
                "removed":        removed_entries,
                "new_count":      len(new_entries),
                "removed_count":  len(removed_entries),
            }

        finally:
            conn.close()

    def list_baselines(self) -> list[dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT * FROM baselines ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def delete_baseline(self, baseline_id: int):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "DELETE FROM baseline_entries WHERE baseline_id=?", (baseline_id,)
            )
            conn.execute(
                "DELETE FROM baselines WHERE id=?", (baseline_id,)
            )
            conn.commit()
        finally:
            conn.close()