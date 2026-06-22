"""
core/exclusion_engine.py
========================
Exclusion / allowlist system for Persistence Hunter.

Four exclusion types
--------------------
  hash     — SHA-256 of the binary (survives renames, catches repackaging)
  path     — path prefix, case-insensitive (e.g. C:\\Program Files\\VMware)
  process  — entry display name (registry value name, task name, service name)
  rule     — APT/behavioral rule id; value "*" = pause all rules

Exclusions may be permanent (expires_at = NULL) or temporary (expires_at = ISO
datetime).  Expired rows are left in the DB but ignored at query time so that
history is preserved.  Call clean_expired() periodically to prune them.

Public API
----------
  is_excluded(entry, score_result, db_path)  → (bool, reason_str)
  add_exclusion(type, value, label, expires_minutes, db_path) → int (new id)
  list_exclusions(db_path)                   → list[dict]
  remove_exclusion(id, db_path)              → bool
  clean_expired(db_path)                     → int (rows deleted)
  load_exclusion_set(db_path)                → dict (fast-lookup sets for correlator)
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

DB_PATH = "reghunt.db"

_VALID_TYPES = frozenset({"hash", "path", "process", "rule"})

_DDL = """
CREATE TABLE IF NOT EXISTS exclusions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    label       TEXT,
    added_at    TEXT,
    expires_at  TEXT
)
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(_DDL)
    conn.commit()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_expired(expires_at: Optional[str]) -> bool:
    if not expires_at:
        return False
    try:
        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp
    except Exception:
        return False


def _load_active(conn: sqlite3.Connection) -> list:
    rows = conn.execute("SELECT * FROM exclusions").fetchall()
    return [dict(r) for r in rows if not _is_expired(r["expires_at"])]


def _entry_name(entry: dict) -> str:
    return (
        entry.get("name") or
        entry.get("task_name") or
        entry.get("service_name") or
        ""
    ).lower()


def _entry_value(entry: dict) -> str:
    return (
        entry.get("value_data") or
        entry.get("command")    or
        entry.get("binary_path") or
        ""
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def clean_expired(db_path: str = DB_PATH) -> int:
    """Delete exclusions whose expires_at is in the past. Returns count."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_table(conn)
    try:
        rows = conn.execute("SELECT id, expires_at FROM exclusions").fetchall()
        to_delete = [r["id"] for r in rows if _is_expired(r["expires_at"])]
        for eid in to_delete:
            conn.execute("DELETE FROM exclusions WHERE id=?", (eid,))
        conn.commit()
        return len(to_delete)
    finally:
        conn.close()


def is_excluded(
    entry:        dict,
    score_result: dict,
    db_path:      str = DB_PATH,
) -> tuple:
    """
    Return (True, reason) if the entry should be suppressed, else (False, "").

    Checks (in order):
      1. hash     — SHA-256 of the resolved binary is in the exclusion list
      2. path     — binary path starts with an excluded prefix
      3. process  — entry display name matches an excluded process
      4. rule     — any matched rule id is excluded, OR value "*" (pause)
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_table(conn)
    try:
        active = _load_active(conn)
    finally:
        conn.close()

    if not active:
        return False, ""

    hash_excl    = {e["value"].lower(): e for e in active if e["type"] == "hash"}
    path_excl    = [e["value"].lower() for e in active if e["type"] == "path"]
    process_excl = {e["value"].lower() for e in active if e["type"] == "process"}
    rule_excl    = {e["value"].lower() for e in active if e["type"] == "rule"}

    value    = _entry_value(entry)
    exe_path = None
    fhash    = None

    # Attempt to resolve binary path & hash
    if hash_excl or path_excl:
        try:
            from enrichment.local import _extract_exe_path, _file_sha256
            exe_path = _extract_exe_path(value)
            if exe_path and hash_excl:
                fhash = _file_sha256(exe_path)
        except ImportError:
            pass

    # 1. Hash check
    if fhash and fhash.lower() in hash_excl:
        ex = hash_excl[fhash.lower()]
        return True, f"hash:{ex.get('label') or fhash[:12]}"

    # 2. Path prefix check (value string, not just exe_path — catches cmd-line entries)
    if path_excl:
        check_paths = [value.lower()]
        if exe_path:
            check_paths.append(exe_path.lower())
        for pfx in path_excl:
            for cp in check_paths:
                if cp.startswith(pfx):
                    return True, f"path:{pfx}"

    # 3. Process / entry name check
    name = _entry_name(entry)
    if name and name in process_excl:
        return True, f"process:{name}"

    # 4. Rule suppression
    if rule_excl:
        # Pause-all wildcard
        if "*" in rule_excl:
            return True, "paused"

        matched_rule_ids = [
            m.get("id", "").lower()
            for m in score_result.get("apt_matches", [])
        ]
        for rid in matched_rule_ids:
            if rid in rule_excl:
                return True, f"rule:{rid}"

    return False, ""


def add_exclusion(
    excl_type:       str,
    value:           str,
    label:           Optional[str] = None,
    expires_minutes: Optional[int] = None,
    db_path:         str = DB_PATH,
) -> int:
    """Add a new exclusion. Returns the new row id."""
    if excl_type not in _VALID_TYPES:
        raise ValueError(f"Invalid exclusion type: {excl_type!r}")

    expires_at: Optional[str] = None
    if expires_minutes is not None:
        expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
        ).isoformat(timespec="seconds")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_table(conn)
    try:
        cur = conn.execute(
            """
            INSERT INTO exclusions (type, value, label, added_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (excl_type, value, label, _now_iso(), expires_at),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_exclusions(db_path: str = DB_PATH) -> list:
    """Return all exclusion rows, each with an `expired` bool field."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_table(conn)
    try:
        rows = conn.execute(
            "SELECT * FROM exclusions ORDER BY added_at DESC"
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["expired"] = _is_expired(d.get("expires_at"))
            result.append(d)
        return result
    finally:
        conn.close()


def remove_exclusion(excl_id: int, db_path: str = DB_PATH) -> bool:
    """Delete an exclusion by id. Returns True if a row was deleted."""
    conn = sqlite3.connect(db_path)
    _ensure_table(conn)
    try:
        cur = conn.execute("DELETE FROM exclusions WHERE id=?", (excl_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def load_exclusion_set(db_path: str = DB_PATH) -> dict:
    """
    Return a lightweight snapshot of active exclusions for use in the
    correlator's hot path.

    Returns:
        {
          "paths":     [str, ...]   — lower-cased path prefixes
          "processes": {str, ...}   — lower-cased process/entry names
          "rules":     {str, ...}   — lower-cased rule ids; "*" = pause all
          "paused":    bool         — True if any rule exclusion value == "*"
        }
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_table(conn)
    try:
        active = _load_active(conn)
    finally:
        conn.close()

    rules = {e["value"].lower() for e in active if e["type"] == "rule"}
    return {
        "paths":     [e["value"].lower() for e in active if e["type"] == "path"],
        "processes": {e["value"].lower() for e in active if e["type"] == "process"},
        "rules":     rules,
        "paused":    "*" in rules,
    }
