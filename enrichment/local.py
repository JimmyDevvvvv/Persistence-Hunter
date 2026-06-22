"""
enrichment/local.py
===================
Local PE signature checking via PowerShell Get-AuthenticodeSignature.
No API key, no network. Always available.

Key public API
--------------
  batch_check_signatures(paths, db_path) -> dict
      Check many paths in ONE PowerShell call.
      Results are cached in the signature_cache table keyed by SHA-256 so
      unchanged binaries are never checked twice.

  check_signature(path, db_path)  -> dict   (single-path wrapper)
  enrich_entry(entry, db_path)    -> dict   (entry-dict wrapper)

All return dicts keyed for use as the `enrichment` arg to score_entry():
    pe_is_pe  : bool  — True if we resolved an .exe
    pe_signed : bool  — True when Authenticode status == Valid
    pe_vendor : str   — CN from signer certificate, or ""

Performance
-----------
  N sequential PowerShell calls: N × ~0.5 s
  1 batch PowerShell call:        1 × ~0.7 s  (all N paths)
  Cached call:                    0 s          (pure SQLite lookup)

The signature_cache table (reghunt.db) persists hashes so the expensive
PowerShell call is only made once per unique binary.  If the file is later
replaced, the SHA-256 changes and the new version is checked automatically.
"""

from __future__ import annotations

import os
import re
import json
import hashlib
import sqlite3
import subprocess
from typing import Optional

# ── Constants ──────────────────────────────────────────────────────────────

DB_PATH = "reghunt.db"

_STATUS_MAP: dict = {
    0: "Valid",
    1: "HashMismatch",
    2: "NotSigned",
    3: "UnknownError",
    4: "NotSupportedFileFormat",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_exe_path(value: str) -> Optional[str]:
    """Pull the first .exe path from a persistence value / binary path."""
    if not value:
        return None
    v = os.path.expandvars(value.strip())

    m = re.match(r'^"([^"]+\.exe)"', v, re.IGNORECASE)
    if m:
        return m.group(1)

    m = re.match(r'^([A-Za-z]:[^\s"]+\.exe)', v, re.IGNORECASE)
    if m:
        return m.group(1)

    m = re.match(r'^(\S+\.exe)', v, re.IGNORECASE)
    if m and os.path.exists(m.group(1)):
        return m.group(1)

    return None


def _file_sha256(path: str) -> Optional[str]:
    """SHA-256 hex digest of *path*, or None on any I/O error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _parse_status(raw) -> str:
    if isinstance(raw, int):
        return _STATUS_MAP.get(raw, f"Unknown({raw})")
    return str(raw) if raw else "UnknownError"


def _parse_publisher(subject: str) -> str:
    """Extract CN= value from a certificate Subject string."""
    m = re.search(r"CN=([^,]+)", subject or "")
    return m.group(1).strip() if m else (subject or "").strip()


# ---------------------------------------------------------------------------
# Cache table
# ---------------------------------------------------------------------------

def _ensure_sig_cache_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS signature_cache (
            file_hash   TEXT    PRIMARY KEY,
            path        TEXT,
            signed      INTEGER NOT NULL DEFAULT 0,
            publisher   TEXT    NOT NULL DEFAULT '',
            status      TEXT    NOT NULL DEFAULT '',
            checked_at  TEXT    DEFAULT (datetime('now'))
        )
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Batch PowerShell call
# ---------------------------------------------------------------------------

def _ps_escape(path: str) -> str:
    """Escape a file path for embedding in a PowerShell double-quoted string."""
    return path.replace('"', '`"')


def _powershell_batch(paths: list) -> dict:
    """
    Run Get-AuthenticodeSignature on *paths* in a SINGLE PowerShell call.

    Returns {original_path_lower: {"signed": bool, "publisher": str, "status": str}}.
    Keys are lower-cased so callers can do case-insensitive lookup.
    Paths that do not exist on disk are silently absent from the result.
    """
    if not paths:
        return {}

    arr_literal = ",".join(f'"{_ps_escape(p)}"' for p in paths)

    # One-liner:
    #   $pa = @("p1","p2",...)           — array of paths
    #   $r  = $pa | Where-Object {...}   — skip missing files
    #           | Get-AuthenticodeSignature
    #           | ForEach-Object { ... } — project to plain PSCustomObject
    #   ConvertTo-Json $r                — serialise (single obj or array)
    #
    # Note: braces in this regular (non-f) string are literal PowerShell braces.
    ps = (
        "$pa=@(" + arr_literal + "); "
        "$r=$pa|Where-Object{Test-Path $_}"
        "|Get-AuthenticodeSignature"
        "|ForEach-Object{"
        "[PSCustomObject]@{"
        "Path=$_.Path;"
        "Status=[int]$_.Status;"
        "Subject=if($_.SignerCertificate){$_.SignerCertificate.Subject}else{''}"
        "}}; "
        "ConvertTo-Json $r"
    )

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=60,
        )
        text = (proc.stdout or "").strip()
        if not text or text.lower() == "null":
            return {}

        data = json.loads(text)
        if isinstance(data, dict):
            data = [data]   # single result — normalise to list

        out: dict = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            raw_path  = (item.get("Path") or "")
            publisher = _parse_publisher(item.get("Subject") or "")
            status    = _parse_status(item.get("Status"))
            out[raw_path.lower()] = {
                "signed":    status == "Valid",
                "publisher": publisher,
                "status":    status,
            }
        return out

    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return {}


# ---------------------------------------------------------------------------
# Public batch API
# ---------------------------------------------------------------------------

def batch_check_signatures(
    paths: list,
    db_path: str = DB_PATH,
) -> tuple[dict, int, int]:
    """
    Check Authenticode signatures for *paths* efficiently.

    Algorithm:
      1. Non-existent files → {"signed": False, "publisher": "", "status": "missing"}
      2. Hash existing files (SHA-256); look up in signature_cache.
      3. Cache hits → returned immediately (zero PowerShell cost).
      4. Cache misses → ONE PowerShell call for ALL uncached paths.
      5. New results stored in cache for next run.

    Returns:
        (results, n_cached, n_fresh)
        results  : {path: {"signed": bool, "publisher": str, "status": str}}
        n_cached : how many paths came from cache
        n_fresh  : how many required a live PowerShell check
    """
    if not paths:
        return {}, 0, 0

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_sig_cache_table(conn)

    results:        dict = {}
    path_to_hash:   dict = {}   # path -> sha256 or None
    uncached:       list = []   # paths that need a live check
    n_cached = 0

    # ── Step 1: hash files, check cache ─────────────────────────────────
    for path in paths:
        if not os.path.isfile(path):
            results[path] = {"signed": False, "publisher": "", "status": "missing"}
            continue

        fhash = _file_sha256(path)
        path_to_hash[path] = fhash

        if fhash:
            row = conn.execute(
                "SELECT signed, publisher, status "
                "FROM   signature_cache WHERE file_hash = ?",
                (fhash,),
            ).fetchone()
            if row:
                results[path] = {
                    "signed":    bool(row["signed"]),
                    "publisher": row["publisher"] or "",
                    "status":    row["status"]    or "",
                }
                n_cached += 1
                continue

        uncached.append(path)

    # ── Step 2: batch PowerShell for uncached paths ──────────────────────
    n_fresh = len(uncached)

    if uncached:
        ps_results = _powershell_batch(uncached)   # keys are lower-cased paths

        for path in uncached:
            sig = ps_results.get(path.lower())
            if sig is None:
                # File vanished between hash and PS call, or PS error
                sig = {"signed": False, "publisher": "", "status": "missing"}

            results[path] = sig

            # ── Step 3: cache the fresh result ───────────────────────────
            fhash = path_to_hash.get(path)
            if fhash:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO signature_cache
                        (file_hash, path, signed, publisher, status, checked_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                    """,
                    (
                        fhash,
                        path,
                        1 if sig["signed"] else 0,
                        sig["publisher"],
                        sig["status"],
                    ),
                )

        conn.commit()

    conn.close()
    return results, n_cached, n_fresh


# ---------------------------------------------------------------------------
# Legacy single-path API (kept for backwards compatibility)
# ---------------------------------------------------------------------------

def check_signature(path: str, db_path: str = DB_PATH) -> dict:
    """
    Check Authenticode signature for a single file.
    Uses the cache and the same PowerShell batch internally.
    Prefer batch_check_signatures() when checking multiple paths.
    """
    results, _, _ = batch_check_signatures([path], db_path=db_path)
    return results.get(path, {"signed": False, "publisher": "", "status": "error"})


def enrich_entry(entry: dict, db_path: str = DB_PATH) -> dict:
    """
    Resolve the binary path from a persistence entry dict and check
    its Authenticode signature.  Returned dict is keyed for score_entry().
    """
    value = (
        entry.get("value_data") or
        entry.get("command")    or
        entry.get("binary_path") or
        ""
    )
    exe_path = _extract_exe_path(value)
    if not exe_path:
        return {"pe_is_pe": False, "pe_signed": False, "pe_vendor": ""}

    sig = check_signature(exe_path, db_path=db_path)
    return {
        "pe_is_pe":  True,
        "pe_signed": sig["signed"],
        "pe_vendor": sig["publisher"],
    }
