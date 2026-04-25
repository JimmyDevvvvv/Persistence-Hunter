"""api/routes/signatures.py — /api/signatures"""

import os
import sys
import json
import sqlite3
from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import JSONResponse
from api.dependencies import DB_PATH

# Ensure project root on path for check_signatures imports
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

router = APIRouter()

# In-memory cache — re-run only when POST /api/signatures/run is called
_last_results: list = []
_last_run_at: str | None = None


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _run_check() -> list:
    """Run the full signature check and return results list."""
    from check_signatures import (
        extract_exe_path, sha256_file, check_signature,
        is_suspicious_path, is_system_path
    )

    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM service_entries ORDER BY severity DESC, service_name"
    ).fetchall()
    conn.close()

    results = []
    for row in rows:
        svc      = dict(row)
        name     = svc["service_name"]
        bp       = svc["binary_path"]
        severity = svc["severity"]
        ioc      = svc.get("ioc_notes", "")

        exe_path = extract_exe_path(bp)

        result = {
            "service_name":   name,
            "binary_path":    bp,
            "exe_path":       exe_path,
            "severity":       severity,
            "ioc_notes":      ioc,
            "sha256":         None,
            "sig_status":     None,
            "signer":         None,
            "issuer":         None,
            "vt_url":         None,
            "suspicious_path": False,
            "file_exists":    False,
        }

        if exe_path:
            result["file_exists"]     = os.path.exists(exe_path)
            result["suspicious_path"] = is_suspicious_path(exe_path)

            sha256 = sha256_file(exe_path)
            result["sha256"]  = sha256
            result["vt_url"]  = (
                f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else None
            )

            sig = check_signature(exe_path)
            result["sig_status"] = sig["status"]
            result["signer"]     = sig["signer"]
            result["issuer"]     = sig["issuer"]
        else:
            result["sig_status"] = "N/A"

        results.append(result)

    return results


def _summarize(results: list) -> dict:
    exe_results = [r for r in results if r["sig_status"] != "N/A"]
    return {
        "total":     len(results),
        "exe_only":  len(exe_results),
        "drivers":   len(results) - len(exe_results),
        "signed":    sum(1 for r in exe_results if r["sig_status"] == "Valid"),
        "unsigned":  sum(1 for r in exe_results if r["sig_status"] == "NotSigned"),
        "missing":   sum(1 for r in exe_results if r["sig_status"] == "Missing"),
        "mismatch":  sum(1 for r in exe_results if r["sig_status"] == "HashMismatch"),
    }


# ── Routes ─────────────────────────────────────────────────────────────────

@router.get("")
def get_signatures(
    unsigned_only: bool = False,
    exe_only:      bool = False,
    severity:      str  = "all",   # all | critical | high
):
    """
    Return cached signature results.
    Call POST /api/signatures/run first to populate.
    """
    global _last_results, _last_run_at

    if not _last_results:
        return JSONResponse(status_code=404, content={
            "detail": "No signature data yet. POST /api/signatures/run to scan.",
            "results": [], "summary": {}
        })

    results = _last_results

    # Filters
    if severity != "all":
        results = [r for r in results if r["severity"] == severity]
    if exe_only:
        results = [r for r in results if r["exe_path"]]
    if unsigned_only:
        results = [r for r in results
                   if r["sig_status"] in ("NotSigned", "Missing", "HashMismatch")]

    return {
        "run_at":   _last_run_at,
        "summary":  _summarize(_last_results),  # always full summary
        "results":  results,
        "iocs": {
            "unsigned":     [r for r in results if r["sig_status"] == "NotSigned"],
            "missing":      [r for r in results if r["sig_status"] == "Missing"],
            "suspicious":   [r for r in results
                             if r["suspicious_path"] and r["sig_status"] != "Valid"],
        }
    }


@router.post("/run")
async def run_signatures(background_tasks: BackgroundTasks):
    """
    Trigger a full signature check in the background.
    Results are cached and returned by GET /api/signatures.
    """
    from datetime import datetime, timezone

    def _do_run():
        global _last_results, _last_run_at
        _last_results = _run_check()
        _last_run_at  = datetime.now(tz=timezone.utc).isoformat()

    background_tasks.add_task(_do_run)
    return {"message": "Signature check started — poll GET /api/signatures for results"}


@router.get("/iocs")
def get_iocs():
    """
    Return only actionable IOCs:
    unsigned binaries, ghost services, suspicious paths.
    """
    if not _last_results:
        return {"iocs": [], "detail": "Run POST /api/signatures/run first"}

    iocs = []
    for r in _last_results:
        if r["sig_status"] in ("NotSigned", "Missing", "HashMismatch"):
            iocs.append({**r, "ioc_type": r["sig_status"].lower()})
        elif r["suspicious_path"] and r["file_exists"]:
            iocs.append({**r, "ioc_type": "suspicious_path"})

    return {
        "count": len(iocs),
        "iocs":  sorted(iocs, key=lambda x: (
            0 if x["ioc_type"] == "missing" else
            1 if x["ioc_type"] == "notsigned" else 2
        ))
    }