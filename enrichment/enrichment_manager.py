"""
enrichment/enrichment_manager.py
---------------------------------
Orchestrates all enrichment for persistence entries.
Ties together: file_enricher, threat_intel, baseline.
Stores results back into the DB.

CLI usage:
    python enrichment/enrichment_manager.py --enrich-all --hours 24
    python enrichment/enrichment_manager.py --enrich-id 42 --type registry
    python enrichment/enrichment_manager.py --baseline
    python enrichment/enrichment_manager.py --diff
    python enrichment/enrichment_manager.py --diff --show-all
"""

import os
import sys
import json
import sqlite3
import argparse
from datetime import datetime, timezone

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from enrichment.file_enricher   import FileEnricher
from enrichment.threat_intel    import ThreatIntelEnricher
from enrichment.baseline        import BaselineManager
try:
    from collector.base_collector import Colors
except ImportError:
    try:
        from base_collector import Colors
    except ImportError:
        class Colors:
            RED=YELLOW=GREEN=CYAN=MAGENTA=BOLD=DIM=RESET=WHITE=GREY=""
            @classmethod
            def disable(cls): pass


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _init_enrichment_table(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS enrichment_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_type      TEXT NOT NULL,
            entry_id        INTEGER NOT NULL,
            exe_path        TEXT,
            md5             TEXT,
            sha1            TEXT,
            sha256          TEXT,
            file_exists     INTEGER DEFAULT 0,
            file_size       INTEGER,
            pe_is_pe        INTEGER DEFAULT 0,
            pe_compile_time TEXT,
            pe_compile_suspicious INTEGER DEFAULT 0,
            pe_signed       INTEGER DEFAULT 0,
            pe_valid_sig    INTEGER DEFAULT 0,
            pe_publisher    TEXT,
            pe_entropy_high INTEGER DEFAULT 0,
            vt_found        INTEGER DEFAULT 0,
            vt_malicious    INTEGER DEFAULT 0,
            vt_total        INTEGER DEFAULT 0,
            vt_verdict      TEXT,
            vt_link         TEXT,
            mb_found        INTEGER DEFAULT 0,
            mb_malware      INTEGER DEFAULT 0,
            mb_signature    TEXT,
            mb_link         TEXT,
            risk_indicators TEXT DEFAULT '[]',
            overall_verdict TEXT DEFAULT 'unknown',
            enriched_at     TEXT,
            UNIQUE(entry_type, entry_id)
        );
        CREATE INDEX IF NOT EXISTS idx_enrich_type_id
            ON enrichment_results(entry_type, entry_id);
        CREATE INDEX IF NOT EXISTS idx_enrich_sha256
            ON enrichment_results(sha256);
        CREATE INDEX IF NOT EXISTS idx_enrich_verdict
            ON enrichment_results(overall_verdict);
    """)
    conn.commit()
    conn.close()


def _get_entries(db_path: str, entry_type: str,
                 only_high_critical: bool = False) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        sev_filter = "AND severity IN ('high','critical')" if only_high_critical else ""
        if entry_type == "registry":
            rows = conn.execute(
                f"SELECT id, name, value_data, severity FROM registry_entries {sev_filter}"
            ).fetchall()
            return [{"id": r["id"], "name": r["name"],
                     "value_data": r["value_data"],
                     "severity": r["severity"]} for r in rows]
        elif entry_type == "task":
            rows = conn.execute(
                f"SELECT id, task_name, command, arguments, severity FROM task_entries {sev_filter}"
            ).fetchall()
            return [{"id": r["id"], "task_name": r["task_name"],
                     "command": r["command"], "arguments": r["arguments"] or "",
                     "severity": r["severity"]} for r in rows]
        elif entry_type == "service":
            rows = conn.execute(
                f"SELECT id, service_name, binary_path, severity FROM service_entries {sev_filter}"
            ).fetchall()
            return [{"id": r["id"], "service_name": r["service_name"],
                     "binary_path": r["binary_path"],
                     "severity": r["severity"]} for r in rows]
    finally:
        conn.close()
    return []


def _store_enrichment(db_path: str, entry_type: str,
                      entry_id: int, result: dict):
    """Flatten enrichment result into DB columns."""
    file_info = result.get("file_info", {})
    hashes    = result.get("hashes", {})
    pe        = result.get("pe_metadata", {})
    sig       = result.get("signature", {})
    intel     = result.get("threat_intel", {}) or {}
    vt        = intel.get("virustotal") or {}
    mb        = intel.get("malwarebazaar") or {}

    all_indicators = (
        result.get("risk_indicators", []) +
        intel.get("risk_indicators", [])
    )

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            INSERT OR REPLACE INTO enrichment_results (
                entry_type, entry_id, exe_path,
                md5, sha1, sha256,
                file_exists, file_size,
                pe_is_pe, pe_compile_time, pe_compile_suspicious,
                pe_signed, pe_valid_sig, pe_publisher, pe_entropy_high,
                vt_found, vt_malicious, vt_total, vt_verdict, vt_link,
                mb_found, mb_malware, mb_signature, mb_link,
                risk_indicators, overall_verdict, enriched_at
            ) VALUES (
                ?,?,?,  ?,?,?,  ?,?,  ?,?,?,  ?,?,?,?,
                ?,?,?,?,?,  ?,?,?,?,  ?,?,?
            )
        """, (
            entry_type, entry_id, result.get("exe_path"),
            hashes.get("md5"), hashes.get("sha1"), hashes.get("sha256"),
            1 if file_info.get("exists") else 0,
            file_info.get("size_bytes"),
            1 if pe.get("is_pe") else 0,
            pe.get("compile_time"),
            1 if pe.get("compile_time_suspicious") else 0,
            1 if sig.get("signed") else 0,
            1 if sig.get("valid") else 0,
            sig.get("publisher"),
            1 if any(
                s.get("entropy", 0) >= 7.0 for s in pe.get("sections", [])
            ) else 0,
            1 if vt.get("found") else 0,
            vt.get("malicious", 0),
            vt.get("total", 0),
            intel.get("verdict"),
            vt.get("vt_link"),
            1 if mb.get("found") else 0,
            1 if mb.get("malware") else 0,
            mb.get("signature"),
            mb.get("mb_link"),
            json.dumps(all_indicators),
            intel.get("verdict", result.get("verdict", "unknown")),
            datetime.now(tz=timezone.utc).isoformat(),
        ))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Main enrichment manager
# ---------------------------------------------------------------------------

class EnrichmentManager:

    def __init__(self, db_path: str = "reghunt.db",
                 vt_api_key: str = None, mb_api_key: str = None):
        self.db_path  = db_path
        self.file_enricher  = FileEnricher()
        self.intel_enricher = ThreatIntelEnricher(
            vt_api_key=vt_api_key or os.environ.get("VT_API_KEY"),
            mb_api_key=mb_api_key or os.environ.get("MB_API_KEY"),
            db_path=db_path,
        )
        self.baseline = BaselineManager(db_path)
        _init_enrichment_table(db_path)

    def enrich_entry(self, entry: dict, entry_type: str,
                     run_intel: bool = True) -> dict:
        """Fully enrich a single entry."""
        # File enrichment
        result = self.file_enricher.enrich(entry, entry_type)

        # Threat intel (only if file exists and we have a hash)
        if run_intel and result.get("hashes", {}).get("sha256"):
            intel = self.intel_enricher.enrich(result["hashes"])
            result["threat_intel"] = intel
        else:
            result["threat_intel"] = None

        # Store to DB
        entry_id = entry.get("id")
        if entry_id:
            _store_enrichment(self.db_path, entry_type, entry_id, result)

        return result

    def enrich_all(self, entry_type: str = "all",
                   only_high_critical: bool = True,
                   run_intel: bool = True) -> list[dict]:
        """Enrich all (or high/critical) entries of a given type."""
        types = (["registry", "task", "service"]
                 if entry_type == "all" else [entry_type])
        results = []
        for etype in types:
            entries = _get_entries(
                self.db_path, etype, only_high_critical
            )
            print(f"[*] Enriching {len(entries)} {etype} entries...")
            for entry in entries:
                name = (entry.get("name") or
                        entry.get("task_name") or
                        entry.get("service_name") or "?")
                print(f"    [{etype}] {name[:50]}...", end=" ", flush=True)
                try:
                    result = self.enrich_entry(entry, etype, run_intel)
                    verdict = (result.get("threat_intel") or {}).get(
                        "verdict", "no_intel"
                    )
                    exists  = result.get("file_info", {}).get("exists", False)
                    signed  = result.get("signature", {}).get("signed", False)
                    print(f"{'✅' if exists else '❌'} "
                          f"{'🔏' if signed else '🔓'} "
                          f"verdict={verdict}")
                    results.append(result)
                except Exception as e:
                    print(f"ERROR: {e}")
        return results

    def get_enrichment(self, entry_type: str, entry_id: int) -> dict | None:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM enrichment_results WHERE entry_type=? AND entry_id=?",
                (entry_type, entry_id),
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            result["risk_indicators"] = json.loads(
                result.get("risk_indicators") or "[]"
            )
            return result
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _print_diff(diff: dict, show_all: bool = False):
    info = diff.get("baseline_info") or {}
    print(Colors.BOLD + "\n[*] Baseline: " + info.get("name", "?") +
          " (created " + info.get("created_at", "?")[:16] + ")" + Colors.RESET)
    print(f"    Baseline entries: {info.get('entry_count', '?')} | "
          f"Current entries: {diff.get('current_count', '?')}")

    new      = diff.get("new", [])
    removed  = diff.get("removed", [])

    print(Colors.BOLD + f"\n[+] {len(new)} NEW entries since baseline:" + Colors.RESET)
    if new:
        for e in new:
            icon = {"critical": "🔴", "high": "🟠",
                    "medium": "🟡", "low": "🟢"}.get(e.get("severity"), "⚪")
            sev_color = {"critical": Colors.RED, "high": Colors.YELLOW,
                         "medium": Colors.WHITE, "low": Colors.GREEN}.get(
                             e.get("severity"), Colors.RESET)
            print(f"  {icon} {sev_color}[{(e.get('severity') or '?').upper()}]"
                  f"{Colors.RESET} [{e.get('type','?')}] "
                  f"{(e.get('name') or '?')[:50]} "
                  f"-> {(e.get('value') or '')[:60]}")
    else:
        print("  ✅ No new persistence entries detected")

    if removed:
        print(Colors.BOLD + f"\n[-] {len(removed)} entries REMOVED since baseline:" +
              Colors.RESET)
        for e in removed:
            print(f"  🗑️  {(e.get('name') or '?')[:50]} -> {(e.get('value') or '')[:60]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Persistence-Hunter Enrichment Manager"
    )
    parser.add_argument("--db",            default="reghunt.db")
    parser.add_argument("--vt-key",        default=None,
                        help="VirusTotal API key (or set VT_API_KEY env var)")
    parser.add_argument("--mb-key",        default=None,
                        help="MalwareBazaar API key (or set MB_API_KEY env var)")
    parser.add_argument("--enrich-all",    action="store_true",
                        help="Enrich all high/critical entries")
    parser.add_argument("--enrich-type",   default="all",
                        choices=["all", "registry", "task", "service"])
    parser.add_argument("--all-severities",action="store_true",
                        help="Include medium/low entries in enrichment")
    parser.add_argument("--no-intel",      action="store_true",
                        help="Skip VT/MB lookups (file enrichment only)")
    parser.add_argument("--enrich-id",     type=int,
                        help="Enrich a single entry by ID")
    parser.add_argument("--type",          default="registry",
                        choices=["registry", "task", "service"],
                        help="Entry type for --enrich-id")
    parser.add_argument("--baseline",      action="store_true",
                        help="Create a new baseline snapshot")
    parser.add_argument("--baseline-name", default=None)
    parser.add_argument("--diff",          action="store_true",
                        help="Show new entries since last baseline")
    parser.add_argument("--diff-type",     default="all",
                        choices=["all", "registry", "task", "service"])
    parser.add_argument("--list-baselines",action="store_true")
    parser.add_argument("--no-color",      action="store_true")
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    mgr = EnrichmentManager(
        db_path=args.db,
        vt_api_key=args.vt_key,
        mb_api_key=args.mb_key,
    )

    if args.baseline:
        print("[*] Creating baseline snapshot...")
        bid = mgr.baseline.create_baseline(
            entry_type=args.diff_type,
            name=args.baseline_name,
        )
        baselines = mgr.baseline.list_baselines()
        b = next((b for b in baselines if b["id"] == bid), None)
        if b:
            print(f"[+] Baseline '{b['name']}' created with "
                  f"{b['entry_count']} entries (ID={bid})")

    if args.diff:
        diff = mgr.baseline.diff(entry_type=args.diff_type)
        if "error" in diff:
            print("[!] " + diff["error"])
        else:
            _print_diff(diff)

    if args.list_baselines:
        baselines = mgr.baseline.list_baselines()
        print(f"\n[*] {len(baselines)} baselines stored:")
        for b in baselines:
            print(f"  ID={b['id']} | {b['name']} | "
                  f"{b['entry_type']} | {b['entry_count']} entries | "
                  f"created {b['created_at'][:16]}")

    if args.enrich_all:
        mgr.enrich_all(
            entry_type=args.enrich_type,
            only_high_critical=not args.all_severities,
            run_intel=not args.no_intel,
        )

    if args.enrich_id:
        entries = _get_entries(args.db, args.type)
        entry   = next((e for e in entries if e["id"] == args.enrich_id), None)
        if not entry:
            print(f"[!] Entry ID {args.enrich_id} not found in {args.type}")
        else:
            print(f"[*] Enriching {args.type} entry {args.enrich_id}...")
            result = mgr.enrich_entry(entry, args.type,
                                      run_intel=not args.no_intel)
            print(json.dumps(result, indent=2, default=str))