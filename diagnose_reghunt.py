"""
diagnose_reghunt.py  —  RegHunt chain attribution debugger
===========================================================
Run this AFTER running registry_collector.py --scan --events --sysmon

Usage:
    python diagnose_reghunt.py [--db reghunt.db] [--id 15]

It will:
  1. Show the raw registry entry for --id
  2. Show ALL registry_writes rows that contain the entry name
  3. Show ALL process_events rows that match the malware exe name
  4. Step through _find_writer logic verbosely
  5. Print a summary of exactly what's failing and why
"""

import sqlite3
import os
import sys
import argparse
import re

# ── helpers ──────────────────────────────────────────────────────────────────

def open_db(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        print(f"[!] Database not found: {path}")
        sys.exit(1)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def h(title: str):
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def row_dict(row) -> dict:
    return dict(row) if row else {}


# ── main diagnostic ──────────────────────────────────────────────────────────

def diagnose(db_path: str, entry_id: int):
    conn = open_db(db_path)

    # ── 1. Registry entry ────────────────────────────────────────────────────
    h(f"1. Registry entry ID={entry_id}")
    entry_row = conn.execute(
        "SELECT * FROM registry_entries WHERE id = ?", (entry_id,)
    ).fetchone()

    if not entry_row:
        print(f"[!] No entry with id={entry_id}")
        available = conn.execute(
            "SELECT id, name, severity FROM registry_entries ORDER BY id"
        ).fetchall()
        print("\nAvailable entries:")
        for r in available:
            print(f"  id={r['id']:3d}  [{r['severity']:8s}]  {r['name']}")
        return

    entry = dict(entry_row)
    for k, v in entry.items():
        print(f"  {k:20s} = {v!r}")

    entry_name = (entry.get("name") or "").lower()
    value_data = entry.get("value_data") or ""
    exe_token  = value_data.strip().split()[0] if value_data.strip() else ""
    exe_name   = os.path.basename(exe_token.strip('"'))

    print(f"\n  >> entry_name (search key) = {entry_name!r}")
    print(f"  >> exe_name   (fuzzy match) = {exe_name!r}")

    # ── 2. DB stats ──────────────────────────────────────────────────────────
    h("2. Database stats")
    n_entries = conn.execute("SELECT COUNT(*) FROM registry_entries").fetchone()[0]
    n_proc    = conn.execute("SELECT COUNT(*) FROM process_events").fetchone()[0]
    n_sysmon  = conn.execute("SELECT COUNT(*) FROM registry_writes").fetchone()[0]
    print(f"  registry_entries : {n_entries}")
    print(f"  process_events   : {n_proc}")
    print(f"  registry_writes  : {n_sysmon}")

    # ── 3. What's actually stored in registry_writes? ────────────────────────
    h("3. Sample registry_writes rows (first 5)")
    sample = conn.execute(
        "SELECT * FROM registry_writes ORDER BY event_time DESC LIMIT 5"
    ).fetchall()
    if not sample:
        print("  [!] registry_writes is EMPTY — Sysmon events never stored!")
    for r in sample:
        print(f"  key_path   = {r['key_path']!r}")
        print(f"  proc_name  = {r['process_name']!r}")
        print(f"  pid        = {r['pid']}")
        print(f"  event_time = {r['event_time']!r}")
        print()

    # ── 4. Search registry_writes for our entry_name ─────────────────────────
    h(f"4. registry_writes LIKE '%\\\\{entry_name}'  (Sysmon match)")
    sysmon_rows = conn.execute(
        "SELECT * FROM registry_writes WHERE LOWER(key_path) LIKE ?",
        (f"%\\{entry_name}",)
    ).fetchall()
    print(f"  Rows found: {len(sysmon_rows)}")
    for r in sysmon_rows:
        print(f"  key_path   = {r['key_path']!r}")
        print(f"  proc_name  = {r['process_name']!r}")
        print(f"  pid        = {r['pid']}")
        print(f"  event_time = {r['event_time']!r}")
        print()

    if not sysmon_rows:
        # Try broader search
        print("  [!] No exact match. Trying broader search for 'run' in key_path...")
        broad = conn.execute(
            "SELECT DISTINCT key_path FROM registry_writes "
            "WHERE LOWER(key_path) LIKE '%currentversion%run%' LIMIT 10"
        ).fetchall()
        if broad:
            print("  Run-related key_path values stored:")
            for r in broad:
                print(f"    {r['key_path']!r}")
        else:
            print("  [!] NO Run key writes stored at all.")
            print()
            print("  This means one of:")
            print("  A) The 'currentversion\\\\run' filter in _store_sysmon_from_xml")
            print("     is broken — events pass filter but Run key check never matched")
            print("  B) Sysmon is not configured to log Run key writes")
            print()
            print("  Let's check what key_paths ARE being stored:")
            all_keys = conn.execute(
                "SELECT DISTINCT key_path FROM registry_writes LIMIT 20"
            ).fetchall()
            for r in all_keys:
                print(f"    {r['key_path']!r}")

    # ── 5. What does the raw TargetObject look like in Sysmon events? ─────────
    h("5. Raw TargetObject format check")
    print("  Checking what format key_paths are stored in...")
    samples = conn.execute(
        "SELECT DISTINCT key_path FROM registry_writes LIMIT 3"
    ).fetchall()
    for r in samples:
        kp = r['key_path']
        print(f"  Stored: {kp!r}")
        if kp.startswith("\\REGISTRY\\"):
            print("  ⚠️  KERNEL PATH FORMAT — normalise_reg_path is NOT converting this!")
            print("      Expected: HKCU\\... or HKLM\\...")
            print("      Got:      \\REGISTRY\\MACHINE\\... or \\REGISTRY\\USER\\SID\\...")
        elif kp.startswith("HKCU") or kp.startswith("HKLM") or kp.startswith("HKU"):
            print("  ✅  Normalised format — path looks correct")
        else:
            print(f"  ❓  Unknown format: {kp[:50]!r}")

    # ── 6. Search process_events for exe_name ─────────────────────────────────
    h(f"6. process_events LIKE '%{exe_name}%' (4688 fuzzy match)")
    proc_rows = conn.execute(
        "SELECT pid, parent_pid, process_name, process_path, event_time "
        "FROM process_events WHERE process_name LIKE ? ORDER BY event_time DESC LIMIT 5",
        (f"%{exe_name}%",)
    ).fetchall()
    print(f"  Rows found: {len(proc_rows)}")
    for r in proc_rows:
        print(f"  pid={r['pid']}  ppid={r['parent_pid']}  "
              f"name={r['process_name']!r}  time={r['event_time']!r}")

    if not proc_rows:
        print(f"  [!] {exe_name!r} was never observed in 4688 events.")
        print("      The process either:")
        print("      A) Was created BEFORE the --hours window")
        print("      B) Was never launched (just installed persistence)")
        print("      C) '4688 Process Creation' audit is not enabled in Windows")
        print()
        print("  To enable: secpol.msc → Advanced Audit Policy → Detailed Tracking")
        print("           → 'Audit Process Creation' → Enable Success")
        print("  For cmdline: gpedit.msc → Computer Config → Admin Templates")
        print("             → System → Audit Process Creation")
        print("             → 'Include command line' → Enabled")

    # ── 7. Summary diagnosis ─────────────────────────────────────────────────
    h("7. DIAGNOSIS SUMMARY")

    issues = []

    if not sysmon_rows:
        # Check if it's a path format issue
        raw_check = conn.execute(
            "SELECT key_path FROM registry_writes WHERE LOWER(key_path) LIKE ? LIMIT 1",
            (f"%currentversion%run%{entry_name}%",)
        ).fetchone()
        if raw_check:
            issues.append(
                f"PATH FORMAT BUG: key_path stored as {raw_check['key_path']!r}\n"
                f"   normalise_reg_path() doesn't handle \\REGISTRY\\ kernel paths.\n"
                f"   Fix: add \\REGISTRY\\MACHINE → HKLM and \\REGISTRY\\USER\\SID → HKCU\n"
                f"   in normalise_reg_path()"
            )
            # Check if the LIKE query would match despite wrong format
            like_check = conn.execute(
                "SELECT COUNT(*) FROM registry_writes WHERE LOWER(key_path) LIKE ?",
                (f"%\\{entry_name}",)
            ).fetchone()[0]
            if like_check == 0:
                issues.append(
                    f"LIKE MISMATCH: Even with kernel paths, '%\\\\{entry_name}' "
                    f"does not match.\n"
                    f"   The value name may be cased differently or the path ends differently."
                )
        else:
            issues.append(
                f"NO SYSMON WRITE EVENT for '{entry_name}'.\n"
                f"   Either: the write happened before --hours window,\n"
                f"   OR: Sysmon is not configured to log Run key writes.\n"
                f"   Run: sysmon -c  to see current config, or check Event Viewer."
            )

    if not proc_rows:
        issues.append(
            f"NO 4688 EVENT for '{exe_name}'.\n"
            f"   Process creation auditing may not be enabled,\n"
            f"   or the process ran outside the --hours window."
        )

    if not issues:
        print("  ✅  Both Sysmon write AND 4688 event found.")
        print("      The chain should be attributed. If it's still [inferred],")
        print("      the chain builder has a bug — check build_attack_chain() logic.")
        if sysmon_rows:
            pid = sysmon_rows[0]['pid']
            print(f"\n  Expected writer PID from Sysmon: {pid}")
            proc_for_pid = conn.execute(
                "SELECT * FROM process_events WHERE pid = ? ORDER BY event_time DESC LIMIT 1",
                (pid,)
            ).fetchone()
            if proc_for_pid:
                print(f"  4688 row for that PID: {dict(proc_for_pid)}")
            else:
                print(f"  [!] No 4688 row for PID {pid} — chain will synthesise from Sysmon only")
                print(f"      This is OK; the synthesised node should NOT be [inferred].")
                print(f"      If it IS still [inferred], the _find_writer LIKE query is failing.")
    else:
        for i, issue in enumerate(issues, 1):
            print(f"  ❌  Issue {i}: {issue}")

    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RegHunt chain attribution debugger")
    parser.add_argument("--db", default="reghunt.db")
    parser.add_argument("--id", type=int, default=15)
    args = parser.parse_args()
    diagnose(args.db, args.id)
