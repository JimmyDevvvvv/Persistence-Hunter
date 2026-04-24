"""
scan_summary.py
Cross-collector scan summary — runs all three collectors in diff mode
and prints a single consolidated actionable report.

Usage:
    python scan_summary.py [--hours 24] [--json] [--chains] [--db reghunt.db]
"""

import os
import sys
import json
import sqlite3
import argparse
import subprocess
from datetime import datetime

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    ORANGE = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def crit(s):  return f"{C.RED}{C.BOLD}{s}{C.RESET}"
def warn(s):  return f"{C.ORANGE}{s}{C.RESET}"
def ok(s):    return f"{C.GREEN}{s}{C.RESET}"
def info(s):  return f"{C.CYAN}{s}{C.RESET}"
def gray(s):  return f"{C.GRAY}{s}{C.RESET}"
def bold(s):  return f"{C.BOLD}{s}{C.RESET}"


def sev_icon(sev):
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "⚪")

def sev_color(sev, text):
    colors = {"critical": C.RED + C.BOLD, "high": C.ORANGE,
              "medium": C.CYAN, "low": C.GRAY}
    return colors.get(sev, "") + text + C.RESET


def query_new_entries(conn, entry_type, table, id_col, name_col, value_col):
    """Get entries not in the active baseline."""
    bl_row = conn.execute(
        "SELECT id FROM baselines ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not bl_row:
        # No baseline — return all high/critical
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE severity IN ('critical','high') "
            f"ORDER BY severity DESC, {name_col}"
        ).fetchall()
        return [dict(r) for r in rows], None

    bl_id = bl_row[0]
    bl_date = conn.execute(
        "SELECT created_at FROM baselines WHERE id=?", (bl_id,)
    ).fetchone()[0]

    rows = conn.execute(
        f"SELECT t.* FROM {table} t "
        f"WHERE NOT EXISTS ("
        f"  SELECT 1 FROM baseline_entries be "
        f"  WHERE be.baseline_id = ? AND be.entry_type = ? AND be.hash_id = t.hash_id"
        f") AND t.severity IN ('critical','high') "
        f"ORDER BY t.severity DESC, t.{name_col}",
        (bl_id, entry_type)
    ).fetchall()
    return [dict(r) for r in rows], bl_date[:19]


def get_chain(conn, entry_type, entry_id):
    """Fetch stored chain JSON."""
    row = conn.execute(
        "SELECT chain_json FROM attack_chains WHERE entry_type=? AND entry_id=?",
        (entry_type, entry_id)
    ).fetchone()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            return []
    return []


def format_chain_summary(chain):
    """One-line chain summary: proc1 → proc2 → proc3"""
    if not chain:
        return gray("  (no chain)")
    parts = []
    for node in chain:
        name = node.get("name") or node.get("process_name") or "?"
        src  = node.get("source", "")
        tag  = f"[{src}]" if src and src not in ("stub", "live") else ""
        parts.append(name + (f" {gray(tag)}" if tag else ""))
    return " → ".join(parts)


def decode_ps_inline(cmdline):
    """Try to decode PS -enc payload."""
    try:
        from ps_decode import decode_ps_command, format_decoded
        decoded = decode_ps_command(cmdline or "")
        if decoded:
            return format_decoded(decoded, max_len=120)
    except ImportError:
        pass
    return None


def print_section(title, entries, conn, entry_type, name_col, value_col,
                  show_chains=False, new_only=True):
    """Print one persistence category section."""
    label = "NEW " if new_only else ""
    print(f"\n{bold('─' * 70)}")
    print(bold(f"  {title}  [{len(entries)} {label}entries]"))
    print(bold('─' * 70))

    if not entries:
        print(f"  {ok('✅ Clean — nothing new since baseline.')}")
        return

    for e in entries:
        sev  = e.get("severity", "medium")
        name = e.get(name_col, "?")
        val  = e.get(value_col, "")
        icon = sev_icon(sev)

        print(f"\n  {icon} {sev_color(sev, '[' + sev.upper() + ']')} {bold(name)}")
        if val:
            print(f"     → {val[:90]}")

        ioc = e.get("ioc_notes", "")
        if ioc and ioc.lower() not in ("none", "manual review recommended", ""):
            print(f"     {warn('⚠ ' + ioc)}")

        # Inline PS decode
        ps_decoded = decode_ps_inline(val)
        if ps_decoded:
            print(f"     {info('🔓 Decoded: ' + ps_decoded)}")

        if show_chains:
            chain = get_chain(conn, entry_type, e["id"])
            if chain:
                print(f"     Chain: {format_chain_summary(chain)}")

        # MITRE tags
        techs = e.get("techniques") or "[]"
        if isinstance(techs, str):
            try:
                techs = json.loads(techs)
            except Exception:
                techs = []
        if techs:
            # Handle both plain strings and MITRE dicts like {"id": "T1059", "name": "..."}
            tags = []
            for t in techs:
                if isinstance(t, dict):
                    tid = t.get("id") or t.get("technique_id") or ""
                    tags.append(tid if tid else str(t))
                else:
                    tags.append(str(t))
            if tags:
                print(f"     {gray('📌 ' + ' | '.join(tags))}")


def main():
    parser = argparse.ArgumentParser(
        description="Persistence Hunter — Cross-collector scan summary"
    )
    parser.add_argument("--hours", type=int, default=24,
                        help="Hours window for event correlation")
    parser.add_argument("--json",   action="store_true",
                        help="Also write summary to scan_summary.json")
    parser.add_argument("--chains", action="store_true",
                        help="Show attack chain summary per entry")
    parser.add_argument("--all",    action="store_true",
                        help="Show all High/Critical (not just new since baseline)")
    parser.add_argument("--db",     default="reghunt.db",
                        help="Database path")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(crit(f"[!] Database not found: {args.db}"))
        print("[!] Run a scan first with --scan on each collector.")
        sys.exit(1)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    # Check baseline
    bl_row = conn.execute("SELECT * FROM baselines ORDER BY id DESC LIMIT 1").fetchone()
    bl_date = dict(bl_row)["created_at"][:19] if bl_row else None
    new_only = not args.all

    print()
    print(bold("=" * 70))
    print(bold("  🔍 PERSISTENCE HUNTER — SCAN SUMMARY"))
    print(bold(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    if bl_date:
        print(bold(f"  Baseline: {bl_date}  |  Showing: {'NEW entries only' if new_only else 'All High/Critical'}"))
    else:
        print(warn("  ⚠ No baseline set — showing all High/Critical entries"))
        print(warn("  Tip: run each collector with --baseline to snapshot clean state"))
    print(bold("=" * 70))

    summary_data = {
        "generated_at": datetime.now().isoformat(),
        "baseline_date": bl_date,
        "registry": [],
        "tasks": [],
        "services": [],
    }

    # ── REGISTRY ──────────────────────────────────────────────────────
    try:
        if new_only:
            reg_entries, _ = query_new_entries(
                conn, "registry", "registry_entries", "id", "name", "value_data"
            )
        else:
            rows = conn.execute(
                "SELECT * FROM registry_entries WHERE severity IN ('critical','high') "
                "ORDER BY severity DESC, name"
            ).fetchall()
            reg_entries = [dict(r) for r in rows]
    except Exception as e:
        reg_entries = []
        print(warn(f"  [!] Registry query failed: {e}"))

    print_section("REGISTRY RUN KEYS", reg_entries, conn, "registry",
                  "name", "value_data",
                  show_chains=args.chains, new_only=new_only)
    summary_data["registry"] = reg_entries

    # ── TASKS ─────────────────────────────────────────────────────────
    try:
        if new_only:
            task_entries, _ = query_new_entries(
                conn, "task", "task_entries", "id", "task_name", "command"
            )
        else:
            rows = conn.execute(
                "SELECT * FROM task_entries WHERE severity IN ('critical','high') "
                "ORDER BY severity DESC, task_name"
            ).fetchall()
            task_entries = [dict(r) for r in rows]
    except Exception as e:
        task_entries = []
        print(warn(f"  [!] Task query failed: {e}"))

    # Rename column for display
    for e in task_entries:
        if "task_name" in e and "name" not in e:
            e["name"] = e["task_name"]
        if "command" in e and "value_data" not in e:
            e["value_data"] = e["command"]

    print_section("SCHEDULED TASKS", task_entries, conn, "task",
                  "task_name", "command",
                  show_chains=args.chains, new_only=new_only)
    summary_data["tasks"] = task_entries

    # ── SERVICES ──────────────────────────────────────────────────────
    try:
        if new_only:
            svc_entries, _ = query_new_entries(
                conn, "service", "service_entries", "id", "service_name", "binary_path"
            )
        else:
            rows = conn.execute(
                "SELECT * FROM service_entries WHERE severity IN ('critical','high') "
                "ORDER BY severity DESC, service_name"
            ).fetchall()
            svc_entries = [dict(r) for r in rows]
    except Exception as e:
        svc_entries = []
        print(warn(f"  [!] Service query failed: {e}"))

    for e in svc_entries:
        if "service_name" in e and "name" not in e:
            e["name"] = e["service_name"]
        if "binary_path" in e and "value_data" not in e:
            e["value_data"] = e["binary_path"]

    print_section("SERVICES", svc_entries, conn, "service",
                  "service_name", "binary_path",
                  show_chains=args.chains, new_only=new_only)
    summary_data["services"] = svc_entries

    # ── OVERALL SUMMARY ───────────────────────────────────────────────
    total = len(reg_entries) + len(task_entries) + len(svc_entries)
    critical = sum(
        1 for e in reg_entries + task_entries + svc_entries
        if e.get("severity") == "critical"
    )
    high = sum(
        1 for e in reg_entries + task_entries + svc_entries
        if e.get("severity") == "high"
    )

    print(f"\n{bold('=' * 70)}")
    print(bold("  OVERALL"))
    print(bold('=' * 70))
    if total == 0:
        print(f"\n  {ok('✅ System clean — no new High/Critical persistence since baseline.')}\n")
    else:
        print(f"\n  {crit('⚠  ' + str(total) + ' actionable entries found')}")
        if critical:
            print(f"     {crit(str(critical) + ' CRITICAL')}")
        if high:
            print(f"     {warn(str(high) + ' HIGH')}")
        print()
        print(f"  Registry : {len(reg_entries)} entries")
        print(f"  Tasks    : {len(task_entries)} entries")
        print(f"  Services : {len(svc_entries)} entries")

        print(f"\n  {bold('Next steps:')}")
        print(f"  1. Run --chain-all on flagged collectors to see full attack chains")
        print(f"  2. Run check_signatures.py --unsigned-only for binary verification")
        if any(
            "-enc" in (e.get("value_data","") or e.get("command","")).lower()
            for e in task_entries + reg_entries
        ):
            print(f"  3. Run with --chains flag to see decoded PowerShell payloads")
        print()

    # ── JSON export ───────────────────────────────────────────────────
    if args.json:
        out = "scan_summary.json"
        summary_data["total_findings"] = total
        summary_data["critical"] = critical
        summary_data["high"] = high
        with open(out, "w") as f:
            json.dump(summary_data, f, indent=2, default=str)
        print(f"  {ok('[+] Summary written to ' + out)}\n")

    conn.close()


if __name__ == "__main__":
    main()