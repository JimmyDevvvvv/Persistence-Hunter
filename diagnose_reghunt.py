"""
diagnose_reghunt.py  —  RegHunt chain attribution debugger
Run AFTER: python collector/registry_collector.py --scan --events --sysmon
Usage:     python diagnose_reghunt.py [--db reghunt.db] [--id 15]
"""
import sqlite3, os, sys, argparse

def open_db(path):
    if not os.path.exists(path):
        print(f"[!] Database not found: {path}"); sys.exit(1)
    conn = sqlite3.connect(path); conn.row_factory = sqlite3.Row; return conn

def h(t): print(); print("=" * 70); print(f"  {t}"); print("=" * 70)

SYSTEM_PROCS = {"sihost.exe","explorer.exe","svchost.exe","taskhostw.exe",
                "runtimebroker.exe","ctfmon.exe","userinit.exe","winlogon.exe","services.exe"}

def diagnose(db_path, entry_id):
    conn = open_db(db_path)

    h(f"1. Registry entry ID={entry_id}")
    row = conn.execute("SELECT * FROM registry_entries WHERE id=?", (entry_id,)).fetchone()
    if not row:
        print(f"[!] No entry with id={entry_id}\n\nAvailable entries:")
        for r in conn.execute("SELECT id,name,severity FROM registry_entries ORDER BY id"):
            print(f"  id={r['id']:3d}  [{r['severity']:8s}]  {r['name']}")
        return

    entry = dict(row)
    for k, v in entry.items(): print(f"  {k:20s} = {v!r}")

    entry_name = (entry.get("name") or "").lower()
    reg_path   = (entry.get("reg_path") or "").lower()
    value_data = entry.get("value_data") or ""
    exe_token  = value_data.strip().split()[0] if value_data.strip() else ""
    exe_path   = exe_token.strip('"')
    exe_name   = os.path.basename(exe_path)
    print(f"\n  >> entry_name = {entry_name!r}")
    print(f"  >> reg_path   = {reg_path!r}")
    print(f"  >> exe_path   = {exe_path!r}")
    print(f"  >> exe_name   = {exe_name!r}")

    h("2. Database stats")
    for tbl in ("registry_entries","process_events","registry_writes"):
        n = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        print(f"  {tbl:25s}: {n}")

    h("3. Sample registry_writes (most recent 5)")
    for r in conn.execute("SELECT * FROM registry_writes ORDER BY event_time DESC LIMIT 5"):
        print(f"  {r['process_name']:20s} pid={r['pid']:6d}  key={r['key_path']!r}")

    h(f"4. Strategy 1 — full-value LIKE '%\\\\{entry_name}'")
    s1 = conn.execute("SELECT * FROM registry_writes WHERE LOWER(key_path) LIKE ? ORDER BY event_time DESC LIMIT 5",
                      (f"%\\{entry_name}",)).fetchall()
    print(f"  Rows: {len(s1)}")
    for r in s1: print(f"  proc={r['process_name']!r}  pid={r['pid']}  key={r['key_path']!r}")

    h(f"5. Strategy 2 — parent-key exact '{reg_path}'")
    s2 = conn.execute("SELECT * FROM registry_writes WHERE LOWER(key_path)=? ORDER BY event_time DESC LIMIT 20",
                      (reg_path,)).fetchall()
    print(f"  Rows: {len(s2)}")
    non_sys = [r for r in s2 if (r["process_name"] or "").lower() not in SYSTEM_PROCS]
    print(f"  Non-system writers: {len(non_sys)}")
    for r in non_sys:
        match = " ✅ EXE MATCH" if (r["process_path"] or "").lower() == exe_path.lower() else ""
        print(f"    {r['process_name']!r}  pid={r['pid']}{match}")

    h(f"6. Strategy 3 — image-path '{exe_path}'")
    s3a = conn.execute("SELECT * FROM registry_writes WHERE LOWER(process_path)=? ORDER BY event_time DESC LIMIT 3",
                       (exe_path.lower(),)).fetchall()
    s3b = conn.execute("SELECT * FROM registry_writes WHERE LOWER(process_name)=? ORDER BY event_time DESC LIMIT 3",
                       (exe_name.lower(),)).fetchall()
    print(f"  By full path: {len(s3a)} rows")
    print(f"  By name:      {len(s3b)} rows")

    h(f"7. Strategy 4 — 4688 LIKE '%{exe_name}%'")
    s4 = conn.execute("SELECT pid,parent_pid,process_name,event_time FROM process_events "
                      "WHERE process_name LIKE ? ORDER BY event_time DESC LIMIT 5",
                      (f"%{exe_name}%",)).fetchall()
    print(f"  Rows: {len(s4)}")
    for r in s4: print(f"  pid={r['pid']}  ppid={r['parent_pid']}  name={r['process_name']!r}  time={r['event_time']!r}")

    h("8. DIAGNOSIS SUMMARY")
    if s1:
        print(f"  ✅  Strategy 1 WILL match. Writer: {s1[0]['process_name']!r} PID={s1[0]['pid']}")
    elif non_sys:
        best = next((r for r in non_sys if (r["process_path"] or "").lower() == exe_path.lower()), non_sys[0])
        print(f"  ✅  Strategy 2 WILL match. Writer: {best['process_name']!r} PID={best['pid']}")
    elif s3a or s3b:
        r = (s3a or s3b)[0]
        print(f"  ✅  Strategy 3 WILL match. Writer: {r['process_name']!r} PID={r['pid']}")
    elif s4:
        print(f"  ✅  Strategy 4 WILL match. Writer: {s4[0]['process_name']!r} PID={s4[0]['pid']}")
    else:
        print(f"  ❌  ALL strategies failed. Chain will show [inferred].")
        print(f"\n  The write for '{entry['name']}' is outside the Sysmon window.")
        print(f"  Re-trigger it then re-run with --hours 1:")
        print(f"\n  Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{entry['name']}'")
        print(f"  Set-ItemProperty   -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{entry['name']}' -Value '{value_data}'")
        print(f"\n  del reghunt.db && python collector/registry_collector.py --scan --events --sysmon --hours 1 --chain {entry_id}")
    print()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="reghunt.db")
    p.add_argument("--id", type=int, default=15)
    args = p.parse_args()
    diagnose(args.db, args.id)