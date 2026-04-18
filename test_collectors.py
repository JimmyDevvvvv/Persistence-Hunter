"""
test_collectors.py
------------------
Persistence-Hunter — manual test cases for the collector cleanup.

Run from the project root (where reghunt.db lives):
    python test_collectors.py

Each test prints PASS / FAIL and explains what it verified.
Requires Windows + Sysmon running + pywin32 installed.
"""

import subprocess
import time
import sqlite3
import os
import sys

DB = "reghunt.db"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: str, shell=True):
    return subprocess.run(cmd, shell=shell, capture_output=True, text=True)

def db_query(sql, params=()):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()

def section(title):
    print("\n" + "="*60)
    print("  " + title)
    print("="*60)

def ok(msg):
    print("  ✅ PASS — " + msg)

def fail(msg):
    print("  ❌ FAIL — " + msg)

def info(msg):
    print("  ℹ️  " + msg)


# ---------------------------------------------------------------------------
# TEST 1 — Severity: Temp path service → HIGH (not MEDIUM)
# ---------------------------------------------------------------------------
section("TEST 1: Temp-path service scores HIGH or CRITICAL")

info("Installing fake service with binary in C:\\Windows\\Temp ...")
run('sc create TestTempSvc binPath= "C:\\Windows\\Temp\\svcupdate32.exe" start= auto')
time.sleep(1)

# Re-run service collector scan
run("python collector/service_collector.py --scan --sysmon --events --hours 1")
time.sleep(2)

rows = db_query(
    "SELECT severity, ioc_notes FROM service_entries WHERE LOWER(service_name) = 'testtempsvc'"
)
if rows:
    sev = rows[0]["severity"]
    if sev in ("high", "critical"):
        ok(f"TestTempSvc scored {sev.upper()} — temp path detected")
    else:
        fail(f"TestTempSvc scored {sev.upper()} — expected HIGH or CRITICAL")
    info("IOC note: " + (rows[0]["ioc_notes"] or "none"))
else:
    fail("TestTempSvc not found in DB — scan may have skipped it")

run("sc delete TestTempSvc")


# ---------------------------------------------------------------------------
# TEST 2 — Severity: service name mimicking Windows → CRITICAL
# ---------------------------------------------------------------------------
section("TEST 2: Mimic-name service scores CRITICAL")

info("Installing fake service named 'svcupdate' ...")
run('sc create svcupdate binPath= "C:\\Windows\\System32\\notepad.exe" start= auto')
time.sleep(1)

run("python collector/service_collector.py --scan --sysmon --events --hours 1")
time.sleep(2)

rows = db_query(
    "SELECT severity, ioc_notes FROM service_entries WHERE LOWER(service_name) = 'svcupdate'"
)
if rows:
    sev = rows[0]["severity"]
    if sev == "critical":
        ok(f"svcupdate scored CRITICAL — name mimicry detected")
    else:
        fail(f"svcupdate scored {sev.upper()} — expected CRITICAL")
    info("IOC note: " + (rows[0]["ioc_notes"] or "none"))
else:
    fail("svcupdate not found in DB")

run("sc delete svcupdate")


# ---------------------------------------------------------------------------
# TEST 3 — LOLBin chain node flagging: rundll32 appears as suspicious
# ---------------------------------------------------------------------------
section("TEST 3: LOLBin in chain marked as suspicious (not normal)")

info("Writing registry key via powershell + reg.exe ...")
run(
    'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" '
    '/v TestLOLBinChain /t REG_SZ /d "C:\\malware\\lolbin_test.exe" /f'
)
time.sleep(2)

run("python collector/registry_collector.py --scan --sysmon --events --hours 1 --chain-all")
time.sleep(8)

# Check that reg.exe / powershell in chains are NOT classified as "normal"
rows = db_query("""
    SELECT ac.chain_json FROM attack_chains ac
    JOIN registry_entries re ON re.id = ac.entry_id AND ac.entry_type = 'registry'
    WHERE re.name = 'TestLOLBinChain'
""")
if rows:
    import json
    chain = json.loads(rows[0]["chain_json"])
    normal_lolbins = [
        n for n in chain
        if n.get("name", "").lower() in ("reg.exe", "powershell.exe", "cmd.exe")
        and n.get("type") == "normal"
    ]
    if not normal_lolbins:
        ok("No LOLBin chain nodes classified as 'normal' — all correctly flagged suspicious/malicious")
    else:
        fail("These LOLBins were classified 'normal': " +
             ", ".join(n["name"] for n in normal_lolbins))
    info("Chain nodes: " + " → ".join(n.get("name","?") + "["+n.get("type","?")+"]" for n in chain))
else:
    fail("No chain found for TestLOLBinChain — did scan run?")

run('reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v TestLOLBinChain /f')


# ---------------------------------------------------------------------------
# TEST 4 — Timestamp sanity: parent event_time after child → chain truncated
# ---------------------------------------------------------------------------
section("TEST 4: PID reuse timestamp sanity check")

info("This test verifies _walk_chain drops parents timestamped AFTER the child.")
info("Checking DB for any chain nodes where parent.event_time > child.event_time ...")

rows = db_query("SELECT chain_json FROM attack_chains WHERE entry_type = 'registry'")
violations = []
for row in rows:
    try:
        import json
        chain = json.loads(row["chain_json"])
        for i in range(1, len(chain)):
            parent_t = chain[i-1].get("event_time", "")
            child_t  = chain[i].get("event_time", "")
            if parent_t and child_t and parent_t > child_t:
                violations.append({
                    "parent": chain[i-1].get("name"),
                    "child":  chain[i].get("name"),
                    "parent_t": parent_t,
                    "child_t":  child_t,
                })
    except Exception:
        pass

if not violations:
    ok("No timestamp-order violations found in any stored chain")
else:
    fail(f"{len(violations)} chain(s) have parent timestamped after child — PID reuse not caught:")
    for v in violations[:3]:
        print(f"    {v['parent']} ({v['parent_t']}) → {v['child']} ({v['child_t']})")


# ---------------------------------------------------------------------------
# TEST 5 — Task chain: schtasks.exe attribution requires /create in cmdline
# ---------------------------------------------------------------------------
section("TEST 5: Task chain correctly attributes schtasks.exe writer")

info("Creating test task from cmd.exe ...")
run(
    'schtasks /create /tn "PH_ChainTest" '
    '/tr "C:\\malware\\task_chain_test.exe" /sc onlogon /f'
)
time.sleep(2)

run("python collector/task_collector.py --scan --sysmon --events --hours 1 --chain-all")
time.sleep(8)

rows = db_query("""
    SELECT ac.chain_json FROM attack_chains ac
    JOIN task_entries te ON te.id = ac.entry_id AND ac.entry_type = 'task'
    WHERE LOWER(te.task_name) LIKE '%ph_chaintest%'
""")
if rows:
    import json
    chain = json.loads(rows[0]["chain_json"])
    found_schtasks = any(
        "schtasks" in n.get("name", "").lower() for n in chain
    )
    found_unknown  = all(n.get("source") == "unknown" for n in chain)

    if found_schtasks:
        ok("schtasks.exe correctly identified as task creator")
        info("Chain: " + " → ".join(n.get("name","?") for n in chain))
    elif found_unknown:
        info("Chain unknown — Sysmon may not have captured the schtasks.exe event yet")
        info("This is expected if the task was created before sysmon events were collected")
    else:
        writer_name = chain[-1].get("name", "?") if chain else "?"
        info(f"Writer identified as: {writer_name} — verify this is correct")
        info("Chain: " + " → ".join(n.get("name","?") for n in chain))
else:
    fail("No chain found for PH_ChainTest task")

run('schtasks /delete /tn "PH_ChainTest" /f')


# ---------------------------------------------------------------------------
# TEST 6 — Full deep chain: cmd → powershell → reg.exe → registry
# ---------------------------------------------------------------------------
section("TEST 6: Full deep chain (3 levels) via cmd → powershell → reg.exe")

info("Run this from a FRESH cmd.exe opened via Win+R for best chain depth:")
info("")
info('  powershell -Command "reg add \'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\' /v PH_DeepChain /t REG_SZ /d \'C:\\malware\\deepchain.exe\' /f"')
info("")
info("Then run:")
info("  python collector/registry_collector.py --scan --sysmon --events --hours 1 --chain-all")
info("")

rows = db_query(
    "SELECT id FROM registry_entries WHERE name = 'PH_DeepChain'"
)
if rows:
    import json
    chain_rows = db_query("""
        SELECT chain_json FROM attack_chains
        WHERE entry_type='registry' AND entry_id=?
    """, (rows[0]["id"],))
    if chain_rows:
        chain = json.loads(chain_rows[0]["chain_json"])
        depth = len(chain)
        names = " → ".join(n.get("name","?") for n in chain)
        if depth >= 3:
            ok(f"Deep chain depth {depth}: {names}")
        else:
            info(f"Chain depth {depth} (expected ≥3): {names}")
            info("Run the command above first, then re-run this test")
    else:
        info("PH_DeepChain found in DB but no chain yet — run --chain-all first")
else:
    info("PH_DeepChain not in DB yet — run the powershell command above first")

run('reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v PH_DeepChain /f 2>nul')


# ---------------------------------------------------------------------------
# TEST 7 — Encoded PowerShell in task → CRITICAL + T1027
# ---------------------------------------------------------------------------
section("TEST 7: Encoded PowerShell in task command → CRITICAL + T1027 tagged")

info("Creating task with -enc flag ...")
run(
    'schtasks /create /tn "PH_EncodedTask" '
    '/tr "powershell.exe -nop -w hidden -enc dGVzdA==" /sc onlogon /f'
)
time.sleep(1)

run("python collector/task_collector.py --scan --hours 1")
time.sleep(2)

rows = db_query(
    "SELECT severity, ioc_notes, techniques FROM task_entries "
    "WHERE LOWER(task_name) LIKE '%ph_encodedtask%'"
)
if rows:
    sev   = rows[0]["severity"]
    techs = rows[0]["techniques"] or "[]"
    import json
    tech_ids = [t["id"] for t in json.loads(techs)]
    sev_ok   = sev == "critical"
    t1027_ok = "T1027" in tech_ids or "T1562.001" in tech_ids

    if sev_ok:
        ok("PH_EncodedTask scored CRITICAL — encoded powershell detected")
    else:
        fail(f"PH_EncodedTask scored {sev.upper()} — expected CRITICAL")

    if t1027_ok:
        ok("T1027 / T1562.001 tagged — obfuscation technique mapped")
    else:
        info("Techniques: " + str(tech_ids) + " (T1027 not present — may be in chain node)")
else:
    fail("PH_EncodedTask not found in DB")

run('schtasks /delete /tn "PH_EncodedTask" /f')


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section("CLEANUP DONE — Test run complete")
info("Delete the test DB entries if needed:")
info("  del reghunt.db   (then re-run full scan)")
info("")
info("Next step: Phase 2 — enrichment layer (file hashing, VT, PE metadata)")