"""
registry_collector.py
Collects registry persistence entries from the 4 main Run/RunOnce keys,
recursing into all subkeys so nothing is missed.
Correlates findings with Event ID 4688 process creation logs.

Requires: Windows, pywin32
Run as Administrator for HKLM access and Security event log access.
"""

import winreg
import sqlite3
import json
import hashlib
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

# pywin32 — install via: pip install pywin32
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32api
    import win32security
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False
    print("[!] pywin32 not installed. Event log correlation disabled.")
    print("    pip install pywin32")


# ── REGISTRY KEYS TO MONITOR ──────────────────────────────
# Only the 4 core Run/RunOnce keys — subkeys are recursed automatically
PERSISTENCE_KEYS = [
    {
        "hive":      winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path":      r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "key_type":  "Run"
    },
    {
        "hive":      winreg.HKEY_CURRENT_USER,
        "hive_name": "HKCU",
        "path":      r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "key_type":  "Run"
    },
    {
        "hive":      winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path":      r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "key_type":  "RunOnce"
    },
    {
        "hive":      winreg.HKEY_CURRENT_USER,
        "hive_name": "HKCU",
        "path":      r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "key_type":  "RunOnce"
    },
]


# ── KNOWN LEGITIMATE PATHS (allowlist) ────────────────────
KNOWN_LEGIT_PATHS = [
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\program files\windows",
    r"c:\program files (x86)\windows",
    r"c:\program files\microsoft",
    r"c:\program files (x86)\microsoft",
]

SUSPICIOUS_PATHS = [
    r"c:\users\public",
    r"c:\temp",
    r"c:\windows\temp",
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\appdata\local",
    r"\downloads",
    r"\desktop",
    r"c:\perflogs",
    r"c:\recycler",
]

# AppData\Local paths that are actually legitimate
LEGIT_APPDATA_LOCAL = [
    r"\appdata\local\microsoft\windowsapps",
    r"\appdata\local\microsoft\teams",
    r"\appdata\local\discord",
    r"\appdata\local\grammarly",
]

LOLBINS = [
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
    "wmic.exe", "powershell.exe", "cmd.exe", "regsvcs.exe",
    "regasm.exe", "installutil.exe",
]


class RegistryCollector:
    def __init__(self, db_path: str = "reghunt.db"):
        self.db_path = db_path
        self.conn = self._init_db()

    def _init_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS registry_entries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                hive        TEXT NOT NULL,
                reg_path    TEXT NOT NULL,
                value_data  TEXT,
                severity    TEXT DEFAULT 'unknown',
                ioc_notes   TEXT,
                first_seen  TEXT,
                last_seen   TEXT,
                hash_id     TEXT UNIQUE
            );

            CREATE TABLE IF NOT EXISTS process_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                pid             INTEGER,
                parent_pid      INTEGER,
                process_name    TEXT,
                process_path    TEXT,
                command_line    TEXT,
                user_name       TEXT,
                event_time      TEXT,
                event_id        INTEGER
            );

            CREATE TABLE IF NOT EXISTS attack_chains (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                reg_entry_id    INTEGER,
                chain_json      TEXT,
                built_at        TEXT,
                FOREIGN KEY(reg_entry_id) REFERENCES registry_entries(id)
            );

            CREATE INDEX IF NOT EXISTS idx_proc_pid  ON process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_proc_ppid ON process_events(parent_pid);
            CREATE INDEX IF NOT EXISTS idx_proc_name ON process_events(process_name);
        """)
        conn.commit()
        return conn

    # ── REGISTRY SCANNING ──────────────────────────────────
    def collect_registry(self) -> list[dict]:
        """Collect all entries from the 4 persistence keys, including all subkeys."""
        results = []
        for key_info in PERSISTENCE_KEYS:
            entries = self._read_key(key_info)
            results.extend(entries)
        return results

    def _read_key(self, key_info: dict) -> list[dict]:
        """
        Read all values at this key level, then recurse into every subkey.
        This ensures we catch anything nested under Run/RunOnce.
        """
        entries = []

        try:
            key = winreg.OpenKey(
                key_info["hive"],
                key_info["path"],
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
        except FileNotFoundError:
            return []
        except PermissionError:
            print(f"[!] Access denied: {key_info['hive_name']}\\{key_info['path']}")
            return []

        try:
            # ── Enumerate all VALUES at this level ────────
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    full_path = f"{key_info['hive_name']}\\{key_info['path']}"
                    data_str  = str(data)
                    severity, ioc = self._assess_severity(name, data_str)
                    hash_id = hashlib.md5(
                        f"{full_path}|{name}|{data_str}".encode()
                    ).hexdigest()

                    entry = {
                        "name":       name,
                        "hive":       f"{key_info['hive_name']}\\{key_info['key_type']}",
                        "reg_path":   full_path,
                        "value_data": data_str,
                        "severity":   severity,
                        "ioc_notes":  ioc,
                        "last_seen":  datetime.now().isoformat(),
                        "hash_id":    hash_id,
                    }
                    entries.append(entry)
                    self._upsert_entry(entry)
                    i += 1
                except OSError:
                    break

            # ── Recurse into all SUBKEYS ───────────────────
            j = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, j)
                    sub_info = {
                        **key_info,
                        "path": f"{key_info['path']}\\{subkey_name}",
                        # hive, hive_name, key_type all inherited from parent
                    }
                    entries.extend(self._read_key(sub_info))
                    j += 1
                except OSError:
                    break

        finally:
            winreg.CloseKey(key)

        return entries

    # ── SEVERITY ASSESSMENT ────────────────────────────────
    def _assess_severity(self, name: str, value: str) -> tuple[str, str]:
        """
        Heuristic severity assessment.
        Returns (severity, ioc_description).
        Checks run highest-risk first and return early.
        """
        value_lower = value.lower()
        notes = []

        # 1. Remote URL in value (always critical)
        if any(proto in value_lower for proto in ["http://", "https://", "ftp://"]):
            notes.append("Remote URL in registry value")
            return "critical", "; ".join(notes)

        # 2. LOLBin detection
        for lol in LOLBINS:
            if lol in value_lower:
                if lol in ("powershell.exe", "cmd.exe"):
                    suspicious_flags = [
                        " -encodedcommand ", " -enc ", " -e ", " -nop ",
                        " -w hidden", " -windowstyle hidden", "bypass",
                        "iex(", "iex (", "invoke-expression"
                    ]
                    if any(f in value_lower for f in suspicious_flags):
                        notes.append(f"LOLBin with suspicious flags: {lol}")
                        return "critical", "; ".join(notes)
                    # Benign cleanup commands (e.g. OneDrive del)
                    if lol == "cmd.exe" and " /q /c del " in value_lower:
                        return "low", "cmd.exe running benign cleanup command"
                else:
                    notes.append(f"LOLBin in Run key: {lol}")
                    return "critical", "; ".join(notes)

        # 3. Standalone encoded command flag
        if re.search(r'(?<![a-z])-enc(?:odedcommand)?\s', value_lower):
            notes.append("Base64-encoded command detected")
            return "critical", "; ".join(notes)

        # 4. Known legit system paths → low
        for legit in KNOWN_LEGIT_PATHS:
            if value_lower.startswith(legit):
                return "low", "Path in known-good location"

        # Allow %windir% / %systemroot%
        if value_lower.startswith("%windir%") or value_lower.startswith("%systemroot%"):
            return "low", "System environment variable path"

        # 5. Known legit AppData paths → medium
        for legit_appdata in LEGIT_APPDATA_LOCAL:
            if legit_appdata in value_lower:
                return "medium", f"AppData path — common app location but verify: {legit_appdata}"

        # 6. Suspicious path locations → high
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in value_lower:
                notes.append(f"Executable in suspicious path: {sus_path}")
                return "high", "; ".join(notes)

        # 7. Default: needs review
        return "medium", "Not in known-good path — manual review recommended"

    def _upsert_entry(self, entry: dict):
        """
        Insert or update a registry entry.
        On conflict (same hash_id), update severity, ioc_notes and last_seen
        so re-scans always reflect the latest assessment.
        """
        self.conn.execute("""
            INSERT INTO registry_entries
                (name, hive, reg_path, value_data, severity, ioc_notes,
                 first_seen, last_seen, hash_id)
            VALUES
                (:name, :hive, :reg_path, :value_data, :severity, :ioc_notes,
                 :last_seen, :last_seen, :hash_id)
            ON CONFLICT(hash_id) DO UPDATE SET
                severity  = excluded.severity,
                ioc_notes = excluded.ioc_notes,
                last_seen = excluded.last_seen
        """, entry)
        self.conn.commit()

    # ── EVENT LOG COLLECTION (4688) ────────────────────────
    def collect_process_events(self, hours_back: int = 24) -> int:
        """
        Pull Event ID 4688 (process creation) from the Security log.
        Requires:
          - Admin rights
          - Audit Process Creation enabled:
            auditpol /set /subcategory:"Process Creation" /success:enable
          - Command line logging enabled:
            HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
            ProcessCreationIncludeCmdLine_Enabled = 1
        """
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available — skipping event log collection")
            return 0

        count = 0
        cutoff = datetime.now() - timedelta(hours=hours_back)

        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
        except Exception as e:
            print(f"[!] Cannot open Security log: {e}")
            print("    Try running as Administrator.")
            return 0

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for event in events:
                    if event.EventID != 4688:
                        continue
                    event_dt = datetime.fromtimestamp(event.TimeGenerated.timestamp())
                    if event_dt < cutoff:
                        win32evtlog.CloseEventLog(hand)
                        return count
                    self._store_event_4688(event, event_dt)
                    count += 1
        except Exception as e:
            print(f"[!] Error reading events: {e}")
        finally:
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass

        return count

    def _store_event_4688(self, event, event_dt: datetime):
        """Parse and store a single 4688 event."""
        strings = event.StringInserts or []

        def get(i, default=""):
            return strings[i] if i < len(strings) else default

        try:
            new_pid    = int(get(4, "0"), 16) if get(4).startswith("0x") else int(get(4) or "0")
            parent_pid = int(get(7, "0"), 16) if get(7).startswith("0x") else int(get(7) or "0")
        except (ValueError, OverflowError):
            new_pid, parent_pid = 0, 0

        proc_name = os.path.basename(get(5, ""))
        proc_path = get(5, "")
        cmd_line  = get(8, "")
        user_name = f"{get(2)}\\{get(1)}" if get(1) else get(1)

        self.conn.execute("""
            INSERT OR IGNORE INTO process_events
                (pid, parent_pid, process_name, process_path,
                 command_line, user_name, event_time, event_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, 4688)
        """, (new_pid, parent_pid, proc_name, proc_path,
              cmd_line, user_name, event_dt.isoformat()))
        self.conn.commit()

    # ── ATTACK CHAIN BUILDER ───────────────────────────────
    def build_attack_chain(self, reg_entry_id: int) -> list[dict]:
        """
        For a registry entry, find the process that wrote it,
        then walk up the parent chain to build the attack chain.
        """
        entry = self.conn.execute(
            "SELECT * FROM registry_entries WHERE id = ?", (reg_entry_id,)
        ).fetchone()
        if not entry:
            return []

        value     = entry["value_data"] or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_name  = os.path.basename(exe_token.strip('"'))

        writer = self.conn.execute("""
            SELECT * FROM process_events
            WHERE process_name LIKE ?
            ORDER BY event_time DESC LIMIT 1
        """, (f"%{exe_name}%",)).fetchone()

        if not writer:
            return [{
                "pid":     0,
                "name":    exe_name or "unknown",
                "type":    "malicious",
                "user":    "unknown",
                "path":    exe_token,
                "cmdline": value,
                "action":  {
                    "type":  "reg",
                    "label": f"Wrote {entry['hive']} key: {entry['name']}"
                }
            }]

        chain = []
        current = dict(writer)
        visited_pids = set()

        while current and current["pid"] not in visited_pids:
            visited_pids.add(current["pid"])
            node_type = self._classify_node(current)
            is_writer = current["pid"] == writer["pid"]

            node = {
                "pid":     current["pid"],
                "name":    current["process_name"] or "unknown",
                "type":    node_type,
                "user":    current["user_name"] or "",
                "path":    current["process_path"] or "",
                "cmdline": current["command_line"] or "",
                "action":  None
            }
            if is_writer:
                node["action"] = {
                    "type":  "reg",
                    "label": f"Wrote {entry['hive']} key: {entry['name']} → {entry['value_data'][:60]}"
                }

            chain.append(node)

            if current["parent_pid"]:
                parent = self.conn.execute("""
                    SELECT * FROM process_events
                    WHERE pid = ?
                    ORDER BY event_time DESC LIMIT 1
                """, (current["parent_pid"],)).fetchone()
                current = dict(parent) if parent else None
            else:
                break

        chain.reverse()  # Root → leaf

        self.conn.execute("""
            INSERT OR REPLACE INTO attack_chains (reg_entry_id, chain_json, built_at)
            VALUES (?, ?, ?)
        """, (reg_entry_id, json.dumps(chain), datetime.now().isoformat()))
        self.conn.commit()

        return chain

    def _classify_node(self, proc: dict) -> str:
        path = (proc.get("process_path") or "").lower()
        name = (proc.get("process_name") or "").lower()
        cmd  = (proc.get("command_line") or "").lower()

        if proc.get("pid") in (4, 0):
            return "system"
        if name in ("system", "smss.exe", "csrss.exe", "wininit.exe",
                    "winlogon.exe", "services.exe", "lsass.exe"):
            return "system"

        severity, _ = RegistryCollector._static_assess(path, cmd)
        if severity == "critical":
            return "malicious"
        if severity == "high":
            return "suspicious"

        return "normal"

    @staticmethod
    def _static_assess(path: str, cmd: str) -> tuple[str, str]:
        """Standalone severity check used by _classify_node."""
        for sus in SUSPICIOUS_PATHS:
            if sus in path:
                return "high", f"Suspicious path: {sus}"
        for lol in LOLBINS:
            if lol in cmd:
                if any(x in cmd for x in ["-enc", "-nop", "bypass", "hidden", "http"]):
                    return "critical", f"LOLBin + suspicious flags: {lol}"
        if any(p in cmd for p in ["http://", "https://"]):
            return "critical", "Remote URL in command"
        return "low", ""

    # ── QUERIES ───────────────────────────────────────────
    def get_all_entries(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM registry_entries ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_entry(self, entry_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM registry_entries WHERE id = ?", (entry_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_chain(self, entry_id: int) -> list[dict]:
        row = self.conn.execute(
            "SELECT chain_json FROM attack_chains WHERE reg_entry_id = ?", (entry_id,)
        ).fetchone()
        if row:
            return json.loads(row["chain_json"])
        return self.build_attack_chain(entry_id)

    def get_stats(self) -> dict:
        rows = self.conn.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM registry_entries
            GROUP BY severity
        """).fetchall()
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in rows:
            stats[r["severity"]] = r["cnt"]
        stats["total"] = sum(stats.values())
        stats["process_events"] = self.conn.execute(
            "SELECT COUNT(*) FROM process_events"
        ).fetchone()[0]
        return stats

    def close(self):
        self.conn.close()


# ── CLI ENTRYPOINT ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="RegHunt — Registry Persistence Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python registry_collector.py --scan
  python registry_collector.py --events --hours 48
  python registry_collector.py --scan --events --chain 1
        """
    )
    parser.add_argument("--scan",   action="store_true", help="Scan registry persistence keys")
    parser.add_argument("--events", action="store_true", help="Collect Event ID 4688 from Security log")
    parser.add_argument("--hours",  type=int, default=24, help="Hours back to pull events (default 24)")
    parser.add_argument("--chain",  type=int, metavar="ID", help="Build attack chain for registry entry ID")
    parser.add_argument("--db",     default="reghunt.db", help="Database path (default: reghunt.db)")
    args = parser.parse_args()

    col = RegistryCollector(db_path=args.db)

    if args.scan:
        print("[*] Scanning registry persistence keys (including all subkeys)...")
        entries = col.collect_registry()
        print(f"[+] Found {len(entries)} entries")
        for e in entries:
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(e["severity"], "⚪")
            print(f"  {sev_icon} [{e['severity'].upper():8}] {e['name']:40} → {e['value_data'][:60]}")

    if args.events:
        print(f"\n[*] Collecting process creation events (last {args.hours}h)...")
        count = col.collect_process_events(hours_back=args.hours)
        print(f"[+] Stored {count} process creation events")

    if args.chain:
        print(f"\n[*] Building attack chain for entry ID {args.chain}...")
        chain = col.build_attack_chain(args.chain)
        if chain:
            print(f"[+] Chain depth: {len(chain)} nodes")
            for i, node in enumerate(chain):
                indent = "  " * i
                type_icon = {"system": "⚙️ ", "normal": "📦", "suspicious": "⚠️ ", "malicious": "💀"}.get(node["type"], "❓")
                print(f"{indent}{type_icon} {node['name']} (PID {node['pid']}) — {node['user']}")
                if node.get("action"):
                    print(f"{indent}   ↳ {node['action']['label']}")
        else:
            print("[!] No chain found. Run --scan and --events first.")

    stats = col.get_stats()
    print(f"\n[*] DB Stats: {stats['total']} entries | {stats['process_events']} process events")
    print(f"    Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}")

    col.close()