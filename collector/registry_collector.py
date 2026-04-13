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


# ── MITRE ATT&CK LOOKUP TABLES ────────────────────────────

# Registry key path → technique(s)
# Each tuple: (lowercase_path_fragment, technique_id, technique_name)
MITRE_REG_TECHNIQUES: list[tuple[str, str, str]] = [
    (r"currentversion\run",    "T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
    (r"currentversion\runonce","T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
]

# Process name → technique(s)
MITRE_PROC_TECHNIQUES: list[tuple[str, str, str]] = [
    ("powershell.exe",  "T1059.001", "Command & Scripting: PowerShell"),
    ("cmd.exe",         "T1059.003", "Command & Scripting: Windows Command Shell"),
    ("wscript.exe",     "T1059.005", "Command & Scripting: Visual Basic"),
    ("cscript.exe",     "T1059.005", "Command & Scripting: Visual Basic"),
    ("mshta.exe",       "T1218.005", "System Binary Proxy: Mshta"),
    ("regsvr32.exe",    "T1218.010", "System Binary Proxy: Regsvr32"),
    ("rundll32.exe",    "T1218.011", "System Binary Proxy: Rundll32"),
    ("certutil.exe",    "T1140",     "Deobfuscate/Decode Files or Information"),
    ("bitsadmin.exe",   "T1197",     "BITS Jobs"),
    ("msiexec.exe",     "T1218.007", "System Binary Proxy: Msiexec"),
    ("wmic.exe",        "T1047",     "Windows Management Instrumentation"),
    ("regsvcs.exe",     "T1218.009", "System Binary Proxy: Regsvcs/Regasm"),
    ("regasm.exe",      "T1218.009", "System Binary Proxy: Regsvcs/Regasm"),
    ("installutil.exe", "T1218.004", "System Binary Proxy: InstallUtil"),
]

# Cmdline pattern → additional technique (stacks on top of proc techniques)
MITRE_CMD_TECHNIQUES: list[tuple[str, str, str]] = [
    ("-enc",              "T1027",     "Obfuscated Files or Information"),
    ("-encodedcommand",   "T1027",     "Obfuscated Files or Information"),
    ("invoke-expression", "T1059.001", "Command & Scripting: PowerShell"),
    ("iex(",              "T1059.001", "Command & Scripting: PowerShell"),
    ("bypass",            "T1562.001", "Disable or Modify Tools"),
    ("-nop",              "T1562.001", "Disable or Modify Tools"),
    ("http://",           "T1105",     "Ingress Tool Transfer"),
    ("https://",          "T1105",     "Ingress Tool Transfer"),
    ("-decode",           "T1140",     "Deobfuscate/Decode Files or Information"),
    ("/transfer",         "T1197",     "BITS Jobs"),
]


def tag_registry(hive: str, reg_path: str) -> list[dict]:
    """Return MITRE techniques that match a registry key path."""
    combined = f"{hive}\\{reg_path}".lower()
    seen, tags = set(), []
    for fragment, tid, tname in MITRE_REG_TECHNIQUES:
        if fragment in combined and tid not in seen:
            seen.add(tid)
            tags.append({"id": tid, "name": tname})
    return tags


def tag_process(proc_name: str, cmdline: str) -> list[dict]:
    """Return MITRE techniques that match a process name + command line."""
    name_l, cmd_l = proc_name.lower(), cmdline.lower()
    seen, tags = set(), []
    for fragment, tid, tname in MITRE_PROC_TECHNIQUES:
        if fragment in name_l and tid not in seen:
            seen.add(tid)
            tags.append({"id": tid, "name": tname})
    for fragment, tid, tname in MITRE_CMD_TECHNIQUES:
        if fragment in cmd_l and tid not in seen:
            seen.add(tid)
            tags.append({"id": tid, "name": tname})
    return tags


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
                techniques  TEXT DEFAULT '[]',
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

            -- Sysmon Event ID 13: registry value set.
            -- Confirmed writer attribution: exactly which PID wrote which key at what time.
            CREATE TABLE IF NOT EXISTS registry_writes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                pid             INTEGER,
                process_name    TEXT,
                process_path    TEXT,
                key_path        TEXT,
                value_data      TEXT,
                user_name       TEXT,
                event_time      TEXT
            );

            CREATE TABLE IF NOT EXISTS attack_chains (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                reg_entry_id    INTEGER,
                chain_json      TEXT,
                built_at        TEXT,
                FOREIGN KEY(reg_entry_id) REFERENCES registry_entries(id)
            );

            CREATE INDEX IF NOT EXISTS idx_proc_pid    ON process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_proc_ppid   ON process_events(parent_pid);
            CREATE INDEX IF NOT EXISTS idx_proc_name   ON process_events(process_name);
            CREATE INDEX IF NOT EXISTS idx_proc_time   ON process_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_regw_key    ON registry_writes(key_path);
            CREATE INDEX IF NOT EXISTS idx_regw_time   ON registry_writes(event_time);
            CREATE INDEX IF NOT EXISTS idx_regw_pid    ON registry_writes(pid);
        """)
        conn.commit()

        # ── Migrations for existing DBs ────────────────────────
        reg_cols = {r[1] for r in conn.execute("PRAGMA table_info(registry_entries)")}
        if "techniques" not in reg_cols:
            conn.execute("ALTER TABLE registry_entries ADD COLUMN techniques TEXT DEFAULT '[]'")
            conn.commit()
        # Add registry_writes if this DB predates Sysmon support
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "registry_writes" not in tables:
            conn.executescript("""
                CREATE TABLE registry_writes (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid             INTEGER,
                    process_name    TEXT,
                    process_path    TEXT,
                    key_path        TEXT,
                    value_data      TEXT,
                    user_name       TEXT,
                    event_time      TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_regw_key  ON registry_writes(key_path);
                CREATE INDEX IF NOT EXISTS idx_regw_time ON registry_writes(event_time);
                CREATE INDEX IF NOT EXISTS idx_regw_pid  ON registry_writes(pid);
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
                        "techniques": json.dumps(tag_registry(
                            f"{key_info['hive_name']}\\{key_info['key_type']}",
                            full_path
                        )),
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
        On conflict (same hash_id), update severity, ioc_notes, techniques
        and last_seen so re-scans always reflect the latest assessment.
        """
        self.conn.execute("""
            INSERT INTO registry_entries
                (name, hive, reg_path, value_data, severity, ioc_notes,
                 techniques, first_seen, last_seen, hash_id)
            VALUES
                (:name, :hive, :reg_path, :value_data, :severity, :ioc_notes,
                 :techniques, :last_seen, :last_seen, :hash_id)
            ON CONFLICT(hash_id) DO UPDATE SET
                severity   = excluded.severity,
                ioc_notes  = excluded.ioc_notes,
                techniques = excluded.techniques,
                last_seen  = excluded.last_seen
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

    # ── SYSMON EVENT ID 13 COLLECTION ────────────────────────
    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def collect_registry_writes(self, hours_back: int = 24) -> int:
        """
        Pull Sysmon Event ID 13 (RegistryEvent — Value Set) from the
        Sysmon operational log. Each event tells us exactly which process
        wrote which registry key at what time — confirmed writer attribution.

        Requires:
          - Sysmon installed:  https://learn.microsoft.com/sysinternals/downloads/sysmon
          - Sysmon config with RegistryEvent ID 13 enabled for Run/RunOnce keys.
          - Admin rights.

        Minimal sysmon config to enable this:
          <Sysmon schemaversion="4.30">
            <EventFiltering>
              <RuleGroup name="" groupRelation="or">
                <RegistryEvent onmatch="include">
                  <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
                </RegistryEvent>
              </RuleGroup>
            </EventFiltering>
          </Sysmon>
        """
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available — skipping Sysmon collection")
            return 0

        count  = 0
        cutoff = datetime.now() - timedelta(hours=hours_back)

        try:
            hand = win32evtlog.OpenEventLog(None, self.SYSMON_CHANNEL)
        except Exception as e:
            print(f"[!] Cannot open Sysmon log: {e}")
            print("    Is Sysmon installed and running?")
            print("    sc query sysmon64")
            return 0

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for event in events:
                    if event.EventID != 13:
                        continue
                    event_dt = datetime.fromtimestamp(event.TimeGenerated.timestamp())
                    if event_dt < cutoff:
                        win32evtlog.CloseEventLog(hand)
                        return count
                    self._store_sysmon_13(event, event_dt)
                    count += 1
        except Exception as e:
            print(f"[!] Error reading Sysmon events: {e}")
        finally:
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass

        return count

    def _store_sysmon_13(self, event, event_dt: datetime):
        """
        Parse and store a Sysmon Event ID 13 (RegistryEvent Value Set).

        Sysmon 13 StringInserts layout:
          [0]  RuleName
          [1]  EventType     (SetValue)
          [2]  UtcTime
          [3]  ProcessGuid
          [4]  ProcessId
          [5]  Image         (full path of writing process)
          [6]  TargetObject  (full registry key path)
          [7]  Details       (value written)
          [8]  User
        """
        strings = event.StringInserts or []

        def get(i, default=""):
            return strings[i] if i < len(strings) else default

        # Only store SetValue events (not DeleteValue etc.)
        if get(1, "").lower() != "setvalue":
            return

        try:
            pid = int(get(4, "0"))
        except ValueError:
            pid = 0

        proc_path  = get(5, "")
        proc_name  = os.path.basename(proc_path)
        key_path   = get(6, "")
        value_data = get(7, "")
        user_name  = get(8, "")

        # Only store keys we care about (Run/RunOnce paths)
        key_lower = key_path.lower()
        if "currentversion\run" not in key_lower:
            return

        self.conn.execute("""
            INSERT OR IGNORE INTO registry_writes
                (pid, process_name, process_path, key_path,
                 value_data, user_name, event_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (pid, proc_name, proc_path, key_path,
              value_data, user_name, event_dt.isoformat()))
        self.conn.commit()

    # ── WRITER LOOKUP ──────────────────────────────────────────
    def _find_writer(self, entry: dict) -> dict | None:
        """
        Find the process that wrote this registry entry.

        Priority:
          1. Sysmon registry_writes — confirmed, exact PID match.
             Match on key_path containing the entry name, time-anchored.
          2. 4688 process_events by exe name — inferred, time-anchored.
             Falls back to this when Sysmon data isn't available.

        Returns a process_events-style dict so the chain builder
        doesn't need to care which source was used. Includes a
        'writer_source' field so the frontend can show a badge.
        """
        reg_path   = (entry.get("reg_path") or "").lower()
        entry_name = (entry.get("name") or "").lower()
        last_seen  = entry["last_seen"]

        # ── 1. Sysmon confirmed match ──────────────────────────
        # Look for a registry_writes row whose key_path ends with
        # our entry name (e.g. "...\Run\TestMalware")
        sysmon_row = self.conn.execute("""
            SELECT * FROM registry_writes
            WHERE  LOWER(key_path) LIKE ?
              AND  event_time      <= ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (f"%\{entry_name}", last_seen)).fetchone()

        if sysmon_row:
            sysmon = dict(sysmon_row)
            # Now look up this PID in process_events to get parent_pid + cmdline
            proc = self.conn.execute("""
                SELECT * FROM process_events
                WHERE  pid        = ?
                  AND  event_time <= ?
                ORDER BY event_time DESC
                LIMIT 1
            """, (sysmon["pid"], last_seen)).fetchone()

            if proc:
                result = dict(proc)
                result["writer_source"] = "sysmon"
                return result

            # Sysmon gave us PID but no 4688 event for it —
            # synthesise a minimal process dict from the Sysmon data
            return {
                "pid":           sysmon["pid"],
                "parent_pid":    None,
                "process_name":  sysmon["process_name"],
                "process_path":  sysmon["process_path"],
                "command_line":  "",
                "user_name":     sysmon["user_name"],
                "event_time":    sysmon["event_time"],
                "writer_source": "sysmon",
            }

        # ── 2. 4688 inferred match ─────────────────────────────
        value     = entry.get("value_data") or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_name  = os.path.basename(exe_token.strip('"'))

        proc = self._find_process(exe_name, last_seen)
        if proc:
            proc["writer_source"] = "4688"
        return proc

    # ── ATTACK CHAIN BUILDER ───────────────────────────────

    # System processes we stop walking at — no point going higher
    SYSTEM_PROCS = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe"
    }
    SYSTEM_PIDS  = {0, 4}
    MAX_DEPTH    = 10  # safety cap — no chain should ever be deeper than this

    def _find_process(self, name: str, before: str) -> dict | None:
        """
        Find the most recent process matching name that started AT OR BEFORE
        the given ISO timestamp. This is the writer candidate.
        
        'before' is the registry entry's last_seen — the key existed by this time,
        so the process that set it must have run at or before this moment.
        """
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE process_name LIKE ?
              AND event_time   <= ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (f"%{name}%", before)).fetchone()
        return dict(row) if row else None

    def _find_parent(self, parent_pid: int, before: str) -> dict | None:
        """
        Find the most recent event for parent_pid that started BEFORE
        the child's event_time. A parent must predate its child.
        """
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE pid        = ?
              AND event_time < ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (parent_pid, before)).fetchone()
        return dict(row) if row else None

    def build_attack_chain(self, reg_entry_id: int) -> list[dict]:
        """
        Build the process ancestry chain for a registry persistence entry.

        Strategy:
          1. Extract the exe name from the registry value_data.
          2. Find the most recent matching process that ran AT OR BEFORE
             the registry entry was last seen (time-anchored, not just name match).
          3. Walk up parent_pid → grandparent etc., each time constraining
             the parent lookup to events that predate the child.
          4. Stop at system processes, PID 0/4, depth cap, or no more parents.
          5. Reverse so chain reads root → writer (left to right / top to bottom).
        """
        entry = self.conn.execute(
            "SELECT * FROM registry_entries WHERE id = ?", (reg_entry_id,)
        ).fetchone()
        if not entry:
            return []

        entry = dict(entry)

        # ── 1. Extract exe name from value_data ───────────────
        value     = entry["value_data"] or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_name  = os.path.basename(exe_token.strip('"'))

        # ── 2. Find writer — Sysmon first, 4688 fallback ────────
        # _find_writer checks registry_writes (Sysmon ID 13) first for
        # confirmed attribution, then falls back to name-based 4688 match.
        writer = self._find_writer(entry)

        # No match in either source — return a placeholder so the
        # frontend still shows something meaningful
        if not writer:
            placeholder = [{
                "pid":        0,
                "name":       exe_name or "unknown",
                "type":       "malicious",
                "user":       "unknown",
                "path":       exe_token,
                "cmdline":    value,
                "event_time": entry["last_seen"],
                "depth":      0,
                "source":     "inferred",
                "action": {
                    "type":  "reg",
                    "label": f"Wrote {entry['hive']} → {entry['name']}"
                }
            }]
            self._save_chain(reg_entry_id, placeholder)
            return placeholder

        # ── 3. Walk up the parent chain ───────────────────────
        chain        = []
        current      = writer
        visited_pids = set()
        depth        = 0

        while current and depth < self.MAX_DEPTH:
            pid  = current["pid"]
            name = (current["process_name"] or "").lower()

            # Stop if we've looped or hit a known system root
            if pid in visited_pids:
                break
            if pid in self.SYSTEM_PIDS or name in self.SYSTEM_PROCS:
                # Still add the system node so the chain shows the full root
                chain.append(self._make_node(current, depth, is_writer=False))
                break

            visited_pids.add(pid)
            is_writer = (pid == writer["pid"])
            chain.append(self._make_node(
                current, depth, is_writer=is_writer,
                entry=entry if is_writer else None
            ))

            # ── 4. Find parent, constrained to before child ───
            parent_pid = current.get("parent_pid")
            if not parent_pid:
                break

            parent = self._find_parent(parent_pid, current["event_time"])
            if not parent:
                break

            current = parent
            depth  += 1

        # ── 5. Reverse: root → writer ─────────────────────────
        chain.reverse()

        # Re-stamp depth after reversal so depth=0 is always the root
        for i, node in enumerate(chain):
            node["depth"] = i

        self._save_chain(reg_entry_id, chain)
        return chain

    def _make_node(
        self,
        proc:      dict,
        depth:     int,
        is_writer: bool,
        entry:     dict | None = None
    ) -> dict:
        """Build a single chain node dict from a process_events row."""
        proc_name = proc["process_name"] or "unknown"
        cmdline   = proc["command_line"] or ""

        node = {
            "pid":        proc["pid"],
            "name":       proc_name,
            "type":       self._classify_node(proc),
            "user":       proc["user_name"] or "",
            "path":       proc["process_path"] or "",
            "cmdline":    cmdline,
            "event_time": proc["event_time"] or "",
            "depth":      depth,
            # writer_source set by _find_writer: "sysmon" | "4688" | absent for ancestors
            "source":     proc.get("writer_source", "4688"),
            "techniques": tag_process(proc_name, cmdline),
            "action":     None,
        }
        if is_writer and entry:
            node["action"] = {
                "type":  "reg",
                "label": f"Wrote {entry['hive']} → {entry['name']} = {entry['value_data'][:60]}"
            }
        return node

    def _save_chain(self, reg_entry_id: int, chain: list[dict]):
        """Persist chain JSON to attack_chains table."""
        self.conn.execute("""
            INSERT OR REPLACE INTO attack_chains (reg_entry_id, chain_json, built_at)
            VALUES (?, ?, ?)
        """, (reg_entry_id, json.dumps(chain), datetime.now().isoformat()))
        self.conn.commit()

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
        entries = []
        for r in rows:
            e = dict(r)
            e["techniques"] = json.loads(e.get("techniques") or "[]")
            entries.append(e)
        return entries

    def get_entry(self, entry_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM registry_entries WHERE id = ?", (entry_id,)
        ).fetchone()
        if not row:
            return None
        e = dict(row)
        e["techniques"] = json.loads(e.get("techniques") or "[]")
        return e

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
    parser.add_argument("--sysmon", action="store_true", help="Collect Sysmon Event ID 13 (registry writes)")
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

    if args.sysmon:
        print(f"\n[*] Collecting Sysmon registry write events (last {args.hours}h)...")
        count = col.collect_registry_writes(hours_back=args.hours)
        print(f"[+] Stored {count} Sysmon registry write events")

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