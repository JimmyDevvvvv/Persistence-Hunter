"""
registry_collector.py
Collects registry persistence entries from the 4 main Run/RunOnce keys,
recursing into all subkeys so nothing is missed.
Correlates findings with Event ID 4688 process creation logs and
Sysmon Event ID 13 (registry value set) for confirmed write attribution.

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
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

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

# Debug flag
DEBUG = os.environ.get("REGHUNT_DEBUG", "").lower() in ("1", "true", "yes")


# ── REGISTRY KEYS TO MONITOR ──────────────────────────────
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

MITRE_REG_TECHNIQUES: list[tuple[str, str, str]] = [
    (r"currentversion\run",     "T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
    (r"currentversion\runonce", "T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
]

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
    combined = f"{hive}\\{reg_path}".lower()
    seen, tags = set(), []
    for fragment, tid, tname in MITRE_REG_TECHNIQUES:
        if fragment in combined and tid not in seen:
            seen.add(tid)
            tags.append({"id": tid, "name": tname})
    return tags


def tag_process(proc_name: str, cmdline: str) -> list[dict]:
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


def _normalise_reg_path(path: str) -> str:
    # Normalise Sysmon HKU/HKEY_* prefixes to short form.
    # No regex — avoids re.sub replacement-string escape issues.
    u = path.upper()
    if u.startswith("HKU\\"):
        rest  = path[4:]
        slash = rest.find("\\")
        path  = "HKCU\\" + (rest[slash + 1:] if slash != -1 else rest)
    elif u.startswith("HKEY_CURRENT_USER\\"):
        path = "HKCU\\" + path[18:]
    elif u.startswith("HKEY_LOCAL_MACHINE\\"):
        path = "HKLM\\" + path[19:]
    return path


class RegistryCollector:
    def __init__(self, db_path: str = "reghunt.db"):
        self.db_path = db_path
        self.conn    = self._init_db()

    # ── DATABASE SETUP ─────────────────────────────────────
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

            CREATE INDEX IF NOT EXISTS idx_proc_pid   ON process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_proc_ppid  ON process_events(parent_pid);
            CREATE INDEX IF NOT EXISTS idx_proc_name  ON process_events(process_name);
            CREATE INDEX IF NOT EXISTS idx_proc_time  ON process_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_regw_key   ON registry_writes(key_path);
            CREATE INDEX IF NOT EXISTS idx_regw_time  ON registry_writes(event_time);
            CREATE INDEX IF NOT EXISTS idx_regw_pid   ON registry_writes(pid);
        """)
        conn.commit()

        # Migrations for existing DBs
        reg_cols = {r[1] for r in conn.execute("PRAGMA table_info(registry_entries)")}
        if "techniques" not in reg_cols:
            conn.execute("ALTER TABLE registry_entries ADD COLUMN techniques TEXT DEFAULT '[]'")
            conn.commit()

        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "registry_writes" not in tables:
            conn.executescript("""
                CREATE TABLE registry_writes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER, process_name TEXT, process_path TEXT,
                    key_path TEXT, value_data TEXT, user_name TEXT, event_time TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_regw_key  ON registry_writes(key_path);
                CREATE INDEX IF NOT EXISTS idx_regw_time ON registry_writes(event_time);
                CREATE INDEX IF NOT EXISTS idx_regw_pid  ON registry_writes(pid);
            """)
            conn.commit()

        return conn

    # ── REGISTRY SCANNING ──────────────────────────────────
    def collect_registry(self, extended: bool = False) -> list[dict]:
        """
        Scan registry persistence keys.
        extended parameter is reserved for future use (e.g., more keys).
        """
        results = []
        for key_info in PERSISTENCE_KEYS:
            results.extend(self._read_key(key_info))
        # TODO: If extended, scan additional persistence locations (Winlogon, Services, etc.)
        return results

    def _read_key(self, key_info: dict) -> list[dict]:
        entries = []
        try:
            key = winreg.OpenKey(
                key_info["hive"], key_info["path"],
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
        except FileNotFoundError:
            return []
        except PermissionError:
            print(f"[!] Access denied: {key_info['hive_name']}\\{key_info['path']}")
            return []

        try:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    full_path = f"{key_info['hive_name']}\\{key_info['path']}"
                    data_str  = str(data)
                    severity, ioc = self._assess_severity(name, data_str)
                    hash_id = hashlib.md5(f"{full_path}|{name}|{data_str}".encode()).hexdigest()
                    entry = {
                        "name":       name,
                        "hive":       f"{key_info['hive_name']}\\{key_info['key_type']}",
                        "reg_path":   full_path,
                        "value_data": data_str,
                        "severity":   severity,
                        "ioc_notes":  ioc,
                        "techniques": json.dumps(tag_registry(
                            f"{key_info['hive_name']}\\{key_info['key_type']}", full_path
                        )),
                        "last_seen":  datetime.now().isoformat(),
                        "hash_id":    hash_id,
                    }
                    entries.append(entry)
                    self._upsert_entry(entry)
                    i += 1
                except OSError:
                    break

            j = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, j)
                    sub_info = {**key_info, "path": f"{key_info['path']}\\{subkey_name}"}
                    entries.extend(self._read_key(sub_info))
                    j += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

        return entries

    # ── SEVERITY ASSESSMENT ────────────────────────────────
    def _assess_severity(self, name: str, value: str) -> tuple[str, str]:
        value_lower = value.lower()
        notes = []

        if any(p in value_lower for p in ["http://", "https://", "ftp://"]):
            return "critical", "Remote URL in registry value"

        for lol in LOLBINS:
            if lol in value_lower:
                if lol in ("powershell.exe", "cmd.exe"):
                    sus_flags = [
                        " -encodedcommand ", " -enc ", " -e ", " -nop ",
                        " -w hidden", " -windowstyle hidden", "bypass",
                        "iex(", "iex (", "invoke-expression"
                    ]
                    if any(f in value_lower for f in sus_flags):
                        return "critical", f"LOLBin with suspicious flags: {lol}"
                    if lol == "cmd.exe" and " /q /c del " in value_lower:
                        return "low", "cmd.exe running benign cleanup command"
                else:
                    return "critical", f"LOLBin in Run key: {lol}"

        if re.search(r'(?<![a-z])-enc(?:odedcommand)?\s', value_lower):
            return "critical", "Base64-encoded command detected"

        for legit in KNOWN_LEGIT_PATHS:
            if value_lower.startswith(legit):
                return "low", "Path in known-good location"

        if value_lower.startswith("%windir%") or value_lower.startswith("%systemroot%"):
            return "low", "System environment variable path"

        for legit_appdata in LEGIT_APPDATA_LOCAL:
            if legit_appdata in value_lower:
                return "medium", f"AppData path — common app location but verify"

        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in value_lower:
                return "high", f"Executable in suspicious path: {sus_path}"

        return "medium", "Not in known-good path — manual review recommended"

    def _upsert_entry(self, entry: dict):
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
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available — skipping")
            return 0

        count  = 0
        cutoff = datetime.now() - timedelta(hours=hours_back)

        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
        except Exception as e:
            print(f"[!] Cannot open Security log: {e}")
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
            print(f"[!] Error reading Security log: {e}")
        finally:
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass

        return count

    def _store_event_4688(self, event, event_dt: datetime):
        strings = event.StringInserts or []

        def get(i, default=""):
            return strings[i] if i < len(strings) else default

        try:
            new_pid    = int(get(4, "0"), 16) if get(4).startswith("0x") else int(get(4) or "0")
            parent_pid = int(get(7, "0"), 16) if get(7).startswith("0x") else int(get(7) or "0")
        except (ValueError, OverflowError):
            new_pid, parent_pid = 0, 0

        self.conn.execute("""
            INSERT OR IGNORE INTO process_events
                (pid, parent_pid, process_name, process_path,
                 command_line, user_name, event_time, event_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, 4688)
        """, (new_pid, parent_pid, os.path.basename(get(5, "")),
              get(5, ""), get(8, ""),
              f"{get(2)}\\{get(1)}" if get(1) else "",
              event_dt.isoformat()))
        self.conn.commit()

    # ── SYSMON COLLECTION (EvtQuery — modern ETW API) ──────
    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def collect_registry_writes(self, hours_back: int = 24) -> int:
        """
        Pull Sysmon Event ID 12 and 13 from the Sysmon operational log
        using EvtQuery — the modern Windows ETW API.

        IMPORTANT: win32evtlog.OpenEventLog() does NOT work for Sysmon.
        It uses the legacy API which can't read ETW/EVTX channels correctly.
        EvtQuery + EvtRender is the correct approach for any modern event log.

        EvtRender returns raw XML which we parse by field name — zero
        dependency on StringInserts order or SafeFormatMessage.
        """
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available — skipping Sysmon collection")
            return 0

        count      = 0
        from datetime import timezone as _tz
        cutoff     = datetime.now(tz=_tz.utc) - timedelta(hours=hours_back)
        cutoff_str = cutoff.strftime('%Y-%m-%dT%H:%M:%S')

        # Simpler XPath: just filter by EventID, we'll filter by time in code
        # Some Windows versions have issues with TimeCreated in XPath
        xpath = "*[System[(EventID=12 or EventID=13)]]"

        if DEBUG:
            print(f"[DEBUG] Querying channel: {self.SYSMON_CHANNEL}")
            print(f"[DEBUG] XPath: {xpath}")
            print(f"[DEBUG] Time cutoff: {cutoff_str}")

        try:
            handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryReverseDirection,
                xpath
            )
        except AttributeError:
            print("[!] EvtQuery not available — pywin32 version too old.")
            print("    pip install --upgrade pywin32")
            return 0
        except Exception as e:
            print(f"[!] Cannot query Sysmon log: {e}")
            print("    Is Sysmon installed and running?  sc query sysmon64")
            return 0

        try:
            while True:
                try:
                    events = win32evtlog.EvtNext(handle, 50)
                except Exception:
                    break
                if not events:
                    break
                for event in events:
                    try:
                        xml_str = win32evtlog.EvtRender(
                            event, win32evtlog.EvtRenderEventXml
                        )
                        if self._store_sysmon_from_xml(xml_str, cutoff):
                            count += 1
                    except Exception as e:
                        if DEBUG:
                            print(f"[DEBUG] Error rendering event: {e}")
                        pass
        except Exception as e:
            print(f"[!] Error iterating Sysmon events: {e}")
        finally:
            try:
                win32evtlog.EvtClose(handle)
            except Exception:
                pass

        return count

    def _store_sysmon_from_xml(self, xml_str: str, cutoff: datetime) -> bool:
        """
        Parse a Sysmon event from its raw XML and store it.

        EvtRender gives us the full event XML — no StringInserts needed.
        We extract fields by Name attribute from <EventData><Data Name="...">
        nodes, which is stable across all Sysmon versions.
        """
        try:
            root = ET.fromstring(xml_str)

            # Namespace used by Windows event XML
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

            # Get timestamp first for filtering
            from datetime import timezone as _tz
            tc = (root.find('.//e:TimeCreated', ns) or root.find('.//TimeCreated'))
            if tc is not None:
                ts = tc.attrib.get('SystemTime', '')
                # Sysmon SystemTime is always UTC: "2026-04-13T08:52:25.4014546Z"
                # Strip sub-second precision and Z, keep as clean ISO string
                if '.' in ts:
                    ts = ts.split('.')[0]   # "2026-04-13T08:52:25"
                ts = ts.rstrip('Z')
                event_time = ts             # stored as "2026-04-13T08:52:25"
                try:
                    # Attach UTC timezone explicitly — fromisoformat gives naive
                    # without it, and we need aware for comparison with cutoff
                    event_dt = datetime.fromisoformat(ts).replace(tzinfo=_tz.utc)
                except Exception:
                    event_dt = datetime.now(tz=_tz.utc)
            else:
                event_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
                event_dt   = datetime.now(tz=_tz.utc)

            # Filter by time
            if event_dt < cutoff:
                return False

            # Extract all <Data Name="..."> fields
            fields = {}
            for node in root.findall('.//e:Data', ns):
                name = node.attrib.get('Name', '')
                if name:
                    fields[name] = (node.text or '').strip()

            if not fields:
                for node in root.iter('Data'):
                    name = node.attrib.get('Name', '')
                    if name:
                        fields[name] = (node.text or '').strip()

            if not fields:
                return False

            # Get EventID
            eid_node = (root.find('.//e:EventID', ns) or root.find('.//EventID'))
            try:
                event_id = int(eid_node.text) if eid_node is not None else 0
            except (ValueError, TypeError):
                event_id = 0

            event_type = fields.get('EventType', '').lower()

            # ID 13: only SetValue events
            # ID 12: CreateKey/OpenKey — also useful
            if event_id == 13 and event_type != 'setvalue':
                return False
            if event_id not in (12, 13):
                return False

            # Parse PID
            try:
                pid = int(fields.get('ProcessId', '0'))
            except (ValueError, TypeError):
                pid = 0

            proc_path  = fields.get('Image', '')
            proc_name  = os.path.basename(proc_path)
            key_path   = fields.get('TargetObject', '')
            value_data = fields.get('Details', '')
            user_name  = fields.get('User', '')

            # Normalise HKU\SID\... → HKCU\...
            key_norm = _normalise_reg_path(key_path)

            # Only store Run / RunOnce keys - check both forward and backslash
            key_lower = key_norm.lower()
            if 'currentversion\\run' not in key_lower and 'currentversion/run' not in key_lower:
                return False

            if DEBUG:
                print(f"[DEBUG] Storing Sysmon event: PID={pid} Image={proc_path} Key={key_norm}")

            self.conn.execute("""
                INSERT OR IGNORE INTO registry_writes
                    (pid, process_name, process_path, key_path,
                     value_data, user_name, event_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (pid, proc_name, proc_path, key_norm,
                  value_data, user_name, event_time[:19]))
            self.conn.commit()
            return True

        except ET.ParseError as e:
            if DEBUG:
                print(f"[DEBUG] XML parse error: {e}")
            return False
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] Unexpected error: {e}")
            return False

    # ── WRITER LOOKUP ──────────────────────────────────────
    def _find_writer(self, entry: dict) -> dict | None:
        """
        Find the process that wrote this registry entry.
        Priority: Sysmon (confirmed) → 4688 by exe name (inferred).
        """
        entry_name = (entry.get("name") or "").lower()
        last_seen  = entry["last_seen"]

        # 1. Sysmon — key_path ends with \<entry_name>
        sysmon_row = self.conn.execute("""
            SELECT * FROM registry_writes
            WHERE  LOWER(key_path) LIKE ?
              AND  event_time      <= ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (f"%\\{entry_name}", last_seen)).fetchone()

        if sysmon_row:
            sysmon = dict(sysmon_row)
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

            # Sysmon PID found but no matching 4688 — synthesise from Sysmon data
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

        # 2. 4688 inferred match by exe name
        value     = entry.get("value_data") or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_name  = os.path.basename(exe_token.strip('"'))

        proc = self._find_process(exe_name, last_seen)
        if proc:
            proc["writer_source"] = "4688"
        return proc

    # ── ATTACK CHAIN BUILDER ───────────────────────────────
    SYSTEM_PROCS = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe"
    }
    SYSTEM_PIDS = {0, 4}
    MAX_DEPTH   = 10

    def _find_process(self, name: str, before: str) -> dict | None:
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE process_name LIKE ?
              AND event_time   <= ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (f"%{name}%", before)).fetchone()
        return dict(row) if row else None

    def _find_parent(self, parent_pid: int, before: str) -> dict | None:
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE pid        = ?
              AND event_time < ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (parent_pid, before)).fetchone()
        return dict(row) if row else None

    def build_attack_chain(self, reg_entry_id: int) -> list[dict]:
        entry = self.conn.execute(
            "SELECT * FROM registry_entries WHERE id = ?", (reg_entry_id,)
        ).fetchone()
        if not entry:
            return []

        entry     = dict(entry)
        value     = entry["value_data"] or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_name  = os.path.basename(exe_token.strip('"'))
        writer    = self._find_writer(entry)

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
                "techniques": [],
                "action": {
                    "type":  "reg",
                    "label": f"Wrote {entry['hive']} → {entry['name']}"
                }
            }]
            self._save_chain(reg_entry_id, placeholder)
            return placeholder

        chain        = []
        current      = writer
        visited_pids = set()
        depth        = 0

        while current and depth < self.MAX_DEPTH:
            pid  = current["pid"]
            name = (current["process_name"] or "").lower()

            if pid in visited_pids:
                break
            if pid in self.SYSTEM_PIDS or name in self.SYSTEM_PROCS:
                chain.append(self._make_node(current, depth, is_writer=False))
                break

            visited_pids.add(pid)
            is_writer = (pid == writer["pid"])
            chain.append(self._make_node(
                current, depth, is_writer=is_writer,
                entry=entry if is_writer else None
            ))

            parent_pid = current.get("parent_pid")
            if not parent_pid:
                break
            parent = self._find_parent(parent_pid, current["event_time"])
            if not parent:
                break

            current = parent
            depth  += 1

        chain.reverse()
        for i, node in enumerate(chain):
            node["depth"] = i

        self._save_chain(reg_entry_id, chain)
        return chain

    def _make_node(self, proc: dict, depth: int, is_writer: bool,
                   entry: dict | None = None) -> dict:
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

        sev, _ = RegistryCollector._static_assess(path, cmd)
        if sev == "critical":
            return "malicious"
        if sev == "high":
            return "suspicious"
        return "normal"

    @staticmethod
    def _static_assess(path: str, cmd: str) -> tuple[str, str]:
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
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM registry_entries GROUP BY severity"
        ).fetchall()
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in rows:
            stats[r["severity"]] = r["cnt"]
        stats["total"]          = sum(stats.values())
        stats["process_events"] = self.conn.execute("SELECT COUNT(*) FROM process_events").fetchone()[0]
        stats["sysmon_writes"]  = self.conn.execute("SELECT COUNT(*) FROM registry_writes").fetchone()[0]
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
  python registry_collector.py --scan --events --sysmon --chain 1
        """
    )
    parser.add_argument("--scan",   action="store_true", help="Scan registry persistence keys")
    parser.add_argument("--events", action="store_true", help="Collect Event ID 4688 from Security log")
    parser.add_argument("--sysmon", action="store_true", help="Collect Sysmon ID 12/13 registry writes")
    parser.add_argument("--hours",  type=int, default=24, help="Hours back to pull events (default 24)")
    parser.add_argument("--chain",  type=int, metavar="ID", help="Build attack chain for entry ID")
    parser.add_argument("--db",     default="reghunt.db",  help="Database path (default: reghunt.db)")
    args = parser.parse_args()

    col = RegistryCollector(db_path=args.db)

    if args.scan:
        print("[*] Scanning registry persistence keys (including all subkeys)...")
        entries = col.collect_registry()
        print(f"[+] Found {len(entries)} entries")
        for e in entries:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(e["severity"], "⚪")
            print(f"  {icon} [{e['severity'].upper():8}] {e['name']:40} → {e['value_data'][:60]}")

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
                indent    = "  " * i
                type_icon = {"system": "⚙️ ", "normal": "📦", "suspicious": "⚠️ ", "malicious": "💀"}.get(node["type"], "❓")
                src_badge = f"[{node.get('source','?')}]"
                print(f"{indent}{type_icon} {node['name']} (PID {node['pid']}) {src_badge} — {node['user']}")
                if node.get("action"):
                    print(f"{indent}   ↳ {node['action']['label']}")
                if node.get("techniques"):
                    techs = ", ".join(t['id'] for t in node['techniques'])
                    print(f"{indent}   📌 {techs}")
        else:
            print("[!] No chain found. Run --scan and --events first.")

    stats = col.get_stats()
    print(f"\n[*] DB Stats: {stats['total']} entries | {stats['process_events']} process events | {stats['sysmon_writes']} sysmon writes")
    print(f"    Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}")

    col.close()