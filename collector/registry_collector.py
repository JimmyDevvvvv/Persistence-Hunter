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
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

# pywin32 — install via: pip install pywin32
# Used for EvtQuery → EvtNext → EvtRender (modern Windows Event Log API).
# This is the same API used internally by Event Viewer and is reliable on
# all custom channels (e.g. Sysmon) where the legacy OpenEventLog API fails.
try:
    import win32evtlog
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False
    print("[!] pywin32 not installed. Event log correlation disabled.")
    print("    pip install pywin32")

# Debug flag
DEBUG = os.environ.get("REGHUNT_DEBUG", "").lower() in ("1", "true", "yes")

def debug_print(*args, **kwargs):
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

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


def normalise_reg_path(path: str) -> str:
    r"""
    Normalise registry paths for consistent matching.

    Input formats we must handle:
      1. Kernel paths from EvtRender raw XML (the most common case with EvtQuery):
           \REGISTRY\MACHINE\SOFTWARE\...          -> HKLM\SOFTWARE\...
           \REGISTRY\USER\S-1-5-21-...\Software\.. -> HKCU\Software\...
           \REGISTRY\USER\.DEFAULT\...             -> HKU\.DEFAULT\...

      2. Sysmon-abbreviated paths (from Sysmon's own rendering):
           HKLM\...   HKU\SID\...   HKCR\...

      3. Win32 API names:
           HKEY_LOCAL_MACHINE\...
           HKEY_CURRENT_USER\...
    """
    p = path.lstrip("\\")           # strip leading backslash(es)
    upper = p.upper()

    # ── ① Kernel paths: \REGISTRY\MACHINE\... and \REGISTRY\USER\... ─────────
    if upper.startswith("REGISTRY\\MACHINE\\"):
        return "HKLM\\" + p[len("REGISTRY\\MACHINE\\"):]

    if upper.startswith("REGISTRY\\USER\\"):
        rest = p[len("REGISTRY\\USER\\"):]          # SID\Software\... or .DEFAULT\...
        # Skip the SID component (everything up to the first \)
        parts = rest.split("\\", 1)
        if len(parts) == 2:
            sid, remainder = parts
            # Well-known service SIDs are not HKCU
            if sid.upper() in (".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"):
                return f"HKU\\{sid}\\{remainder}"
            return "HKCU\\" + remainder
        return "HKCU\\" + rest

    # ── ② Sysmon-abbreviated: HKU\SID\... ────────────────────────────────────
    if upper.startswith("HKU\\"):
        parts = p.split("\\", 2)                    # ["HKU", "SID", "rest"]
        if len(parts) >= 3:
            sid = parts[1].upper()
            if sid in (".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"):
                return f"HKU\\{parts[1]}\\{parts[2]}"
            return "HKCU\\" + parts[2]
        return "HKCU\\" + (parts[1] if len(parts) > 1 else "")

    # ── ③ Win32 long-form names ───────────────────────────────────────────────
    if upper.startswith("HKEY_LOCAL_MACHINE\\"):
        return "HKLM\\" + p[19:]
    if upper.startswith("HKEY_CURRENT_USER\\"):
        return "HKCU\\" + p[18:]
    if upper.startswith("HKEY_USERS\\"):
        return normalise_reg_path("HKU\\" + p[11:])
    if upper.startswith("HKEY_CLASSES_ROOT\\"):
        return "HKCR\\" + p[18:]

    # Already normalised (HKLM\, HKCU\, HKCR\, etc.)
    return p


class RegistryCollector:
    def __init__(self, db_path: str = "reghunt.db"):
        self.db_path = db_path
        self.conn    = self._init_db()
        self.SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

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
        # TODO: If extended, scan additional persistence locations
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
        """
        Collect Security EventID 4688 (process creation) using the modern
        EvtQuery API with a timediff() XPath filter — same pattern as
        collect_registry_writes so both are consistent and reliable.
        Requires 'Audit Process Creation' to be enabled and
        'Include command line in process creation events' for full cmdline.
        """
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available — skipping")
            return 0

        try:
            import pywintypes
        except ImportError:
            print("[!] pywintypes not available — skipping")
            return 0

        ms_back = hours_back * 3_600_000
        cutoff  = datetime.utcnow() - timedelta(hours=hours_back)
        xpath   = (
            f"*[System[EventID=4688 and "
            f"TimeCreated[timediff(@SystemTime) <= {ms_back}]]]"
        )
        debug_print(f"4688 XPath: {xpath}")

        count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                "Security",
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath,
                None,
            )
        except pywintypes.error as e:
            err_code = e.args[0] if e.args else 0
            if err_code == 5:
                print("[!] Access denied reading Security log — run as Administrator")
            else:
                print(f"[!] Cannot open Security log: {e}")
            return 0

        try:
            while True:
                try:
                    events = win32evtlog.EvtNext(query_handle, 100, -1, 0)
                except pywintypes.error:
                    break
                if not events:
                    break
                for evt_handle in events:
                    try:
                        xml_str = win32evtlog.EvtRender(
                            evt_handle, win32evtlog.EvtRenderEventXml
                        )
                        if self._store_event_4688_xml(xml_str, cutoff):
                            count += 1
                    except Exception as exc:
                        debug_print(f"Error rendering 4688 event: {exc}")
        except Exception as e:
            print(f"[!] Error reading Security log: {e}")
        finally:
            try:
                win32evtlog.EvtClose(query_handle)
            except Exception:
                pass

        return count

    def _store_event_4688_xml(self, xml_str: str, cutoff: datetime) -> bool:
        """
        Parse a 4688 event rendered as XML by EvtRender and store it.
        Named EventData fields used (Vista+):
          SubjectDomainName, SubjectUserName, NewProcessId,
          ProcessId (parent), NewProcessName, CommandLine
        """
        try:
            root = ET.fromstring(xml_str)
            ns   = "{http://schemas.microsoft.com/win/2004/08/events/event}"

            # Timestamp
            tc = root.find(f".//{ns}TimeCreated")
            if tc is None:
                return False
            ts = tc.attrib.get("SystemTime", "")
            if not ts:
                return False
            ts_clean = ts.split(".")[0].rstrip("Z")
            event_dt = datetime.fromisoformat(ts_clean)
            if event_dt < cutoff:
                return False

            # Named EventData fields
            fields: dict[str, str] = {}
            for data in root.findall(f".//{ns}Data"):
                name = data.attrib.get("Name", "")
                if name:
                    fields[name] = (data.text or "").strip()

            def _parse_pid(val: str) -> int:
                try:
                    return int(val, 16) if val.startswith("0x") else int(val)
                except (ValueError, OverflowError):
                    return 0

            new_pid    = _parse_pid(fields.get("NewProcessId", "0"))
            parent_pid = _parse_pid(fields.get("ProcessId",    "0"))
            proc_path  = fields.get("NewProcessName", "")
            proc_name  = os.path.basename(proc_path)
            cmdline    = fields.get("CommandLine", "")
            domain     = fields.get("SubjectDomainName", "")
            user       = fields.get("SubjectUserName", "")
            user_name  = f"{domain}\\{user}" if user else ""

            self.conn.execute("""
                INSERT OR IGNORE INTO process_events
                    (pid, parent_pid, process_name, process_path,
                     command_line, user_name, event_time, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, 4688)
            """, (new_pid, parent_pid, proc_name, proc_path,
                  cmdline, user_name, event_dt.isoformat()))
            self.conn.commit()
            return True

        except ET.ParseError as e:
            debug_print(f"4688 XML parse error: {e}")
            return False
        except Exception as e:
            debug_print(f"4688 store error: {e}")
            return False

    # ── SYSMON COLLECTION (EvtQuery → EvtNext → EvtRender) ────
    def collect_registry_writes(self, hours_back: int = 24) -> int:
        """
        Collect Sysmon EventID 12/13 events by querying the live channel
        directly via win32evtlog.EvtQuery — no temp files, no wevtutil,
        no python-evtx required.

        Uses timediff() for time filtering, which is reliable across all
        Windows versions (absolute-UTC comparisons with wevtutil epl are not).
        """
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available — skipping Sysmon collection")
            return 0

        try:
            import pywintypes
        except ImportError:
            print("[!] pywintypes not available — skipping Sysmon collection")
            return 0

        ms_back = hours_back * 3_600_000          # hours → milliseconds
        cutoff  = datetime.utcnow() - timedelta(hours=hours_back)

        # timediff() is the only reliable time-filter for EvtQuery / wevtutil.
        # It computes milliseconds since the event was written, relative to NOW.
        xpath = (
            f"*[System["
            f"(EventID=12 or EventID=13) and "
            f"TimeCreated[timediff(@SystemTime) <= {ms_back}]"
            f"]]"
        )
        debug_print(f"Hours back : {hours_back}")
        debug_print(f"ms_back    : {ms_back}")
        debug_print(f"XPath      : {xpath}")

        count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath,
                None,
            )
        except pywintypes.error as e:
            # ERROR_EVT_CHANNEL_NOT_FOUND (15007) → Sysmon not installed/running
            # ERROR_ACCESS_DENIED (5)             → not running as Administrator
            err_code = e.args[0] if e.args else 0
            if err_code == 15007:
                print(f"[!] Sysmon channel not found — is Sysmon installed and running?")
            elif err_code == 5:
                print(f"[!] Access denied reading Sysmon log — run as Administrator")
            else:
                print(f"[!] Cannot open Sysmon channel: {e}")
            return self._collect_registry_writes_fallback(hours_back)

        try:
            while True:
                # Pull events in batches of 100 — minimises round-trip overhead
                try:
                    events = win32evtlog.EvtNext(query_handle, 100, -1, 0)
                except pywintypes.error:
                    break  # no more events

                if not events:
                    break

                for evt_handle in events:
                    try:
                        xml_str = win32evtlog.EvtRender(
                            evt_handle, win32evtlog.EvtRenderEventXml
                        )
                        if self._store_sysmon_from_xml(xml_str, cutoff):
                            count += 1
                            if DEBUG and count % 100 == 0:
                                debug_print(f"  … stored {count} events so far")
                    except Exception as exc:
                        debug_print(f"Error rendering event: {exc}")

        except Exception as e:
            print(f"[!] Sysmon EvtQuery enumeration failed: {e}")
        finally:
            try:
                win32evtlog.EvtClose(query_handle)
            except Exception:
                pass

        debug_print(f"Stored {count} Sysmon events from the last {hours_back} hours")
        return count

    def _collect_registry_writes_fallback(self, hours_back: int) -> int:
        """
        Last-resort fallback: call PowerShell Get-WinEvent and parse its XML
        output. Used only when EvtQuery fails (e.g. Sysmon not installed).
        No temp .evtx files — output is piped directly from stdout.
        """
        ms_back = hours_back * 3_600_000
        cutoff  = datetime.utcnow() - timedelta(hours=hours_back)

        xpath = (
            f"*[System[(EventID=12 or EventID=13) and "
            f"TimeCreated[timediff(@SystemTime) <= {ms_back}]]]"
        )

        ps_cmd = (
            f"Get-WinEvent -LogName '{self.SYSMON_CHANNEL}' "
            f"-FilterXPath '{xpath}' -ErrorAction SilentlyContinue "
            f"| ForEach-Object {{ $_.ToXml() }}"
        )

        debug_print(f"[fallback] PowerShell: {ps_cmd}")

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True, text=True, check=False, timeout=60,
            )
        except Exception as e:
            print(f"[!] PowerShell fallback failed: {e}")
            return 0

        if result.returncode not in (0, 1):   # rc=1 when no events found is normal
            debug_print(f"[fallback] PS stderr: {result.stderr[:200]}")
            return 0

        count = 0
        # Each event comes back as a standalone XML fragment; split on </Event>
        for fragment in re.split(r'(?<=</Event>)', result.stdout):
            fragment = fragment.strip()
            if not fragment:
                continue
            if self._store_sysmon_from_xml(fragment, cutoff):
                count += 1

        debug_print(f"[fallback] Stored {count} events via PowerShell")
        return count

    def _store_sysmon_from_xml(self, xml_str: str, cutoff: datetime) -> bool:
        """
        Parse a Sysmon event XML and store it if within time window.
        Returns True if stored.
        """
        try:
            root = ET.fromstring(xml_str)

            # Extract EventID and timestamp
            event_id = None
            event_dt = None
            for node in root.iter():
                tag = node.tag.split('}')[-1] if '}' in node.tag else node.tag
                if tag == 'EventID':
                    event_id = int(node.text or '0')
                elif tag == 'TimeCreated':
                    ts = node.attrib.get('SystemTime', '')
                    if ts:
                        ts_clean = ts.split('.')[0].rstrip('Z')
                        event_dt = datetime.fromisoformat(ts_clean)
                        break

            if event_id is None or event_dt is None:
                return False
            if event_id not in (12, 13):
                return False
            if event_dt < cutoff:
                return False

            # Extract Data fields
            fields = {}
            for node in root.iter():
                tag = node.tag.split('}')[-1] if '}' in node.tag else node.tag
                if tag == 'Data':
                    name = node.attrib.get('Name', '')
                    if name:
                        fields[name] = (node.text or '').strip()

            if not fields:
                return False

            # EventType filter for ID 13 (SetValue)
            if event_id == 13 and fields.get('EventType', '').lower() != 'setvalue':
                return False

            # Extract values
            try:
                pid = int(fields.get('ProcessId', '0'))
            except (ValueError, TypeError):
                pid = 0

            proc_path = fields.get('Image', '')
            proc_name = os.path.basename(proc_path)
            key_path = fields.get('TargetObject', '')
            value_data = fields.get('Details', '')
            user_name = fields.get('User', '')

            if not key_path:
                return False

            # Normalize path
            key_norm = normalise_reg_path(key_path)

            # Only store Run / RunOnce keys
            if 'currentversion\\run' not in key_norm.lower():
                return False

            # Store the event
            event_time_str = event_dt.isoformat()[:19]
            self.conn.execute("""
                INSERT OR IGNORE INTO registry_writes
                    (pid, process_name, process_path, key_path,
                     value_data, user_name, event_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (pid, proc_name, proc_path, key_norm,
                  value_data, user_name, event_time_str))
            self.conn.commit()
            debug_print(f"Stored event: PID={pid} Image={proc_path} Key={key_norm}")
            return True

        except ET.ParseError as e:
            debug_print(f"XML parse error: {e}")
            return False
        except Exception as e:
            debug_print(f"Unexpected error: {e}")
            return False

    # ── WRITER LOOKUP ──────────────────────────────────────
    def _find_writer(self, entry: dict) -> dict | None:
        """
        Try to attribute which process wrote this Run key entry.

        Strategy (in order):
          1. Sysmon key-path LIKE match  (exact, most reliable)
          2. Sysmon image-path match     (matches any Sysmon event whose Image
                                          matches the value_data exe path)
          3. 4688 fuzzy exe-name match   (last resort)
        """
        entry_name = (entry.get("name") or "").lower()
        value_data = entry.get("value_data") or ""
        exe_token  = value_data.strip().split()[0] if value_data.strip() else ""
        exe_path   = exe_token.strip('"')
        exe_name   = os.path.basename(exe_path)

        # ── 1. Sysmon key-path match ─────────────────────────
        sysmon_row = self.conn.execute("""
            SELECT * FROM registry_writes
            WHERE  LOWER(key_path) LIKE ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (f"%\\{entry_name}",)).fetchone()

        debug_print(f"_find_writer [{entry_name}]: "
                    f"sysmon key-path={'found' if sysmon_row else 'NONE'}")

        if sysmon_row:
            return self._enrich_from_sysmon(sysmon_row)

        # ── 2. Sysmon image-path match ───────────────────────
        # If the Run value points to totally_not_malware.exe, find any Sysmon
        # registry write whose Image field matches that path.
        if exe_path:
            img_row = self.conn.execute("""
                SELECT * FROM registry_writes
                WHERE  LOWER(process_path) = ?
                ORDER BY event_time DESC
                LIMIT 1
            """, (exe_path.lower(),)).fetchone()

            if not img_row and exe_name:
                img_row = self.conn.execute("""
                    SELECT * FROM registry_writes
                    WHERE  LOWER(process_name) = ?
                    ORDER BY event_time DESC
                    LIMIT 1
                """, (exe_name.lower(),)).fetchone()

            debug_print(f"  sysmon image-path match ({'found' if img_row else 'NONE'})")
            if img_row:
                return self._enrich_from_sysmon(img_row)

        # ── 3. 4688 fuzzy exe-name fallback ──────────────────
        debug_print(f"  falling back to 4688 fuzzy on exe_name={exe_name!r}")
        proc = self._find_process(exe_name)
        if proc:
            proc["writer_source"] = "4688"
            return proc

        debug_print(f"  no match found → chain will be inferred")
        return None

    def _enrich_from_sysmon(self, sysmon_row) -> dict:
        """
        Given a registry_writes row, try to cross-reference with a 4688 row
        for the same PID. If found, return the enriched 4688 data.
        If not, synthesise a node from Sysmon alone (still attributed, not inferred).
        """
        sysmon = dict(sysmon_row)
        debug_print(f"  sysmon PID={sysmon['pid']} proc={sysmon['process_name']!r} "
                    f"time={sysmon['event_time']!r}")

        proc = self.conn.execute("""
            SELECT * FROM process_events
            WHERE  pid = ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (sysmon["pid"],)).fetchone()

        if proc:
            debug_print(f"  enriched with 4688 row for PID {sysmon['pid']}")
            result = dict(proc)
            result["writer_source"] = "sysmon"
            return result

        debug_print(f"  no 4688 row for PID {sysmon['pid']} — synthesising from Sysmon")
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

    # ── ATTACK CHAIN BUILDER ───────────────────────────────
    SYSTEM_PROCS = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe"
    }
    SYSTEM_PIDS = {0, 4}
    MAX_DEPTH   = 10

    def _find_process(self, name: str) -> dict | None:
        """Find the most recent process event matching name (fuzzy)."""
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE process_name LIKE ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (f"%{name}%",)).fetchone()
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
            debug_print(
                f"No writer found for entry {reg_entry_id} ({entry.get('name')!r}). "
                f"Run: python diagnose_reghunt.py --db {self.db_path} --id {reg_entry_id}"
            )
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
    parser.add_argument("--scan",      action="store_true", help="Scan registry persistence keys")
    parser.add_argument("--events",    action="store_true", help="Collect Event ID 4688 from Security log")
    parser.add_argument("--sysmon",    action="store_true", help="Collect Sysmon ID 12/13 registry writes")
    parser.add_argument("--hours",     type=int, default=24, help="Hours back to pull events (default 24)")
    parser.add_argument("--chain",     type=int, metavar="ID", help="Build attack chain for entry ID")
    parser.add_argument("--chain-all", action="store_true",   help="Build chains for all High/Critical entries")
    parser.add_argument("--db",        default="reghunt.db",  help="Database path (default: reghunt.db)")
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

    if args.chain_all:
        print(f"\n[*] Building chains for all High/Critical entries...")
        rows = col.conn.execute(
            "SELECT id, name, severity FROM registry_entries "
            "WHERE severity IN ('high','critical') ORDER BY severity DESC, id"
        ).fetchall()
        print(f"[+] Found {len(rows)} High/Critical entries")
        for row in rows:
            print(f"\n  --- Entry {row['id']}: {row['name']} [{row['severity'].upper()}] ---")
            chain = col.build_attack_chain(row['id'])
            if chain:
                for i, node in enumerate(chain):
                    indent    = "    " + "  " * i
                    type_icon = {"system": "⚙️ ", "normal": "📦", "suspicious": "⚠️ ", "malicious": "💀"}.get(node["type"], "❓")
                    src_badge = f"[{node.get('source','?')}]"
                    print(f"{indent}{type_icon} {node['name']} (PID {node['pid']}) {src_badge} — {node['user']}")
                    if node.get("action"):
                        print(f"{indent}   ↳ {node['action']['label']}")
            else:
                print("    [!] No chain")

    stats = col.get_stats()
    print(f"\n[*] DB Stats: {stats['total']} entries | {stats['process_events']} process events | {stats['sysmon_writes']} sysmon writes")
    print(f"    Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}")

    col.close()