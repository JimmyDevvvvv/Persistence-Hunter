"""
registry_collector.py
Collects registry persistence entries from Run/RunOnce keys.
Correlates with:
  - Sysmon Event 13 (RegistryValueSet) and Event 1 (ProcessCreate) [preferred]
  - Event ID 4688 process creation logs [fallback]

Requires: Windows, pywin32, Sysmon (optional but recommended)
Run as Administrator for HKLM access and event log access.
"""

import winreg
import sqlite3
import json
import hashlib
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

try:
    import win32evtlog
    import pywintypes
    PYWIN32_AVAILABLE = True
    # Check for modern EvtQuery function (required for Sysmon/4688)
    if not hasattr(win32evtlog, 'EvtQuery'):
        print("[!] pywin32 too old. Upgrade: pip install --upgrade pywin32")
        PYWIN32_AVAILABLE = False
except ImportError:
    PYWIN32_AVAILABLE = False
    print("[!] pywin32 not installed. Event log correlation disabled.")
    print("    pip install pywin32")

DEBUG = os.environ.get("REGHUNT_DEBUG", "").lower() in ("1", "true", "yes")
def debug_print(*args, **kwargs):
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

# ── REGISTRY KEYS TO MONITOR ──────────────────────────────
PERSISTENCE_KEYS = [
    {"hive": winreg.HKEY_LOCAL_MACHINE, "hive_name": "HKLM", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "key_type": "Run"},
    {"hive": winreg.HKEY_CURRENT_USER,  "hive_name": "HKCU", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "key_type": "Run"},
    {"hive": winreg.HKEY_LOCAL_MACHINE, "hive_name": "HKLM", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "key_type": "RunOnce"},
    {"hive": winreg.HKEY_CURRENT_USER,  "hive_name": "HKCU", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "key_type": "RunOnce"},
]

KNOWN_LEGIT_PATHS = [r"c:\windows\system32", r"c:\windows\syswow64", r"c:\program files\windows", r"c:\program files (x86)\windows", r"c:\program files\microsoft", r"c:\program files (x86)\microsoft"]
SUSPICIOUS_PATHS = [r"c:\users\public", r"c:\temp", r"c:\windows\temp", r"\appdata\local\temp", r"\appdata\roaming", r"\appdata\local", r"\downloads", r"\desktop", r"c:\perflogs", r"c:\recycler", r"c:\malware", r"c:\payload", r"c:\tools\implant", r"c:\staged"]
SUSPICIOUS_NAME_PATTERNS = ["fake", "malware", "backdoor", "payload", "implant", "keylog", "rat.", "trojan", "dropper", "loader", "stager", "beacon", "inject", "shellcode", "exploit", "not_malware", "definitely_not", "totally_not"]
_ROOT_EXE_RE = re.compile(r'^[a-z]:\\[^\\]+\.exe', re.IGNORECASE)
LEGIT_APPDATA_LOCAL = [r"\appdata\local\microsoft\windowsapps", r"\appdata\local\microsoft\teams", r"\appdata\local\discord", r"\appdata\local\grammarly"]
LOLBINS = ["mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wmic.exe", "powershell.exe", "cmd.exe", "regsvcs.exe", "regasm.exe", "installutil.exe"]

# MITRE lookups (same as before)
MITRE_REG_TECHNIQUES = [(r"currentversion\run", "T1547.001", "Boot/Logon Autostart: Registry Run Keys"), (r"currentversion\runonce", "T1547.001", "Boot/Logon Autostart: Registry Run Keys")]
MITRE_PROC_TECHNIQUES = [("powershell.exe", "T1059.001", "Command & Scripting: PowerShell"), ("cmd.exe", "T1059.003", "Command & Scripting: Windows Command Shell"), ("wscript.exe", "T1059.005", "Command & Scripting: Visual Basic"), ("cscript.exe", "T1059.005", "Command & Scripting: Visual Basic"), ("mshta.exe", "T1218.005", "System Binary Proxy: Mshta"), ("regsvr32.exe", "T1218.010", "System Binary Proxy: Regsvr32"), ("rundll32.exe", "T1218.011", "System Binary Proxy: Rundll32"), ("certutil.exe", "T1140", "Deobfuscate/Decode Files or Information"), ("bitsadmin.exe", "T1197", "BITS Jobs"), ("msiexec.exe", "T1218.007", "System Binary Proxy: Msiexec"), ("wmic.exe", "T1047", "Windows Management Instrumentation"), ("regsvcs.exe", "T1218.009", "System Binary Proxy: Regsvcs/Regasm"), ("regasm.exe", "T1218.009", "System Binary Proxy: Regsvcs/Regasm"), ("installutil.exe", "T1218.004", "System Binary Proxy: InstallUtil")]
MITRE_CMD_TECHNIQUES = [("-enc", "T1027", "Obfuscated Files or Information"), ("-encodedcommand", "T1027", "Obfuscated Files or Information"), ("invoke-expression", "T1059.001", "Command & Scripting: PowerShell"), ("iex(", "T1059.001", "Command & Scripting: PowerShell"), ("bypass", "T1562.001", "Disable or Modify Tools"), ("-nop", "T1562.001", "Disable or Modify Tools"), ("http://", "T1105", "Ingress Tool Transfer"), ("https://", "T1105", "Ingress Tool Transfer"), ("-decode", "T1140", "Deobfuscate/Decode Files or Information"), ("/transfer", "T1197", "BITS Jobs")]

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
    p = path.lstrip("\\")
    upper = p.upper()
    if upper.startswith("REGISTRY\\MACHINE\\"):
        return "HKLM\\" + p[len("REGISTRY\\MACHINE\\"):]
    if upper.startswith("REGISTRY\\USER\\"):
        rest = p[len("REGISTRY\\USER\\"):]
        parts = rest.split("\\", 1)
        if len(parts) == 2:
            sid, remainder = parts
            if sid.upper() in (".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"):
                return f"HKU\\{sid}\\{remainder}"
            return "HKCU\\" + remainder
        return "HKCU\\" + rest
    if upper.startswith("HKU\\"):
        parts = p.split("\\", 2)
        if len(parts) >= 3:
            sid = parts[1].upper()
            if sid in (".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"):
                return f"HKU\\{parts[1]}\\{parts[2]}"
            return "HKCU\\" + parts[2]
        return "HKCU\\" + (parts[1] if len(parts) > 1 else "")
    if upper.startswith("HKEY_LOCAL_MACHINE\\"):
        return "HKLM\\" + p[19:]
    if upper.startswith("HKEY_CURRENT_USER\\"):
        return "HKCU\\" + p[18:]
    if upper.startswith("HKEY_USERS\\"):
        return normalise_reg_path("HKU\\" + p[11:])
    if upper.startswith("HKEY_CLASSES_ROOT\\"):
        return "HKCR\\" + p[18:]
    return p


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

            -- Sysmon tables
            CREATE TABLE IF NOT EXISTS sysmon_process_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                pid             INTEGER,
                parent_pid      INTEGER,
                process_name    TEXT,
                process_path    TEXT,
                command_line    TEXT,
                user_name       TEXT,
                hashes          TEXT,
                integrity_level TEXT,
                event_time      TEXT,
                event_id        INTEGER
            );

            CREATE TABLE IF NOT EXISTS sysmon_registry_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                pid             INTEGER,
                process_name    TEXT,
                process_path    TEXT,
                event_time      TEXT,
                key_path        TEXT,
                value_name      TEXT,
                value_data      TEXT,
                event_id        INTEGER
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
            CREATE INDEX IF NOT EXISTS idx_sysmon_reg_key  ON sysmon_registry_events(key_path, value_name);
            CREATE INDEX IF NOT EXISTS idx_sysmon_reg_pid  ON sysmon_registry_events(pid);
            CREATE INDEX IF NOT EXISTS idx_sysmon_proc_pid ON sysmon_process_events(pid);
        """)
        conn.commit()

        # Migrations for existing DBs
        reg_cols = {r[1] for r in conn.execute("PRAGMA table_info(registry_entries)")}
        if "techniques" not in reg_cols:
            conn.execute("ALTER TABLE registry_entries ADD COLUMN techniques TEXT DEFAULT '[]'")
            conn.commit()
        return conn

    # ── REGISTRY SCANNING (unchanged) ─────────────────────────
    def collect_registry(self, extended: bool = False) -> list[dict]:
        results = []
        for key_info in PERSISTENCE_KEYS:
            results.extend(self._read_key(key_info))
        return results

    def _read_key(self, key_info: dict) -> list[dict]:
        entries = []
        try:
            key = winreg.OpenKey(key_info["hive"], key_info["path"], 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except (FileNotFoundError, PermissionError):
            return []
        try:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    full_path = f"{key_info['hive_name']}\\{key_info['path']}"
                    data_str = str(data)
                    severity, ioc = self._assess_severity(name, data_str)
                    hash_id = hashlib.md5(f"{full_path}|{name}|{data_str}".encode()).hexdigest()
                    entry = {
                        "name": name, "hive": f"{key_info['hive_name']}\\{key_info['key_type']}",
                        "reg_path": full_path, "value_data": data_str, "severity": severity,
                        "ioc_notes": ioc, "techniques": json.dumps(tag_registry(f"{key_info['hive_name']}\\{key_info['key_type']}", full_path)),
                        "last_seen": datetime.now().isoformat(), "hash_id": hash_id,
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

    def _assess_severity(self, name: str, value: str) -> tuple[str, str]:
        value_lower = value.lower()
        if any(p in value_lower for p in ["http://", "https://", "ftp://"]):
            return "critical", "Remote URL in registry value"
        for lol in LOLBINS:
            if lol in value_lower:
                if lol in ("powershell.exe", "cmd.exe"):
                    sus_flags = [" -encodedcommand ", " -enc ", " -e ", " -nop ", " -w hidden", " -windowstyle hidden", "bypass", "iex(", "iex (", "invoke-expression"]
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
                return "medium", "AppData path — common app location but verify"
        exe_lower = value_lower.split("\\")[-1].split('"')[0].split(" ")[0]
        for pat in SUSPICIOUS_NAME_PATTERNS:
            if pat in exe_lower or pat in name.lower():
                return "critical", f"Suspicious filename pattern: {pat}"
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in value_lower:
                return "high", f"Executable in suspicious path: {sus_path}"
        clean_val = value_lower.lstrip('"')
        if _ROOT_EXE_RE.match(clean_val):
            return "high", "Executable at filesystem root — unusual location"
        return "medium", "Not in known-good path — manual review recommended"

    def _upsert_entry(self, entry: dict):
        self.conn.execute("""
            INSERT INTO registry_entries
                (name, hive, reg_path, value_data, severity, ioc_notes, techniques, first_seen, last_seen, hash_id)
            VALUES (:name, :hive, :reg_path, :value_data, :severity, :ioc_notes, :techniques, :last_seen, :last_seen, :hash_id)
            ON CONFLICT(hash_id) DO UPDATE SET
                severity = excluded.severity, ioc_notes = excluded.ioc_notes,
                techniques = excluded.techniques, last_seen = excluded.last_seen
        """, entry)
        self.conn.commit()

    # ── SYSMON COLLECTION (with safe EvtClose handling) ────────
    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def collect_sysmon_events(self, hours_back: int = 24) -> int:
        """Collect Sysmon Event ID 13 (RegistryValueSet) and Event ID 1 (ProcessCreate)."""
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available or too old.")
            return 0
        ms_back = hours_back * 3_600_000
        cutoff = datetime.utcnow() - timedelta(hours=hours_back)
        reg_count = self._collect_sysmon_registry_events(ms_back, cutoff)
        proc_count = self._collect_sysmon_process_events(ms_back, cutoff)
        return reg_count + proc_count

    def _collect_sysmon_registry_events(self, ms_back: int, cutoff: datetime) -> int:
        xpath = f"*[System[EventID=13 and TimeCreated[timediff(@SystemTime) <= {ms_back}]]]"
        count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None
            )
        except pywintypes.error as e:
            if e.args[0] == 2:
                print("[!] Sysmon not installed. Install from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon")
                print("    Example: sysmon64 -accepteula -i -n")
            else:
                print(f"[!] Cannot open Sysmon log: {e}")
            return 0
        except AttributeError as e:
            print("[!] pywin32 missing EvtQuery. Upgrade: pip install --upgrade pywin32")
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
                        xml_str = win32evtlog.EvtRender(evt_handle, win32evtlog.EvtRenderEventXml)
                        if self._store_sysmon_registry_event(xml_str, cutoff):
                            count += 1
                    except Exception as e:
                        debug_print(f"Error rendering Sysmon registry event: {e}")
        finally:
            # Safely close handle if EvtClose exists
            try:
                win32evtlog.EvtClose(query_handle)
            except AttributeError:
                pass
        return count

    def _store_sysmon_registry_event(self, xml_str: str, cutoff: datetime) -> bool:
        try:
            root = ET.fromstring(xml_str)
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
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

            # Extract EventData
            data_dict = {}
            for data in root.findall(f".//{ns}Data"):
                name = data.attrib.get("Name", "")
                if name:
                    data_dict[name] = (data.text or "").strip()

            # TargetObject is the registry key path (e.g., HKLM\SOFTWARE\...\Run)
            # Details is the value data
            # ProcessId is the PID (decimal in some versions, hex in others)
            key_path = data_dict.get("TargetObject", "")
            if not key_path:
                return False

            # Normalise key path: Sysmon may give \REGISTRY\MACHINE\... but we want HKLM\...
            key_path_norm = normalise_reg_path(key_path)
            # Extract value name from end of key path (Sysmon includes value name in TargetObject)
            # Format: HKLM\SOFTWARE\...\Run\ValueName
            value_name = ""
            if "\\" in key_path_norm:
                parts = key_path_norm.split("\\")
                value_name = parts[-1]  # last part is the value name
                key_path_norm = "\\".join(parts[:-1])  # parent key path

            value_data = data_dict.get("Details", "")
            pid_str = data_dict.get("ProcessId", "0")
            try:
                pid = int(pid_str, 16) if pid_str.startswith("0x") else int(pid_str)
            except ValueError:
                pid = 0
            process_path = data_dict.get("Image", "")
            process_name = os.path.basename(process_path) if process_path else ""

            self.conn.execute("""
                INSERT OR IGNORE INTO sysmon_registry_events
                    (pid, process_name, process_path, event_time, key_path, value_name, value_data, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, 13)
            """, (pid, process_name, process_path, event_dt.isoformat(), key_path_norm, value_name, value_data))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print(f"Error storing Sysmon registry event: {e}")
            return False

    def _collect_sysmon_process_events(self, ms_back: int, cutoff: datetime) -> int:
        xpath = f"*[System[EventID=1 and TimeCreated[timediff(@SystemTime) <= {ms_back}]]]"
        count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None
            )
        except (pywintypes.error, AttributeError):
            # Silently ignore if Sysmon not installed or functions missing
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
                        xml_str = win32evtlog.EvtRender(evt_handle, win32evtlog.EvtRenderEventXml)
                        if self._store_sysmon_process_event(xml_str, cutoff):
                            count += 1
                    except Exception:
                        pass
        finally:
            try:
                win32evtlog.EvtClose(query_handle)
            except AttributeError:
                pass
        return count

    def _store_sysmon_process_event(self, xml_str: str, cutoff: datetime) -> bool:
        try:
            root = ET.fromstring(xml_str)
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
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

            data_dict = {}
            for data in root.findall(f".//{ns}Data"):
                name = data.attrib.get("Name", "")
                if name:
                    data_dict[name] = (data.text or "").strip()

            # Standard Sysmon Event 1 fields
            pid = int(data_dict.get("ProcessId", "0"))
            parent_pid = int(data_dict.get("ParentProcessId", "0"))
            process_path = data_dict.get("Image", "")
            process_name = os.path.basename(process_path)
            command_line = data_dict.get("CommandLine", "")
            user_name = data_dict.get("User", "")
            hashes = data_dict.get("Hashes", "")
            integrity = data_dict.get("IntegrityLevel", "")

            self.conn.execute("""
                INSERT OR IGNORE INTO sysmon_process_events
                    (pid, parent_pid, process_name, process_path, command_line, user_name, hashes, integrity_level, event_time, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (pid, parent_pid, process_name, process_path, command_line, user_name, hashes, integrity, event_dt.isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print(f"Error storing Sysmon process event: {e}")
            return False

    # ── EVENT LOG COLLECTION (4688 fallback) ─────────────────
    def collect_process_events(self, hours_back: int = 24) -> int:
        if not PYWIN32_AVAILABLE:
            return 0
        ms_back = hours_back * 3_600_000
        cutoff = datetime.utcnow() - timedelta(hours=hours_back)
        xpath = f"*[System[EventID=4688 and TimeCreated[timediff(@SystemTime) <= {ms_back}]]]"
        count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                "Security",
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None
            )
        except pywintypes.error as e:
            if e.args[0] == 5:
                print("[!] Access denied reading Security log — run as Administrator")
            else:
                print(f"[!] Cannot open Security log: {e}")
            return 0
        except AttributeError:
            print("[!] pywin32 missing EvtQuery. Upgrade: pip install --upgrade pywin32")
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
                        xml_str = win32evtlog.EvtRender(evt_handle, win32evtlog.EvtRenderEventXml)
                        if self._store_event_4688_xml(xml_str, cutoff):
                            count += 1
                    except Exception:
                        pass
        finally:
            try:
                win32evtlog.EvtClose(query_handle)
            except AttributeError:
                pass
        return count

    def _store_event_4688_xml(self, xml_str: str, cutoff: datetime) -> bool:
        try:
            root = ET.fromstring(xml_str)
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
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
            fields = {}
            for data in root.findall(f".//{ns}Data"):
                name = data.attrib.get("Name", "")
                if name:
                    fields[name] = (data.text or "").strip()
            def _parse_pid(val: str) -> int:
                try:
                    return int(val, 16) if val.startswith("0x") else int(val)
                except:
                    return 0
            new_pid = _parse_pid(fields.get("NewProcessId", "0"))
            parent_pid = _parse_pid(fields.get("ProcessId", "0"))
            proc_path = fields.get("NewProcessName", "")
            proc_name = os.path.basename(proc_path)
            cmdline = fields.get("CommandLine", "")
            domain = fields.get("SubjectDomainName", "")
            user = fields.get("SubjectUserName", "")
            user_name = f"{domain}\\{user}" if user else ""
            self.conn.execute("""
                INSERT OR IGNORE INTO process_events
                    (pid, parent_pid, process_name, process_path, command_line, user_name, event_time, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, 4688)
            """, (new_pid, parent_pid, proc_name, proc_path, cmdline, user_name, event_dt.isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print(f"4688 store error: {e}")
            return False

    # ── WRITER LOOKUP (Sysmon first, then 4688) ────────────────
    def _find_writer(self, entry: dict) -> dict | None:
        reg_path = entry["reg_path"]
        value_name = entry["name"]
        # Sysmon exact match (case‑insensitive)
        row = self.conn.execute("""
            SELECT sre.pid, sre.process_path, sre.process_name, sre.event_time,
                   spe.parent_pid, spe.command_line, spe.user_name
            FROM sysmon_registry_events sre
            LEFT JOIN sysmon_process_events spe ON sre.pid = spe.pid
            WHERE LOWER(sre.key_path) = LOWER(?) AND LOWER(sre.value_name) = LOWER(?)
            ORDER BY sre.event_time DESC
            LIMIT 1
        """, (reg_path, value_name)).fetchone()
        if row:
            result = dict(row)
            result["writer_source"] = "sysmon_exact"
            return result

        # Fallback to 4688 logic (original)
        value_data = entry.get("value_data") or ""
        exe_token = value_data.strip().split()[0] if value_data.strip() else ""
        exe_path = exe_token.strip('"')
        exe_name = os.path.basename(exe_path)
        if not exe_name:
            return None
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE LOWER(process_name) = LOWER(?)
            ORDER BY event_time DESC
            LIMIT 1
        """, (exe_name,)).fetchone()
        if row:
            result = dict(row)
            result["writer_source"] = "4688"
            return result
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE LOWER(process_name) LIKE ?
            ORDER BY event_time DESC
            LIMIT 1
        """, (f"%{exe_name.lower()}%",)).fetchone()
        if row:
            result = dict(row)
            result["writer_source"] = "4688"
            return result
        REGISTRY_WRITERS = ("reg.exe", "powershell.exe", "cmd.exe", "regedit.exe", "regini.exe", "python.exe", "pwsh.exe", "wscript.exe", "cscript.exe")
        for tool in REGISTRY_WRITERS:
            row = self.conn.execute("""
                SELECT * FROM process_events
                WHERE LOWER(process_name) = ?
                  AND (LOWER(command_line) LIKE ? OR LOWER(command_line) LIKE ?)
                ORDER BY event_time DESC
                LIMIT 1
            """, (tool, f"%{value_name.lower()}%", f"%{exe_path.lower()}%")).fetchone()
            if row:
                result = dict(row)
                result["writer_source"] = f"4688-indirect({tool})"
                return result
        return None

    # ── ATTACK CHAIN BUILDER (unchanged but uses _find_writer) ──
    SYSTEM_PROCS = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe"}
    SYSTEM_PIDS = {0, 4}
    MAX_DEPTH = 10

    def _find_parent(self, parent_pid: int, before: str) -> dict | None:
        # Try 4688 table first
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE pid = ? AND event_time < ?
            ORDER BY event_time DESC LIMIT 1
        """, (parent_pid, before)).fetchone()
        if row:
            return dict(row)
        # Then try sysmon_process_events
        row = self.conn.execute("""
            SELECT pid, parent_pid, process_name, process_path, command_line, user_name, event_time
            FROM sysmon_process_events
            WHERE pid = ? AND event_time < ?
            ORDER BY event_time DESC LIMIT 1
        """, (parent_pid, before)).fetchone()
        return dict(row) if row else None

    def build_attack_chain(self, reg_entry_id: int) -> list[dict]:
        entry = self.conn.execute("SELECT * FROM registry_entries WHERE id = ?", (reg_entry_id,)).fetchone()
        if not entry:
            return []
        entry = dict(entry)
        value = entry["value_data"] or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_name = os.path.basename(exe_token.strip('"'))
        writer = self._find_writer(entry)
        if not writer:
            placeholder = [{
                "pid": 0, "name": exe_name or "unknown.exe", "type": "unknown",
                "user": "unknown", "path": exe_token, "cmdline": value,
                "event_time": entry["last_seen"], "depth": 0, "source": "inferred",
                "techniques": tag_process(exe_name, value),
                "action": {"type": "reg", "label": f"Wrote {entry['hive']} → {entry['name']}"}
            }]
            self._save_chain(reg_entry_id, placeholder)
            return placeholder
        chain = []
        current = writer
        visited_pids = set()
        depth = 0
        while current and depth < self.MAX_DEPTH:
            pid = current["pid"]
            name = (current["process_name"] or "").lower()
            if pid in visited_pids:
                break
            if pid in self.SYSTEM_PIDS or name in self.SYSTEM_PROCS:
                chain.append(self._make_node(current, depth, is_writer=False))
                break
            visited_pids.add(pid)
            is_writer = (pid == writer["pid"])
            chain.append(self._make_node(current, depth, is_writer=is_writer, entry=entry if is_writer else None))
            parent_pid = current.get("parent_pid")
            if not parent_pid:
                break
            parent = self._find_parent(parent_pid, current["event_time"])
            if not parent:
                break
            current = parent
            depth += 1
        chain.reverse()
        for i, node in enumerate(chain):
            node["depth"] = i
        self._save_chain(reg_entry_id, chain)
        return chain

    def _make_node(self, proc: dict, depth: int, is_writer: bool, entry: dict | None = None) -> dict:
        proc_name = proc.get("process_name") or "unknown"
        cmdline = proc.get("command_line") or ""
        node = {
            "pid": proc.get("pid"), "name": proc_name,
            "type": self._classify_node(proc),
            "user": proc.get("user_name") or "",
            "path": proc.get("process_path") or "",
            "cmdline": cmdline,
            "event_time": proc.get("event_time") or "",
            "depth": depth,
            "source": proc.get("writer_source", "sysmon/4688"),
            "techniques": tag_process(proc_name, cmdline),
            "action": None,
        }
        if is_writer and entry:
            node["action"] = {
                "type": "reg",
                "label": f"Wrote {entry['hive']} → {entry['name']} = {entry['value_data'][:60]}"
            }
        return node

    def _save_chain(self, reg_entry_id: int, chain: list[dict]):
        self.conn.execute("INSERT OR REPLACE INTO attack_chains (reg_entry_id, chain_json, built_at) VALUES (?, ?, ?)",
                          (reg_entry_id, json.dumps(chain), datetime.now().isoformat()))
        self.conn.commit()

    def _classify_node(self, proc: dict) -> str:
        path = (proc.get("process_path") or "").lower()
        name = (proc.get("process_name") or "").lower()
        cmd = (proc.get("command_line") or "").lower()
        if proc.get("pid") in (4, 0):
            return "system"
        if name in ("system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe"):
            return "system"
        sev, _ = self._static_assess(path, cmd)
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

    # ── QUERIES (unchanged) ────────────────────────────────────
    def get_all_entries(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM registry_entries ORDER BY last_seen DESC").fetchall()
        entries = []
        for r in rows:
            e = dict(r)
            e["techniques"] = json.loads(e.get("techniques") or "[]")
            entries.append(e)
        return entries

    def get_entry(self, entry_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM registry_entries WHERE id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        e = dict(row)
        e["techniques"] = json.loads(e.get("techniques") or "[]")
        return e

    def get_chain(self, entry_id: int) -> list[dict]:
        row = self.conn.execute("SELECT chain_json FROM attack_chains WHERE reg_entry_id = ?", (entry_id,)).fetchone()
        if row:
            return json.loads(row["chain_json"])
        return self.build_attack_chain(entry_id)

    def get_stats(self) -> dict:
        rows = self.conn.execute("SELECT severity, COUNT(*) as cnt FROM registry_entries GROUP BY severity").fetchall()
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in rows:
            stats[r["severity"]] = r["cnt"]
        stats["total"] = sum(stats.values())
        stats["process_events"] = self.conn.execute("SELECT COUNT(*) FROM process_events").fetchone()[0]
        stats["sysmon_events"] = self.conn.execute("SELECT COUNT(*) FROM sysmon_registry_events").fetchone()[0] + \
                                 self.conn.execute("SELECT COUNT(*) FROM sysmon_process_events").fetchone()[0]
        return stats

    def close(self):
        self.conn.close()


# ── CLI ENTRYPOINT ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="RegHunt — Registry Persistence Collector (Sysmon enhanced)")
    parser.add_argument("--scan", action="store_true", help="Scan registry persistence keys")
    parser.add_argument("--events", action="store_true", help="Collect Event ID 4688 (fallback)")
    parser.add_argument("--sysmon", action="store_true", help="Collect Sysmon Event ID 13 and 1 (recommended)")
    parser.add_argument("--hours", type=int, default=72, help="Hours back to pull events")
    parser.add_argument("--chain", type=int, metavar="ID", help="Build attack chain for entry ID")
    parser.add_argument("--chain-all", action="store_true", help="Build chains for all High/Critical entries")
    parser.add_argument("--db", default="reghunt.db", help="Database path")
    args = parser.parse_args()

    col = RegistryCollector(db_path=args.db)

    if args.scan:
        print("[*] Scanning registry persistence keys...")
        entries = col.collect_registry()
        print(f"[+] Found {len(entries)} entries")
        for e in entries:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(e["severity"], "⚪")
            print(f"  {icon} [{e['severity'].upper():8}] {e['name']:40} → {e['value_data'][:60]}")

    if args.sysmon:
        print(f"\n[*] Collecting Sysmon events (last {args.hours}h)...")
        count = col.collect_sysmon_events(hours_back=args.hours)
        print(f"[+] Stored {count} Sysmon events (registry + process)")

    if args.events:
        print(f"\n[*] Collecting Security 4688 events (last {args.hours}h)...")
        count = col.collect_process_events(hours_back=args.hours)
        print(f"[+] Stored {count} 4688 events")

    if args.chain:
        print(f"\n[*] Building attack chain for entry ID {args.chain}...")
        chain = col.build_attack_chain(args.chain)
        if chain:
            print(f"[+] Chain depth: {len(chain)} nodes")
            for i, node in enumerate(chain):
                indent = "  " * i
                type_icon = {"system": "⚙️ ", "normal": "📦", "suspicious": "⚠️ ", "malicious": "💀", "unknown": "❓"}.get(node["type"], "❓")
                src_badge = f"[{node.get('source','?')}]"
                print(f"{indent}{type_icon} {node['name']} (PID {node['pid']}) {src_badge} — {node['user']}")
                if node.get("action"):
                    print(f"{indent}   ↳ {node['action']['label']}")
                if node.get("techniques"):
                    techs = ", ".join(t['id'] for t in node['techniques'])
                    print(f"{indent}   📌 {techs}")
        else:
            print("[!] No chain found.")

    if args.chain_all:
        print(f"\n[*] Building chains for all High/Critical entries...")
        rows = col.conn.execute("SELECT id, name, severity FROM registry_entries WHERE severity IN ('high','critical') ORDER BY severity DESC, id").fetchall()
        print(f"[+] Found {len(rows)} High/Critical entries")
        for row in rows:
            print(f"\n  --- Entry {row['id']}: {row['name']} [{row['severity'].upper()}] ---")
            chain = col.build_attack_chain(row['id'])
            if chain:
                for i, node in enumerate(chain):
                    indent = "    " + "  " * i
                    type_icon = {"system": "⚙️ ", "normal": "📦", "suspicious": "⚠️ ", "malicious": "💀", "unknown": "❓"}.get(node["type"], "❓")
                    src_badge = f"[{node.get('source','?')}]"
                    print(f"{indent}{type_icon} {node['name']} (PID {node['pid']}) {src_badge} — {node['user']}")
                    if node.get("action"):
                        print(f"{indent}   ↳ {node['action']['label']}")
            else:
                print("    [!] No chain")

    stats = col.get_stats()
    print(f"\n[*] DB Stats: {stats['total']} entries | 4688 events: {stats['process_events']} | Sysmon events: {stats['sysmon_events']}")
    print(f"    Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}")
    col.close()