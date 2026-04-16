"""
registry_collector.py
Collects registry persistence entries from Run/RunOnce keys.
Correlates with:
  - Sysmon Event 13 (RegistryValueSet) and Event 1 (ProcessCreate) [preferred]
  - Event ID 4688 process creation logs [fallback]
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
    if not hasattr(win32evtlog, 'EvtQuery'):
        print("[!] pywin32 too old. Upgrade: pip install --upgrade pywin32")
        PYWIN32_AVAILABLE = False
except ImportError:
    PYWIN32_AVAILABLE = False
    print("[!] pywin32 not installed. Event log correlation disabled.")

DEBUG = os.environ.get("REGHUNT_DEBUG", "").lower() in ("1", "true", "yes")
def debug_print(*args, **kwargs):
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

PERSISTENCE_KEYS = [
    {"hive": winreg.HKEY_LOCAL_MACHINE, "hive_name": "HKLM", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "key_type": "Run"},
    {"hive": winreg.HKEY_CURRENT_USER,  "hive_name": "HKCU", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "key_type": "Run"},
    {"hive": winreg.HKEY_LOCAL_MACHINE, "hive_name": "HKLM", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "key_type": "RunOnce"},
    {"hive": winreg.HKEY_CURRENT_USER,  "hive_name": "HKCU", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "key_type": "RunOnce"},
]

KNOWN_LEGIT_PATHS = [r"c:\windows\system32", r"c:\windows\syswow64"]
SUSPICIOUS_PATHS = [r"c:\users\public", r"c:\temp", r"\appdata\roaming", r"\downloads"]
SUSPICIOUS_NAME_PATTERNS = ["fake", "malware", "backdoor", "payload", "implant", "totally_not"]
_ROOT_EXE_RE = re.compile(r'^[a-zA-Z]:\\[^\\]+\.exe$', re.IGNORECASE)
LOLBINS = ["powershell.exe", "cmd.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"]

MITRE_REG_TECHNIQUES = [(r"currentversion\run", "T1547.001", "Boot/Logon Autostart")]
MITRE_PROC_TECHNIQUES = [("powershell.exe", "T1059.001", "PowerShell"), ("cmd.exe", "T1059.003", "Command Shell")]
MITRE_CMD_TECHNIQUES = [("-enc", "T1027", "Obfuscated"), ("http://", "T1105", "Ingress Tool Transfer")]

def tag_registry(hive: str, reg_path: str) -> list[dict]:
    combined = (hive + "\\" + reg_path).lower()
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
                return "HKU\\" + sid + "\\" + remainder
            return "HKCU\\" + remainder
        return "HKCU\\" + rest
    if upper.startswith("HKU\\"):
        parts = p.split("\\", 2)
        if len(parts) >= 3:
            sid = parts[1].upper()
            if sid in (".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"):
                return "HKU\\" + parts[1] + "\\" + parts[2]
            return "HKCU\\" + parts[2]
    if upper.startswith("HKEY_LOCAL_MACHINE\\"):
        return "HKLM\\" + p[19:]
    if upper.startswith("HKEY_CURRENT_USER\\"):
        return "HKCU\\" + p[18:]
    return p

class RegistryCollector:
    DEFAULT_HOURS = 24
    MAX_HOURS = 720

    def __init__(self, db_path: str = "reghunt.db", collection_hours: int = None):
        self.db_path = db_path
        self.collection_hours = collection_hours or self.DEFAULT_HOURS
        self.conn = self._init_db()

    def _init_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS registry_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                hive TEXT NOT NULL,
                reg_path TEXT NOT NULL,
                value_data TEXT,
                severity TEXT DEFAULT 'unknown',
                ioc_notes TEXT,
                techniques TEXT DEFAULT '[]',
                first_seen TEXT,
                last_seen TEXT,
                hash_id TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER,
                parent_pid INTEGER,
                process_name TEXT,
                process_path TEXT,
                command_line TEXT,
                user_name TEXT,
                event_time TEXT,
                event_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS sysmon_process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER,
                parent_pid INTEGER,
                process_name TEXT,
                process_path TEXT,
                command_line TEXT,
                user_name TEXT,
                hashes TEXT,
                integrity_level TEXT,
                event_time TEXT,
                event_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS sysmon_registry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER,
                process_name TEXT,
                process_path TEXT,
                event_time TEXT,
                key_path TEXT,
                value_name TEXT,
                value_data TEXT,
                event_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reg_entry_id INTEGER,
                chain_json TEXT,
                built_at TEXT,
                FOREIGN KEY(reg_entry_id) REFERENCES registry_entries(id)
            );
            CREATE INDEX IF NOT EXISTS idx_proc_pid ON process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_proc_ppid ON process_events(parent_pid);
            CREATE INDEX IF NOT EXISTS idx_proc_time ON process_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_sysmon_reg_key ON sysmon_registry_events(key_path, value_name);
            CREATE INDEX IF NOT EXISTS idx_sysmon_reg_pid ON sysmon_registry_events(pid);
            CREATE INDEX IF NOT EXISTS idx_sysmon_proc_pid ON sysmon_process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_sysmon_proc_ppid ON sysmon_process_events(parent_pid);
            CREATE INDEX IF NOT EXISTS idx_sysmon_proc_time ON sysmon_process_events(event_time);
        """)
        conn.commit()

        reg_cols = {r[1] for r in conn.execute("PRAGMA table_info(registry_entries)")}
        if "techniques" not in reg_cols:
            conn.execute("ALTER TABLE registry_entries ADD COLUMN techniques TEXT DEFAULT '[]'")
            conn.commit()
        return conn

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
                    full_path = key_info['hive_name'] + "\\" + key_info['path']
                    data_str = str(data)
                    severity, ioc = self._assess_severity(name, data_str)
                    hash_id = hashlib.md5((full_path + "|" + name + "|" + data_str).encode()).hexdigest()
                    now = datetime.now().isoformat()
                    entry = {
                        "name": name, 
                        "hive": key_info['hive_name'] + "\\" + key_info['key_type'],
                        "reg_path": full_path, 
                        "value_data": data_str, 
                        "severity": severity,
                        "ioc_notes": ioc, 
                        "techniques": json.dumps(tag_registry(key_info['hive_name'] + "\\" + key_info['key_type'], full_path)),
                        "first_seen": now, 
                        "last_seen": now, 
                        "hash_id": hash_id,
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
                    sub_info = {**key_info, "path": key_info['path'] + "\\" + subkey_name}
                    entries.extend(self._read_key(sub_info))
                    j += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)
        return entries

    def _assess_severity(self, name: str, value: str) -> tuple[str, str]:
        value_lower = value.lower()
        if any(p in value_lower for p in ["http://", "https://"]):
            return "critical", "Remote URL in registry value"
        for lol in LOLBINS:
            if lol in value_lower:
                sus_flags = [" -enc", " -nop", "bypass", "hidden", "iex("]
                if any(f in value_lower for f in sus_flags):
                    return "critical", "LOLBin with suspicious flags: " + lol
        for pat in SUSPICIOUS_NAME_PATTERNS:
            if pat in value_lower or pat in name.lower():
                return "critical", "Suspicious filename: " + pat
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in value_lower:
                return "high", "Executable in suspicious path"
        if value_lower.startswith(r"c:\windows\system32") or value_lower.startswith(r"c:\windows\syswow64"):
            return "low", "System path"
        return "medium", "Manual review recommended"

    def _upsert_entry(self, entry: dict):
        self.conn.execute("""
            INSERT INTO registry_entries
                (name, hive, reg_path, value_data, severity, ioc_notes, techniques, first_seen, last_seen, hash_id)
            VALUES (:name, :hive, :reg_path, :value_data, :severity, :ioc_notes, :techniques, :first_seen, :last_seen, :hash_id)
            ON CONFLICT(hash_id) DO UPDATE SET
                severity = excluded.severity, ioc_notes = excluded.ioc_notes,
                techniques = excluded.techniques, last_seen = excluded.last_seen
        """, entry)
        self.conn.commit()

    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def collect_sysmon_events(self, hours_back: int = None) -> int:
        if hours_back is None:
            hours_back = self.collection_hours
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available")
            return 0
        ms_back = hours_back * 3600000
        cutoff = datetime.utcnow() - timedelta(hours=hours_back)
        reg_count = self._collect_sysmon_registry_events(ms_back, cutoff)
        proc_count = self._collect_sysmon_process_events(ms_back, cutoff)
        return reg_count + proc_count

    def _collect_sysmon_registry_events(self, ms_back: int, cutoff: datetime) -> int:
        xpath = "*[System[EventID=13 and TimeCreated[timediff(@SystemTime) <= " + str(ms_back) + "]]]"
        count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None
            )
        except pywintypes.error as e:
            if e.args[0] == 2:
                print("[!] Sysmon not installed")
            else:
                print("[!] Cannot open Sysmon log: " + str(e))
            return 0
        except AttributeError:
            print("[!] pywin32 missing EvtQuery")
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
                        debug_print("Error rendering event:", e)
        finally:
            try:
                win32evtlog.EvtClose(query_handle)
            except AttributeError:
                pass
        return count

    def _store_sysmon_registry_event(self, xml_str: str, cutoff: datetime) -> bool:
        try:
            root = ET.fromstring(xml_str)
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            tc = root.find(".//" + ns + "TimeCreated")
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
            for data in root.findall(".//" + ns + "Data"):
                name = data.attrib.get("Name", "")
                if name:
                    data_dict[name] = (data.text or "").strip()

            key_path = data_dict.get("TargetObject", "")
            if not key_path:
                return False

            key_path_norm = normalise_reg_path(key_path)
            value_name = ""
            if "\\" in key_path_norm:
                parts = key_path_norm.split("\\")
                value_name = parts[-1]
                key_path_norm = "\\".join(parts[:-1])

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
            debug_print("Error storing registry event:", e)
            return False

    def _collect_sysmon_process_events(self, ms_back: int, cutoff: datetime) -> int:
        xpath = "*[System[EventID=1 and TimeCreated[timediff(@SystemTime) <= " + str(ms_back) + "]]]"
        count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None
            )
        except (pywintypes.error, AttributeError):
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
            tc = root.find(".//" + ns + "TimeCreated")
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
            for data in root.findall(".//" + ns + "Data"):
                name = data.attrib.get("Name", "")
                if name:
                    data_dict[name] = (data.text or "").strip()

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
            debug_print("Error storing process event:", e)
            return False

    def collect_process_events(self, hours_back: int = None) -> int:
        if hours_back is None:
            hours_back = self.collection_hours
        if not PYWIN32_AVAILABLE:
            return 0
        ms_back = hours_back * 3600000
        cutoff = datetime.utcnow() - timedelta(hours=hours_back)
        xpath = "*[System[EventID=4688 and TimeCreated[timediff(@SystemTime) <= " + str(ms_back) + "]]]"
        count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                "Security",
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None
            )
        except pywintypes.error as e:
            if e.args[0] == 5:
                print("[!] Access denied reading Security log")
            else:
                print("[!] Cannot open Security log:", e)
            return 0
        except AttributeError:
            print("[!] pywin32 missing EvtQuery")
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
            tc = root.find(".//" + ns + "TimeCreated")
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
            for data in root.findall(".//" + ns + "Data"):
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
            user_name = domain + "\\" + user if user else ""
            
            self.conn.execute("""
                INSERT OR IGNORE INTO process_events
                    (pid, parent_pid, process_name, process_path, command_line, user_name, event_time, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, 4688)
            """, (new_pid, parent_pid, proc_name, proc_path, cmdline, user_name, event_dt.isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print("4688 store error:", e)
            return False

    def _find_writer(self, entry: dict) -> dict | None:
        reg_path = entry["reg_path"]
        value_name = entry["name"]
        
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

        value_data = entry.get("value_data") or ""
        exe_token = value_data.strip().split()[0] if value_data.strip() else ""
        exe_path = exe_token.strip('"')
        exe_name = os.path.basename(exe_path)
        
        if not exe_name:
            return self._create_unknown_writer(entry)
            
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
        """, ("%" + exe_name.lower() + "%",)).fetchone()
        
        if row:
            result = dict(row)
            result["writer_source"] = "4688"
            return result
            
        REGISTRY_WRITERS = ("reg.exe", "powershell.exe", "cmd.exe", "regedit.exe", "regini.exe", 
                           "python.exe", "pwsh.exe", "wscript.exe", "cscript.exe")
        for tool in REGISTRY_WRITERS:
            row = self.conn.execute("""
                SELECT * FROM process_events
                WHERE LOWER(process_name) = ?
                  AND (LOWER(command_line) LIKE ? OR LOWER(command_line) LIKE ?)
                ORDER BY event_time DESC
                LIMIT 1
            """, (tool, "%" + value_name.lower() + "%", "%" + exe_path.lower() + "%")).fetchone()
            if row:
                result = dict(row)
                result["writer_source"] = "4688-indirect(" + tool + ")"
                return result
        
        return self._create_unknown_writer(entry)

    def _create_unknown_writer(self, entry: dict) -> dict:
        value = entry.get("value_data") or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_path = exe_token.strip('"')
        exe_name = os.path.basename(exe_path) if exe_path else "unknown.exe"
        
        return {
            "pid": None,
            "process_name": exe_name,
            "process_path": exe_path or "unknown",
            "command_line": value,
            "user_name": None,
            "event_time": entry.get("last_seen"),
            "parent_pid": None,
            "writer_source": "unknown",
            "unknown_reason": self._diagnose_unknown(entry)
        }

    def _diagnose_unknown(self, entry: dict) -> str:
        if not PYWIN32_AVAILABLE:
            return "pywin32 not available"
        
        first_seen = entry.get("first_seen")
        if first_seen:
            try:
                fs = datetime.fromisoformat(first_seen)
                cutoff = datetime.utcnow() - timedelta(hours=self.collection_hours)
                if fs < cutoff:
                    return "Entry created before monitoring window (" + str(self.collection_hours) + "h)"
            except:
                pass
        
        if entry.get("hive", "").startswith("HKLM"):
            return "System hive entry"
        
        sysmon_count = self.conn.execute("SELECT COUNT(*) FROM sysmon_registry_events").fetchone()[0]
        if sysmon_count == 0:
            return "No Sysmon events in database"
        
        return "No matching event log entry found"

    SYSTEM_PROCS = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", 
                    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe"}
    SYSTEM_PIDS = {0, 4}
    MAX_DEPTH = 10

    def _find_parent(self, parent_pid: int, before: str) -> dict | None:
        if not parent_pid or parent_pid == 0:
            return None
        
        best_match = None
        best_time = None
        
        row = self.conn.execute("""
            SELECT pid, parent_pid, process_name, process_path, command_line, user_name, event_time
            FROM sysmon_process_events
            WHERE pid = ? AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, (parent_pid, before)).fetchone()
        
        if row:
            best_match = dict(row)
            best_match["_source_table"] = "sysmon"
            best_time = row["event_time"]
        
        row = self.conn.execute("""
            SELECT pid, parent_pid, process_name, process_path, command_line, user_name, event_time
            FROM process_events
            WHERE pid = ? AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, (parent_pid, before)).fetchone()
        
        if row:
            if best_time is None or row["event_time"] > best_time:
                best_match = dict(row)
                best_match["_source_table"] = "4688"
        
        return best_match

    def build_attack_chain(self, reg_entry_id: int) -> list[dict]:
        entry = self.conn.execute("SELECT * FROM registry_entries WHERE id = ?", (reg_entry_id,)).fetchone()
        if not entry:
            return []
        entry = dict(entry)
        
        writer = self._find_writer(entry)
        
        if writer.get("writer_source") == "unknown":
            chain = [self._make_node(writer, 0, is_writer=True, entry=entry)]
            self._save_chain(reg_entry_id, chain)
            return chain
        
        chain_nodes = []
        visited_pids = set()
        current = writer
        depth = 0
        
        while current and depth < self.MAX_DEPTH:
            pid = current.get("pid")
            name = (current.get("process_name") or "").lower()
            
            if pid in visited_pids:
                break
            
            visited_pids.add(pid)
            is_writer = (depth == 0)
            
            if pid in self.SYSTEM_PIDS or name in self.SYSTEM_PROCS:
                chain_nodes.append(self._make_node(current, depth, is_writer=is_writer, entry=entry if is_writer else None))
                break
            
            chain_nodes.append(self._make_node(current, depth, is_writer=is_writer, entry=entry if is_writer else None))
            
            parent_pid = current.get("parent_pid")
            parent_time = current.get("event_time")
            
            if not parent_pid or not parent_time:
                break
            
            parent = self._find_parent(parent_pid, parent_time)
            if not parent:
                break
            
            current = parent
            depth += 1
        
        chain_nodes.reverse()
        
        for i, node in enumerate(chain_nodes):
            node["depth"] = i
        
        self._save_chain(reg_entry_id, chain_nodes)
        return chain_nodes

    def _make_node(self, proc: dict, depth: int, is_writer: bool, entry: dict | None = None) -> dict:
        proc_name = proc.get("process_name") or "unknown"
        cmdline = proc.get("command_line") or ""
        pid = proc.get("pid")
        source = proc.get("writer_source", "sysmon/4688")
        
        if source == "unknown":
            return {
                "pid": None,
                "name": proc_name,
                "type": "unknown",
                "user": proc.get("user_name") or "unknown",
                "path": proc.get("process_path") or "unknown",
                "cmdline": cmdline,
                "event_time": proc.get("event_time") or "",
                "depth": depth,
                "source": "unknown",
                "unknown_reason": proc.get("unknown_reason", "No event log data"),
                "techniques": tag_process(proc_name, cmdline),
                "action": {"type": "reg", "label": "Wrote " + entry['hive'] + " -> " + entry['name']} if entry else None,
            }
        
        node = {
            "pid": pid,
            "name": proc_name,
            "type": self._classify_node(proc),
            "user": proc.get("user_name") or "",
            "path": proc.get("process_path") or "",
            "cmdline": cmdline,
            "event_time": proc.get("event_time") or "",
            "depth": depth,
            "source": source,
            "techniques": tag_process(proc_name, cmdline),
            "action": None,
        }
        
        if is_writer and entry:
            node["action"] = {
                "type": "reg",
                "label": "Wrote " + entry['hive'] + " -> " + entry['name'] + " = " + entry['value_data'][:60]
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
        pid = proc.get("pid")
        
        if pid in (4, 0) or name in ("system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe"):
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
                return "high", "Suspicious path: " + sus
        for lol in LOLBINS:
            if lol in cmd:
                if any(x in cmd for x in ["-enc", "-nop", "bypass", "hidden", "http"]):
                    return "critical", "LOLBin + suspicious flags: " + lol
        if "http://" in cmd or "https://" in cmd:
            return "critical", "Remote URL in command"
        return "low", ""

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
        stats["sysmon_events"] = self.conn.execute("SELECT COUNT(*) FROM sysmon_registry_events").fetchone()[0] + self.conn.execute("SELECT COUNT(*) FROM sysmon_process_events").fetchone()[0]
        return stats

    def close(self):
        self.conn.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="RegHunt - Registry Persistence Collector")
    parser.add_argument("--scan", action="store_true", help="Scan registry persistence keys")
    parser.add_argument("--events", action="store_true", help="Collect Event ID 4688")
    parser.add_argument("--sysmon", action="store_true", help="Collect Sysmon events")
    parser.add_argument("--hours", type=int, default=RegistryCollector.DEFAULT_HOURS, help="Hours back (default: 24)")
    parser.add_argument("--chain", type=int, metavar="ID", help="Build attack chain for entry ID")
    parser.add_argument("--chain-all", action="store_true", help="Build chains for all High/Critical entries")
    parser.add_argument("--db", default="reghunt.db", help="Database path")
    args = parser.parse_args()

    if args.hours > RegistryCollector.MAX_HOURS:
        print("[!] Capping --hours to " + str(RegistryCollector.MAX_HOURS))
        args.hours = RegistryCollector.MAX_HOURS
    elif args.hours < 1:
        print("[!] Setting --hours to 1")
        args.hours = 1

    col = RegistryCollector(db_path=args.db, collection_hours=args.hours)

    if args.scan:
        print("[*] Scanning registry persistence keys...")
        entries = col.collect_registry()
        print("[+] Found " + str(len(entries)) + " entries")
        for e in entries:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(e["severity"], "⚪")
            print("  " + icon + " [" + e['severity'].upper() + "] " + e['name'][:40].ljust(40) + " -> " + e['value_data'][:60])

    if args.sysmon:
        print("[*] Collecting Sysmon events (last " + str(args.hours) + "h)...")
        count = col.collect_sysmon_events()
        print("[+] Stored " + str(count) + " Sysmon events")

    if args.events:
        print("[*] Collecting Security 4688 events (last " + str(args.hours) + "h)...")
        count = col.collect_process_events()
        print("[+] Stored " + str(count) + " 4688 events")

    if args.chain:
        print("[*] Building attack chain for entry ID " + str(args.chain) + "...")
        chain = col.build_attack_chain(args.chain)
        if chain:
            print("[+] Chain depth: " + str(len(chain)) + " nodes")
            for i, node in enumerate(chain):
                indent = "  " * i
                type_icon = {"system": "⚙️", "normal": "📦", "suspicious": "⚠️", "malicious": "💀", "unknown": "❓"}.get(node["type"], "❓")
                if node.get("source") == "unknown":
                    print(indent + type_icon + " " + node['name'] + " (PID unknown) [unknown]")
                    if node.get("unknown_reason"):
                        print(indent + "   ⚠️  " + node['unknown_reason'])
                else:
                    src_badge = "[" + node.get('source', '?') + "]"
                    print(indent + type_icon + " " + node['name'] + " (PID " + str(node['pid']) + ") " + src_badge + " - " + node['user'])
                if node.get("action"):
                    print(indent + "   -> " + node['action']['label'])
                if node.get("techniques"):
                    techs = ", ".join(t['id'] for t in node['techniques'])
                    print(indent + "   📌 " + techs)
        else:
            print("[!] No chain found.")

    if args.chain_all:
        print("[*] Building chains for all High/Critical entries...")
        rows = col.conn.execute("SELECT id, name, severity FROM registry_entries WHERE severity IN ('high','critical') ORDER BY severity DESC, id").fetchall()
        print("[+] Found " + str(len(rows)) + " High/Critical entries")
        for row in rows:
            print("")
            print("--- Entry " + str(row['id']) + ": " + row['name'] + " [" + row['severity'].upper() + "] ---")
            chain = col.build_attack_chain(row['id'])
            if chain:
                for i, node in enumerate(chain):
                    indent = "    " + "  " * i
                    type_icon = {"system": "⚙️", "normal": "📦", "suspicious": "⚠️", "malicious": "💀", "unknown": "❓"}.get(node["type"], "❓")
                    if node.get("source") == "unknown":
                        print(indent + type_icon + " " + node['name'] + " (PID unknown) [unknown]")
                        if node.get("unknown_reason"):
                            print(indent + "   ⚠️  " + node['unknown_reason'])
                    else:
                        src_badge = "[" + node.get('source', '?') + "]"
                        print(indent + type_icon + " " + node['name'] + " (PID " + str(node['pid']) + ") " + src_badge + " - " + node['user'])
                    if node.get("action"):
                        print(indent + "   -> " + node['action']['label'])
                    if node.get("techniques"):
                        techs = ", ".join(t['id'] for t in node['techniques'])
                        print(indent + "   📌 " + techs)
            else:
                print("    [!] No chain")

    stats = col.get_stats()
    print("")
    print("[*] DB Stats: " + str(stats['total']) + " entries | 4688: " + str(stats['process_events']) + " | Sysmon: " + str(stats['sysmon_events']))
    print("    Critical: " + str(stats['critical']) + " | High: " + str(stats['high']) + " | Medium: " + str(stats['medium']) + " | Low: " + str(stats['low']))
    col.close()