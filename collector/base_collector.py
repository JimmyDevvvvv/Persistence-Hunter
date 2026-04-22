"""
base_collector.py
Shared foundation for all Persistence-Hunter collectors.
Provides: DB init, severity scoring, MITRE tagging, color output,
          event log ingestion (Sysmon + 4688), and chain building.
"""

import os
import re
import json
import sqlite3
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

try:
    import win32evtlog
    import pywintypes
    PYWIN32_AVAILABLE = True
    if not hasattr(win32evtlog, "EvtQuery"):
        print("[!] pywin32 too old. Upgrade: pip install --upgrade pywin32")
        PYWIN32_AVAILABLE = False
except ImportError:
    PYWIN32_AVAILABLE = False
    print("[!] pywin32 not installed. Event log correlation disabled.")

DEBUG = os.environ.get("REGHUNT_DEBUG", "").lower() in ("1", "true", "yes")

def debug_print(*args, **kwargs):
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)


# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

class Colors:
    GREY    = "\033[90m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @classmethod
    def disable(cls):
        cls.GREY = cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ""
        cls.MAGENTA = cls.CYAN = cls.WHITE = cls.BOLD = cls.DIM = cls.RESET = ""

if os.name == "nt" and not os.environ.get("TERM"):
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        Colors.disable()


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

KNOWN_LEGIT_PATHS      = [r"c:\windows\system32", r"c:\windows\syswow64"]
SUSPICIOUS_PATHS       = [
    r"c:\users\public",
    r"c:\temp",
    r"c:\windows\temp",   # added — malware frequently drops here
    r"\appdata\roaming",
    r"\appdata\local\temp",
    r"\downloads",
    r"c:\malware",
    r"c:\perflogs",       # rarely legitimate, used by some malware
]
SUSPICIOUS_NAME_PATTERNS = ["fake", "malware", "backdoor", "payload",
                             "implant", "totally_not", "ph_",
                             "svcupdate", "svchost32", "lsass32",  # service name mimicry
                             "windowsupdate", "winupdate"]
LOLBINS = [
    "powershell.exe", "cmd.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "wscript.exe", "cscript.exe", "reg.exe",
    # extended LOLBins
    "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "odbcconf.exe", "ieexec.exe", "pcalua.exe", "msbuild.exe",
    "cmstp.exe", "xwizard.exe", "forfiles.exe", "scriptrunner.exe",
]

MITRE_REG_TECHNIQUES = [
    (r"currentversion\run",   "T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
    (r"currentversion\runonce","T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
]
MITRE_TASK_TECHNIQUES = [
    ("schtasks",   "T1053.005", "Scheduled Task/Job: Scheduled Task"),
    ("at.exe",     "T1053.002", "Scheduled Task/Job: At"),
]
MITRE_SVC_TECHNIQUES = [
    ("services",   "T1543.003", "Create or Modify System Process: Windows Service"),
]
MITRE_PROC_TECHNIQUES = [
    ("powershell.exe",    "T1059.001", "PowerShell"),
    ("cmd.exe",           "T1059.003", "Command Shell"),
    ("wscript.exe",       "T1059.005", "VBScript"),
    ("cscript.exe",       "T1059.005", "VBScript"),
    ("mshta.exe",         "T1218.005", "Mshta"),
    ("regsvr32.exe",      "T1218.010", "Regsvr32"),
    ("rundll32.exe",      "T1218.011", "Rundll32"),
    ("certutil.exe",      "T1140",     "Deobfuscate/Decode via Certutil"),
    ("reg.exe",           "T1112",     "Registry Modification"),
    ("schtasks.exe",      "T1053.005", "Scheduled Task"),
    ("sc.exe",            "T1543.003", "Service Control"),
    ("msiexec.exe",       "T1218.007", "Msiexec LOLBin"),
    ("installutil.exe",   "T1218.004", "InstallUtil LOLBin"),
    ("regasm.exe",        "T1218.009", "Regasm LOLBin"),
    ("regsvcs.exe",       "T1218.009", "Regsvcs LOLBin"),
    ("odbcconf.exe",      "T1218.008", "Odbcconf LOLBin"),
    ("msbuild.exe",       "T1127.001", "MSBuild LOLBin"),
    ("cmstp.exe",         "T1218.003", "CMSTP LOLBin"),
    ("forfiles.exe",      "T1218",     "Forfiles LOLBin"),
]
MITRE_CMD_TECHNIQUES = [
    ("-enc",              "T1027",     "Obfuscated Command"),
    ("-encodedcommand",   "T1027",     "Obfuscated Command"),
    ("invoke-expression", "T1059.001", "PowerShell IEX"),
    ("iex(",              "T1059.001", "PowerShell IEX"),
    ("bypass",            "T1562.001", "Execution Policy Bypass"),
    ("-nop",              "T1562.001", "NoProfile Flag"),
    ("http://",           "T1105",     "Ingress Tool Transfer"),
    ("https://",          "T1105",     "Ingress Tool Transfer"),
]


# ---------------------------------------------------------------------------
# MITRE tagging helpers
# ---------------------------------------------------------------------------

def tag_registry(hive: str, reg_path: str) -> list[dict]:
    combined = (hive + "\\" + reg_path).lower()
    seen, tags = set(), []
    for fragment, tid, tname in MITRE_REG_TECHNIQUES:
        if fragment in combined and tid not in seen:
            seen.add(tid)
            tags.append({"id": tid, "name": tname})
    return tags

def tag_task(_name: str) -> list[dict]:
    return [{"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task"}]

def tag_service(_name: str) -> list[dict]:
    return [{"id": "T1543.003", "name": "Create or Modify System Process: Windows Service"}]

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


# ---------------------------------------------------------------------------
# Registry path normaliser (used by registry collector + event ingestion)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Severity assessment (shared across all collectors)
# ---------------------------------------------------------------------------

def assess_severity(name: str, value: str) -> tuple[str, str]:
    """Return (severity, ioc_note) for a persistence entry."""
    value_lower = value.lower()
    name_lower  = name.lower()

    if any(p in value_lower for p in ["http://", "https://"]):
        return "critical", "Remote URL in persistence value"

    for lol in LOLBINS:
        if lol in value_lower:
            sus_flags = [" -enc", " -nop", "bypass", "hidden", "iex("]
            if any(f in value_lower for f in sus_flags):
                return "critical", "LOLBin with suspicious flags: " + lol

    for pat in SUSPICIOUS_NAME_PATTERNS:
        if pat in value_lower or pat in name_lower:
            return "critical", "Suspicious name pattern: " + pat

    for sus_path in SUSPICIOUS_PATHS:
        if sus_path in value_lower:
            return "high", "Executable in suspicious path: " + sus_path

    if (value_lower.startswith(r"c:\windows\system32") or
            value_lower.startswith(r"c:\windows\syswow64")):
        return "low", "System path"

    return "medium", "Manual review recommended"

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


# ---------------------------------------------------------------------------
# Base collector — DB + event ingestion + chain building
# ---------------------------------------------------------------------------

class BaseCollector:
    DEFAULT_HOURS = 24
    MAX_HOURS     = 720
    MAX_DEPTH     = 15

    # Hard system boundary — append and stop, never walk past these
    SYSTEM_PROCS = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "System",
    }
    # Natural user-session roots — append and stop (these are the A in A->Z)
    SHELL_PROCS = {
        "explorer.exe", "userinit.exe", "dwm.exe",
        "taskhostw.exe", "sihost.exe", "runtimebroker.exe",
        "searchhost.exe", "startmenuexperiencehost.exe",
    }
    # svchost.exe: stop walking upward past it (services.exe is its parent, not interesting)
    SVCHOST_BOUNDARY = {"svchost.exe"}

    SYSTEM_PIDS  = {0, 4}
    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self, db_path: str = "reghunt.db", collection_hours: int = None):
        self.db_path          = db_path
        self.collection_hours = collection_hours or self.DEFAULT_HOURS
        self.conn             = self._init_db()

    # ------------------------------------------------------------------
    # DB initialisation
    # ------------------------------------------------------------------

    def _init_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            -- Shared process event tables
            CREATE TABLE IF NOT EXISTS process_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                pid          INTEGER,
                parent_pid   INTEGER,
                process_name TEXT,
                process_path TEXT,
                command_line TEXT,
                user_name    TEXT,
                event_time   TEXT,
                event_id     INTEGER
            );
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
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                pid          INTEGER,
                process_name TEXT,
                process_path TEXT,
                event_time   TEXT,
                key_path     TEXT,
                value_name   TEXT,
                value_data   TEXT,
                event_id     INTEGER
            );

            -- Registry persistence
            CREATE TABLE IF NOT EXISTS registry_entries (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                hive       TEXT NOT NULL,
                reg_path   TEXT NOT NULL,
                value_data TEXT,
                severity   TEXT DEFAULT 'unknown',
                ioc_notes  TEXT,
                techniques TEXT DEFAULT '[]',
                first_seen TEXT,
                last_seen  TEXT,
                hash_id    TEXT UNIQUE
            );

            -- Scheduled task persistence
            CREATE TABLE IF NOT EXISTS task_entries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                task_name    TEXT NOT NULL,
                task_path    TEXT NOT NULL,
                command      TEXT,
                arguments    TEXT,
                run_as       TEXT,
                trigger_type TEXT,
                enabled      INTEGER DEFAULT 1,
                severity     TEXT DEFAULT 'unknown',
                ioc_notes    TEXT,
                techniques   TEXT DEFAULT '[]',
                first_seen   TEXT,
                last_seen    TEXT,
                hash_id      TEXT UNIQUE
            );

            -- Service persistence
            CREATE TABLE IF NOT EXISTS service_entries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                display_name TEXT,
                binary_path  TEXT,
                start_type   TEXT,
                service_type TEXT,
                run_as       TEXT,
                severity     TEXT DEFAULT 'unknown',
                ioc_notes    TEXT,
                techniques   TEXT DEFAULT '[]',
                first_seen   TEXT,
                last_seen    TEXT,
                hash_id      TEXT UNIQUE
            );

            -- Attack chains (shared across all entry types)
            CREATE TABLE IF NOT EXISTS attack_chains (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_type   TEXT NOT NULL DEFAULT 'registry',
                entry_id     INTEGER NOT NULL,
                chain_json   TEXT,
                built_at     TEXT,
                UNIQUE(entry_type, entry_id)
            );

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_proc_pid        ON process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_proc_ppid       ON process_events(parent_pid);
            CREATE INDEX IF NOT EXISTS idx_proc_time       ON process_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_sysmon_reg_key  ON sysmon_registry_events(key_path, value_name);
            CREATE INDEX IF NOT EXISTS idx_sysmon_reg_pid  ON sysmon_registry_events(pid);
            CREATE INDEX IF NOT EXISTS idx_sysmon_reg_time ON sysmon_registry_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_sysmon_proc_pid ON sysmon_process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_sysmon_proc_ppid ON sysmon_process_events(parent_pid);
            CREATE INDEX IF NOT EXISTS idx_sysmon_proc_time ON sysmon_process_events(event_time);
        """)
        conn.commit()
        return conn

    def close(self):
        self.conn.close()

    # ------------------------------------------------------------------
    # Event ingestion (shared by all collectors)
    # ------------------------------------------------------------------

    def collect_sysmon_events(self, hours_back: int = None) -> int:
        if hours_back is None:
            hours_back = self.collection_hours
        if not PYWIN32_AVAILABLE:
            print("[!] pywin32 not available")
            return 0
        ms_back = hours_back * 3600000
        cutoff  = datetime.utcnow() - timedelta(hours=hours_back)
        reg_count  = self._collect_sysmon_registry_events(ms_back, cutoff)
        proc_count = self._collect_sysmon_process_events(ms_back, cutoff)
        return reg_count + proc_count

    def collect_process_events(self, hours_back: int = None) -> int:
        if hours_back is None:
            hours_back = self.collection_hours
        if not PYWIN32_AVAILABLE:
            return 0
        ms_back = hours_back * 3600000
        cutoff  = datetime.utcnow() - timedelta(hours=hours_back)
        xpath   = ("*[System[EventID=4688 and TimeCreated"
                   "[timediff(@SystemTime) <= " + str(ms_back) + "]]]")
        count   = 0
        try:
            qh = win32evtlog.EvtQuery(
                "Security",
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None,
            )
        except pywintypes.error as e:
            print("[!] Cannot open Security log:", e)
            return 0
        except AttributeError:
            return 0
        try:
            while True:
                try:
                    events = win32evtlog.EvtNext(qh, 100, -1, 0)
                except pywintypes.error:
                    break
                if not events:
                    break
                for eh in events:
                    try:
                        xml_str = win32evtlog.EvtRender(eh, win32evtlog.EvtRenderEventXml)
                        if self._store_event_4688_xml(xml_str, cutoff):
                            count += 1
                    except Exception:
                        pass
        finally:
            try:
                win32evtlog.EvtClose(qh)
            except AttributeError:
                pass
        return count

    def _collect_sysmon_registry_events(self, ms_back: int, cutoff: datetime) -> int:
        xpath = ("*[System[EventID=13 and TimeCreated"
                 "[timediff(@SystemTime) <= " + str(ms_back) + "]]]")
        count = 0
        try:
            qh = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None,
            )
        except pywintypes.error as e:
            if e.args[0] == 2:
                print("[!] Sysmon not installed")
            else:
                print("[!] Cannot open Sysmon log:", e)
            return 0
        except AttributeError:
            return 0
        try:
            while True:
                try:
                    events = win32evtlog.EvtNext(qh, 100, -1, 0)
                except pywintypes.error:
                    break
                if not events:
                    break
                for eh in events:
                    try:
                        xml_str = win32evtlog.EvtRender(eh, win32evtlog.EvtRenderEventXml)
                        if self._store_sysmon_registry_event(xml_str, cutoff):
                            count += 1
                    except Exception as e:
                        debug_print("Error rendering sysmon reg event:", e)
        finally:
            try:
                win32evtlog.EvtClose(qh)
            except AttributeError:
                pass
        return count

    def _collect_sysmon_process_events(self, ms_back: int, cutoff: datetime) -> int:
        xpath = ("*[System[EventID=1 and TimeCreated"
                 "[timediff(@SystemTime) <= " + str(ms_back) + "]]]")
        count = 0
        try:
            qh = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None,
            )
        except (pywintypes.error, AttributeError):
            return 0
        try:
            while True:
                try:
                    events = win32evtlog.EvtNext(qh, 100, -1, 0)
                except pywintypes.error:
                    break
                if not events:
                    break
                for eh in events:
                    try:
                        xml_str = win32evtlog.EvtRender(eh, win32evtlog.EvtRenderEventXml)
                        if self._store_sysmon_process_event(xml_str, cutoff):
                            count += 1
                    except Exception:
                        pass
        finally:
            try:
                win32evtlog.EvtClose(qh)
            except AttributeError:
                pass
        return count

    def _store_sysmon_registry_event(self, xml_str: str, cutoff: datetime) -> bool:
        try:
            root = ET.fromstring(xml_str)
            ns   = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            tc   = root.find(".//" + ns + "TimeCreated")
            if tc is None:
                return False
            ts       = tc.attrib.get("SystemTime", "")
            ts_clean = ts.split(".")[0].rstrip("Z")
            event_dt = datetime.fromisoformat(ts_clean)
            if event_dt < cutoff:
                return False

            data_dict = {
                d.attrib["Name"]: (d.text or "").strip()
                for d in root.findall(".//" + ns + "Data")
                if d.attrib.get("Name")
            }

            key_path = data_dict.get("TargetObject", "")
            if not key_path:
                return False

            key_path_norm = normalise_reg_path(key_path)
            value_name    = ""
            if "\\" in key_path_norm:
                parts      = key_path_norm.split("\\")
                value_name = parts[-1]
                key_path_norm = "\\".join(parts[:-1])

            value_data   = data_dict.get("Details", "")
            pid_str      = data_dict.get("ProcessId", "0")
            try:
                pid = int(pid_str, 16) if pid_str.startswith("0x") else int(pid_str)
            except ValueError:
                pid = 0
            process_path = data_dict.get("Image", "")
            process_name = os.path.basename(process_path) if process_path else ""

            self.conn.execute("""
                INSERT OR IGNORE INTO sysmon_registry_events
                    (pid, process_name, process_path, event_time,
                     key_path, value_name, value_data, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, 13)
            """, (pid, process_name, process_path,
                  event_dt.isoformat(), key_path_norm, value_name, value_data))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print("Error storing sysmon registry event:", e)
            return False

    def _store_sysmon_process_event(self, xml_str: str, cutoff: datetime) -> bool:
        try:
            root = ET.fromstring(xml_str)
            ns   = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            tc   = root.find(".//" + ns + "TimeCreated")
            if tc is None:
                return False
            ts       = tc.attrib.get("SystemTime", "")
            ts_clean = ts.split(".")[0].rstrip("Z")
            event_dt = datetime.fromisoformat(ts_clean)
            if event_dt < cutoff:
                return False

            data_dict = {
                d.attrib["Name"]: (d.text or "").strip()
                for d in root.findall(".//" + ns + "Data")
                if d.attrib.get("Name")
            }

            pid          = int(data_dict.get("ProcessId", "0"))
            parent_pid   = int(data_dict.get("ParentProcessId", "0"))
            process_path = data_dict.get("Image", "")
            process_name = os.path.basename(process_path)
            command_line = data_dict.get("CommandLine", "")
            user_name    = data_dict.get("User", "")
            hashes       = data_dict.get("Hashes", "")
            integrity    = data_dict.get("IntegrityLevel", "")

            self.conn.execute("""
                INSERT OR IGNORE INTO sysmon_process_events
                    (pid, parent_pid, process_name, process_path,
                     command_line, user_name, hashes, integrity_level, event_time, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (pid, parent_pid, process_name, process_path,
                  command_line, user_name, hashes, integrity,
                  event_dt.isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print("Error storing sysmon process event:", e)
            return False

    def _store_event_4688_xml(self, xml_str: str, cutoff: datetime) -> bool:
        try:
            root = ET.fromstring(xml_str)
            ns   = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            tc   = root.find(".//" + ns + "TimeCreated")
            if tc is None:
                return False
            ts       = tc.attrib.get("SystemTime", "")
            ts_clean = ts.split(".")[0].rstrip("Z")
            event_dt = datetime.fromisoformat(ts_clean)
            if event_dt < cutoff:
                return False

            fields = {
                d.attrib["Name"]: (d.text or "").strip()
                for d in root.findall(".//" + ns + "Data")
                if d.attrib.get("Name")
            }

            def _parse_pid(val: str) -> int:
                try:
                    return int(val, 16) if val.startswith("0x") else int(val)
                except Exception:
                    return 0

            new_pid    = _parse_pid(fields.get("NewProcessId", "0"))
            parent_pid = _parse_pid(fields.get("ProcessId", "0"))
            proc_path  = fields.get("NewProcessName", "")
            proc_name  = os.path.basename(proc_path)
            cmdline    = fields.get("CommandLine", "")
            domain     = fields.get("SubjectDomainName", "")
            user       = fields.get("SubjectUserName", "")
            user_name  = domain + "\\" + user if user else ""

            self.conn.execute("""
                INSERT OR IGNORE INTO process_events
                    (pid, parent_pid, process_name, process_path,
                     command_line, user_name, event_time, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, 4688)
            """, (new_pid, parent_pid, proc_name, proc_path,
                  cmdline, user_name, event_dt.isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print("4688 store error:", e)
            return False

    # ------------------------------------------------------------------
    # Process lookup helpers (used by chain builders in all collectors)
    # ------------------------------------------------------------------

    def _find_parent(self, parent_pid: int, before: str) -> dict | None:
        if not parent_pid or parent_pid == 0:
            return None

        best_match = None
        best_time  = None

        row = self.conn.execute("""
            SELECT pid, parent_pid, process_name, process_path,
                   command_line, user_name, event_time
            FROM sysmon_process_events
            WHERE pid = ? AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, (parent_pid, before)).fetchone()

        if row:
            best_match = dict(row)
            best_match["_source_table"] = "sysmon"
            best_time  = row["event_time"]

        row = self.conn.execute("""
            SELECT pid, parent_pid, process_name, process_path,
                   command_line, user_name, event_time
            FROM process_events
            WHERE pid = ? AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, (parent_pid, before)).fetchone()

        if row:
            if best_time is None or row["event_time"] > best_time:
                best_match = dict(row)
                best_match["_source_table"] = "4688"

        return best_match

    def _find_process_by_pid(self, pid: int, before: str) -> dict | None:
        if not pid or pid == 0:
            return None

        row = self.conn.execute("""
            SELECT pid, parent_pid, process_name, process_path,
                   command_line, user_name, event_time
            FROM sysmon_process_events
            WHERE pid = ? AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, (pid, before)).fetchone()

        if row:
            result = dict(row)
            result["_source_table"] = "sysmon"
            return result

        row = self.conn.execute("""
            SELECT pid, parent_pid, process_name, process_path,
                   command_line, user_name, event_time
            FROM process_events
            WHERE pid = ? AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, (pid, before)).fetchone()

        if row:
            result = dict(row)
            result["_source_table"] = "4688"
            return result

        return None

    # ------------------------------------------------------------------
    # Chain building helpers (shared node classification / saving)
    # ------------------------------------------------------------------

    def _classify_node(self, proc: dict) -> str:
        path   = (proc.get("process_path") or "").lower()
        name   = (proc.get("process_name") or "").lower()
        cmd    = (proc.get("command_line") or "").lower()
        pid    = proc.get("pid")
        source = proc.get("_source_table") or proc.get("writer_source") or ""

        # Synthesized stubs (explorer.exe etc. resolved from live process list)
        if source == "stub":
            return "normal"

        if pid in (4, 0) or name in {p.lower() for p in self.SYSTEM_PROCS}:
            return "system"

        if name in {p.lower() for p in self.SHELL_PROCS}:
            return "normal"

        if name in {p.lower() for p in self.SVCHOST_BOUNDARY}:
            return "system"

        # Malicious: binary living in a suspicious path
        for sus in SUSPICIOUS_PATHS:
            if sus in path:
                return "malicious"

        # Malicious: LOLBin with attack-grade flags
        for lol in LOLBINS:
            if lol in name:
                if any(x in cmd for x in ["-enc", "-nop", "bypass", "hidden",
                                           "http", "iex", "downloadstring",
                                           "invoke-expression", "frombase64"]):
                    return "malicious"

        # Suspicious: path is sketchy even without attack flags
        if any(sus in path for sus in SUSPICIOUS_PATHS):
            return "suspicious"

        # Suspicious: bare LOLBin in chain (reg.exe, cmd.exe, powershell.exe etc.)
        if name in {l.lower() for l in LOLBINS}:
            return "suspicious"

        return "normal"

    def _save_chain(self, entry_type: str, entry_id: int, chain: list[dict]):
        self.conn.execute("""
            INSERT OR REPLACE INTO attack_chains
                (entry_type, entry_id, chain_json, built_at)
            VALUES (?, ?, ?, ?)
        """, (entry_type, entry_id, json.dumps(chain), datetime.now().isoformat()))
        self.conn.commit()

    # ------------------------------------------------------------------
    # Live process resolution (EDR-style: fills gaps beyond the log window)
    # ------------------------------------------------------------------

    def _resolve_live_process(self, pid: int) -> dict | None:
        """
        Resolve a PID that has no event log record (e.g. explorer.exe, started
        at login — long before any collection window).
        Tries psutil first (richest), then WMI, then tasklist as last resort.
        Returns a stub-flagged dict or None.
        """
        if not pid or pid == 0:
            return None

        # --- psutil (best: gives exe path, cmdline, ppid, username) ---
        try:
            import psutil
            p    = psutil.Process(pid)
            info = p.as_dict(attrs=["name", "exe", "cmdline", "ppid", "username", "create_time"])
            return {
                "pid":          pid,
                "parent_pid":   info.get("ppid"),
                "process_name": info.get("name") or "",
                "process_path": info.get("exe") or "",
                "command_line": " ".join(info.get("cmdline") or []),
                "user_name":    info.get("username") or "",
                "event_time":   "",          # no log timestamp for stubs
                "_source_table": "stub",
                "writer_source": "stub",
            }
        except Exception:
            pass

        # --- WMI fallback ---
        try:
            import subprocess
            out = subprocess.check_output(
                ["wmic", "process", "where", f"ProcessId={pid}",
                 "get", "Name,ExecutablePath,CommandLine,ParentProcessId,Caption", "/format:csv"],
                timeout=5, text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.strip().split(",")
                if len(parts) >= 5 and parts[0]:
                    try:
                        ppid = int(parts[4]) if parts[4].strip().isdigit() else None
                    except Exception:
                        ppid = None
                    return {
                        "pid":           pid,
                        "parent_pid":    ppid,
                        "process_name":  parts[1].strip() or parts[0].strip(),
                        "process_path":  parts[2].strip(),
                        "command_line":  parts[3].strip(),
                        "user_name":     "",
                        "event_time":    "",
                        "_source_table": "stub",
                        "writer_source": "stub",
                    }
        except Exception:
            pass

        # --- tasklist (name only — minimal stub) ---
        try:
            import subprocess
            out = subprocess.check_output(
                ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
                timeout=3, text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                line = line.strip().strip('"')
                if not line:
                    continue
                parts = [p.strip('"') for p in line.split('","')]
                if parts and parts[0] and parts[0].lower().endswith(".exe"):
                    return {
                        "pid":           pid,
                        "parent_pid":    None,
                        "process_name":  parts[0],
                        "process_path":  "",
                        "command_line":  "",
                        "user_name":     "",
                        "event_time":    "",
                        "_source_table": "stub",
                        "writer_source": "stub",
                    }
        except Exception:
            pass

        return None

    def _walk_chain(self, writer: dict) -> list[dict]:
        """
        EDR-style chain walk: traverse parent PIDs from the writer all the way
        to the session root (explorer.exe / services.exe / system).

        Strategy (in order):
          1. Look up parent in sysmon_process_events (richest — has cmdline, hashes)
          2. Fall back to process_events (4688 — less detail but wider coverage)
          3. If neither has a record (process started before the collection window),
             call _resolve_live_process() to synthesize a stub from the live OS.
          4. Stop when we hit a SYSTEM_PROC, a SHELL_PROC, a SVCHOST_BOUNDARY,
             a PID loop, or MAX_DEPTH.
        """
        chain_nodes  = []
        visited_pids = set()
        current      = writer
        depth        = 0

        while current and depth < self.MAX_DEPTH:
            pid  = current.get("pid")
            name = (current.get("process_name") or "").lower()

            # Loop guard
            if pid in visited_pids:
                break
            if pid is not None:
                visited_pids.add(pid)

            # Hard system boundary — append and stop
            if pid in self.SYSTEM_PIDS or name in {p.lower() for p in self.SYSTEM_PROCS}:
                chain_nodes.append(current)
                break

            chain_nodes.append(current)

            # Natural session roots — stop here (this IS the top of the user chain)
            if name in {p.lower() for p in self.SHELL_PROCS}:
                break

            # svchost boundary — stop walking upward
            if name in {p.lower() for p in self.SVCHOST_BOUNDARY}:
                break

            parent_pid = current.get("parent_pid")
            if not parent_pid or parent_pid == 0:
                break

            # --- 1. Try event log (sysmon preferred, then 4688) ---
            # Use child's event_time as the upper bound so we don't pick a
            # recycled PID that started AFTER the child.
            child_time = current.get("event_time") or datetime.now().isoformat()
            parent = self._find_parent(parent_pid, child_time)
            if not parent:
                parent = self._find_process_by_pid(parent_pid, child_time)

            # --- 2. Timestamp sanity (60-second grace for log latency) ---
            if parent and parent.get("_source_table") != "stub":
                p_evt = parent.get("event_time") or ""
                c_evt = child_time
                if p_evt and c_evt:
                    try:
                        p_dt = datetime.fromisoformat(p_evt)
                        c_dt = datetime.fromisoformat(c_evt)
                        if (p_dt - c_dt).total_seconds() > 60:
                            # Likely a PID-reuse ghost — fall through to live lookup
                            parent = None
                    except Exception:
                        pass

            # --- 3. Live OS stub — fills gap for long-running parents ---
            if not parent:
                parent = self._resolve_live_process(parent_pid)

            if not parent:
                break

            current = parent
            depth  += 1

        chain_nodes.reverse()
        for i, node in enumerate(chain_nodes):
            node["depth"] = i
        return chain_nodes

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        def _count(table, col=None, val=None):
            if col:
                return self.conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {col}=?", (val,)
                ).fetchone()[0]
            return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

        return {
            "registry": {
                sev: _count("registry_entries", "severity", sev)
                for sev in ("critical", "high", "medium", "low")
            },
            "tasks": {
                sev: _count("task_entries", "severity", sev)
                for sev in ("critical", "high", "medium", "low")
            },
            "services": {
                sev: _count("service_entries", "severity", sev)
                for sev in ("critical", "high", "medium", "low")
            },
            "process_events":  _count("process_events"),
            "sysmon_events":   (_count("sysmon_registry_events") +
                                _count("sysmon_process_events")),
        }