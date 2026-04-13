"""
registry_collector.py
Collects registry persistence entries from the 4 main Run/RunOnce keys,
recursing into all subkeys so nothing is missed.
Correlates findings with Event ID 4688 process creation logs and
Sysmon Event ID 12/13 for confirmed registry write attribution.

Sysmon collection uses wevtutil.exe (built-in Windows tool) instead of
pywin32 ETW APIs which have compatibility issues with Sysmon's channel.

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

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32api
    import win32security
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False
    print("[!] pywin32 not installed. pip install pywin32")


PERSISTENCE_KEYS = [
    {"hive": winreg.HKEY_LOCAL_MACHINE, "hive_name": "HKLM",
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "key_type": "Run"},
    {"hive": winreg.HKEY_CURRENT_USER,  "hive_name": "HKCU",
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "key_type": "Run"},
    {"hive": winreg.HKEY_LOCAL_MACHINE, "hive_name": "HKLM",
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "key_type": "RunOnce"},
    {"hive": winreg.HKEY_CURRENT_USER,  "hive_name": "HKCU",
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "key_type": "RunOnce"},
]

KNOWN_LEGIT_PATHS = [
    r"c:\windows\system32", r"c:\windows\syswow64",
    r"c:\program files\windows", r"c:\program files (x86)\windows",
    r"c:\program files\microsoft", r"c:\program files (x86)\microsoft",
]

SUSPICIOUS_PATHS = [
    r"c:\users\public", r"c:\temp", r"c:\windows\temp",
    r"\appdata\local\temp", r"\appdata\roaming", r"\appdata\local",
    r"\downloads", r"\desktop", r"c:\perflogs", r"c:\recycler",
]

LEGIT_APPDATA_LOCAL = [
    r"\appdata\local\microsoft\windowsapps", r"\appdata\local\microsoft\teams",
    r"\appdata\local\discord", r"\appdata\local\grammarly",
]

LOLBINS = [
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
    "wmic.exe", "powershell.exe", "cmd.exe", "regsvcs.exe",
    "regasm.exe", "installutil.exe",
]

MITRE_REG_TECHNIQUES = [
    (r"currentversion\run",     "T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
    (r"currentversion\runonce", "T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
]

MITRE_PROC_TECHNIQUES = [
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

MITRE_CMD_TECHNIQUES = [
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


def tag_registry(hive, reg_path):
    combined = f"{hive}\\{reg_path}".lower()
    seen, tags = set(), []
    for fragment, tid, tname in MITRE_REG_TECHNIQUES:
        if fragment in combined and tid not in seen:
            seen.add(tid)
            tags.append({"id": tid, "name": tname})
    return tags


def tag_process(proc_name, cmdline):
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


def _normalise_reg_path(path):
    p = re.sub(r'^HKU\\S-[0-9-]+\\', 'HKCU\\', path, flags=re.IGNORECASE)
    p = re.sub(r'^HKEY_CURRENT_USER\\',  'HKCU\\', p, flags=re.IGNORECASE)
    p = re.sub(r'^HKEY_LOCAL_MACHINE\\', 'HKLM\\', p, flags=re.IGNORECASE)
    return p


class RegistryCollector:
    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
    SYSTEM_PROCS   = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe"
    }
    SYSTEM_PIDS = {0, 4}
    MAX_DEPTH   = 10

    def __init__(self, db_path="reghunt.db"):
        self.db_path = db_path
        self.conn    = self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS registry_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                hive TEXT NOT NULL, reg_path TEXT NOT NULL, value_data TEXT,
                severity TEXT DEFAULT 'unknown', ioc_notes TEXT,
                techniques TEXT DEFAULT '[]', first_seen TEXT,
                last_seen TEXT, hash_id TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, pid INTEGER,
                parent_pid INTEGER, process_name TEXT, process_path TEXT,
                command_line TEXT, user_name TEXT, event_time TEXT, event_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS registry_writes (
                id INTEGER PRIMARY KEY AUTOINCREMENT, pid INTEGER,
                process_name TEXT, process_path TEXT, key_path TEXT,
                value_data TEXT, user_name TEXT, event_time TEXT
            );
            CREATE TABLE IF NOT EXISTS attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT, reg_entry_id INTEGER,
                chain_json TEXT, built_at TEXT,
                FOREIGN KEY(reg_entry_id) REFERENCES registry_entries(id)
            );
            CREATE INDEX IF NOT EXISTS idx_proc_pid  ON process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_proc_ppid ON process_events(parent_pid);
            CREATE INDEX IF NOT EXISTS idx_proc_name ON process_events(process_name);
            CREATE INDEX IF NOT EXISTS idx_proc_time ON process_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_regw_key  ON registry_writes(key_path);
            CREATE INDEX IF NOT EXISTS idx_regw_time ON registry_writes(event_time);
            CREATE INDEX IF NOT EXISTS idx_regw_pid  ON registry_writes(pid);
        """)
        conn.commit()
        cols = {r[1] for r in conn.execute("PRAGMA table_info(registry_entries)")}
        if "techniques" not in cols:
            conn.execute("ALTER TABLE registry_entries ADD COLUMN techniques TEXT DEFAULT '[]'")
            conn.commit()
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "registry_writes" not in tables:
            conn.executescript("""
                CREATE TABLE registry_writes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, pid INTEGER,
                    process_name TEXT, process_path TEXT, key_path TEXT,
                    value_data TEXT, user_name TEXT, event_time TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_regw_key  ON registry_writes(key_path);
                CREATE INDEX IF NOT EXISTS idx_regw_time ON registry_writes(event_time);
                CREATE INDEX IF NOT EXISTS idx_regw_pid  ON registry_writes(pid);
            """)
            conn.commit()
        return conn

    def collect_registry(self):
        results = []
        for key_info in PERSISTENCE_KEYS:
            results.extend(self._read_key(key_info))
        return results

    def _read_key(self, key_info):
        entries = []
        try:
            key = winreg.OpenKey(key_info["hive"], key_info["path"],
                                 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
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
                    sev, ioc  = self._assess_severity(name, data_str)
                    hash_id   = hashlib.md5(f"{full_path}|{name}|{data_str}".encode()).hexdigest()
                    entry = {
                        "name": name,
                        "hive": f"{key_info['hive_name']}\\{key_info['key_type']}",
                        "reg_path": full_path, "value_data": data_str,
                        "severity": sev, "ioc_notes": ioc,
                        "techniques": json.dumps(tag_registry(
                            f"{key_info['hive_name']}\\{key_info['key_type']}", full_path)),
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

    def _assess_severity(self, name, value):
        v = value.lower()
        if any(p in v for p in ["http://", "https://", "ftp://"]):
            return "critical", "Remote URL in registry value"
        for lol in LOLBINS:
            if lol in v:
                if lol in ("powershell.exe", "cmd.exe"):
                    sus = [" -encodedcommand ", " -enc ", " -e ", " -nop ",
                           " -w hidden", " -windowstyle hidden", "bypass",
                           "iex(", "iex (", "invoke-expression"]
                    if any(f in v for f in sus):
                        return "critical", f"LOLBin with suspicious flags: {lol}"
                    if lol == "cmd.exe" and " /q /c del " in v:
                        return "low", "cmd.exe running benign cleanup command"
                else:
                    return "critical", f"LOLBin in Run key: {lol}"
        if re.search(r'(?<![a-z])-enc(?:odedcommand)?\s', v):
            return "critical", "Base64-encoded command detected"
        for legit in KNOWN_LEGIT_PATHS:
            if v.startswith(legit):
                return "low", "Path in known-good location"
        if v.startswith("%windir%") or v.startswith("%systemroot%"):
            return "low", "System environment variable path"
        for la in LEGIT_APPDATA_LOCAL:
            if la in v:
                return "medium", "AppData path — common app location but verify"
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in v:
                return "high", f"Executable in suspicious path: {sus_path}"
        return "medium", "Not in known-good path — manual review recommended"

    def _upsert_entry(self, entry):
        self.conn.execute("""
            INSERT INTO registry_entries
                (name, hive, reg_path, value_data, severity, ioc_notes,
                 techniques, first_seen, last_seen, hash_id)
            VALUES (:name, :hive, :reg_path, :value_data, :severity, :ioc_notes,
                    :techniques, :last_seen, :last_seen, :hash_id)
            ON CONFLICT(hash_id) DO UPDATE SET
                severity=excluded.severity, ioc_notes=excluded.ioc_notes,
                techniques=excluded.techniques, last_seen=excluded.last_seen
        """, entry)
        self.conn.commit()

    def collect_process_events(self, hours_back=24):
        if not PYWIN32_AVAILABLE:
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

    def _store_event_4688(self, event, event_dt):
        strings = event.StringInserts or []
        def get(i, d=""):
            return strings[i] if i < len(strings) else d
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

    def collect_registry_writes(self, hours_back=24):
        """
        Collect Sysmon ID 12/13 events using wevtutil.exe.

        This bypasses all pywin32 ETW compatibility issues.
        wevtutil is built into Windows Vista+, always available,
        and correctly handles ETW channels like Sysmon.
        """
        count      = 0
        cutoff     = datetime.now() - timedelta(hours=hours_back)
        cutoff_str = cutoff.strftime('%Y-%m-%dT%H:%M:%S')

        query = (
            f"*[System[(EventID=12 or EventID=13) and "
            f"TimeCreated[@SystemTime>='{cutoff_str}']]]"
        )

        cmd = [
            'wevtutil', 'qe',
            self.SYSMON_CHANNEL,
            f'/q:{query}',
            '/f:xml',
            '/rd:true',
            '/c:10000'
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding='utf-8', errors='replace', timeout=60
            )
        except subprocess.TimeoutExpired:
            print("[!] wevtutil timed out after 60s")
            return 0
        except FileNotFoundError:
            print("[!] wevtutil.exe not found")
            return 0
        except Exception as e:
            print(f"[!] wevtutil error: {e}")
            return 0

        print(f"[DEBUG] wevtutil returncode: {result.returncode}")
        print(f"[DEBUG] wevtutil stderr: {result.stderr.strip()!r}")
        print(f"[DEBUG] wevtutil stdout length: {len(result.stdout)} chars")
        print(f"[DEBUG] wevtutil stdout preview: {result.stdout[:300]!r}")

        if result.returncode != 0:
            err = result.stderr.strip()
            if err:
                print(f"[!] wevtutil: {err}")
            return 0

        if not result.stdout.strip():
            print("[DEBUG] wevtutil returned empty output — no events in window")
            return 0

        # wevtutil outputs multiple bare <Event> elements — wrap for ET
        xml_str = f"<Events>{result.stdout}</Events>"
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            cleaned = result.stdout.replace('\x00', '').replace('\r', '')
            try:
                root = ET.fromstring(f"<Events>{cleaned}</Events>")
            except ET.ParseError as e:
                print(f"[!] XML parse error: {e}")
                return 0

        for event_node in root.findall('Event'):
            try:
                xml_single = ET.tostring(event_node, encoding='unicode')
                if self._store_sysmon_from_xml(xml_single):
                    count += 1
            except Exception:
                pass

        return count

    def _store_sysmon_from_xml(self, xml_str):
        try:
            root = ET.fromstring(xml_str)

            # Extract all <Data Name="..."> using tag suffix matching
            fields = {}
            for node in root.iter():
                tag = node.tag.split('}')[-1] if '}' in node.tag else node.tag
                if tag == 'Data':
                    name = node.attrib.get('Name', '')
                    if name:
                        fields[name] = (node.text or '').strip()

            if not fields:
                return False

            event_id = 0
            for node in root.iter():
                tag = node.tag.split('}')[-1] if '}' in node.tag else node.tag
                if tag == 'EventID':
                    try:
                        event_id = int(node.text or '0')
                    except ValueError:
                        pass
                    break

            event_type = fields.get('EventType', '').lower()
            if event_id == 13 and event_type != 'setvalue':
                return False
            if event_id not in (12, 13):
                return False

            try:
                pid = int(fields.get('ProcessId', '0'))
            except (ValueError, TypeError):
                pid = 0

            proc_path  = fields.get('Image', '')
            proc_name  = os.path.basename(proc_path)
            key_path   = fields.get('TargetObject', '')
            value_data = fields.get('Details', '')
            user_name  = fields.get('User', '')

            event_time = ''
            for node in root.iter():
                tag = node.tag.split('}')[-1] if '}' in node.tag else node.tag
                if tag == 'TimeCreated':
                    ts = node.attrib.get('SystemTime', '')
                    event_time = ts[:19].replace('T', ' ')
                    break
            if not event_time:
                event_time = datetime.utcnow().isoformat()[:19]

            key_norm = _normalise_reg_path(key_path)
            if 'currentversion\\run' not in key_norm.lower():
                return False

            self.conn.execute("""
                INSERT OR IGNORE INTO registry_writes
                    (pid, process_name, process_path, key_path,
                     value_data, user_name, event_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (pid, proc_name, proc_path, key_norm,
                  value_data, user_name, event_time))
            self.conn.commit()
            return True
        except Exception:
            return False

    def _find_writer(self, entry):
        entry_name = (entry.get("name") or "").lower()
        last_seen  = entry["last_seen"]

        sysmon_row = self.conn.execute("""
            SELECT * FROM registry_writes
            WHERE (
                LOWER(key_path) LIKE ?
                OR LOWER(key_path) LIKE ?
                OR LOWER(key_path) LIKE ?
            )
            AND event_time <= ?
            ORDER BY
                CASE WHEN LOWER(key_path) LIKE ? THEN 0 ELSE 1 END,
                event_time DESC
            LIMIT 1
        """, (f"%\\{entry_name}", f"%\\run", f"%\\runonce",
              last_seen, f"%\\{entry_name}")).fetchone()

        if sysmon_row:
            sysmon = dict(sysmon_row)
            proc = self.conn.execute("""
                SELECT * FROM process_events
                WHERE pid = ? AND event_time <= ?
                ORDER BY event_time DESC LIMIT 1
            """, (sysmon["pid"], last_seen)).fetchone()
            if proc:
                result = dict(proc)
                result["writer_source"] = "sysmon"
                return result
            return {
                "pid": sysmon["pid"], "parent_pid": None,
                "process_name": sysmon["process_name"],
                "process_path": sysmon["process_path"],
                "command_line": "", "user_name": sysmon["user_name"],
                "event_time": sysmon["event_time"], "writer_source": "sysmon",
            }

        value     = entry.get("value_data") or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_name  = os.path.basename(exe_token.strip('"'))
        proc      = self._find_process(exe_name, last_seen)
        if proc:
            proc["writer_source"] = "4688"
        return proc

    def _find_process(self, name, before):
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE process_name LIKE ? AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, (f"%{name}%", before)).fetchone()
        return dict(row) if row else None

    def _find_parent(self, parent_pid, before):
        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE pid = ? AND event_time < ?
            ORDER BY event_time DESC LIMIT 1
        """, (parent_pid, before)).fetchone()
        return dict(row) if row else None

    def build_attack_chain(self, reg_entry_id):
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
                "pid": 0, "name": exe_name or "unknown", "type": "malicious",
                "user": "unknown", "path": exe_token, "cmdline": value,
                "event_time": entry["last_seen"], "depth": 0, "source": "inferred",
                "techniques": [],
                "action": {"type": "reg", "label": f"Wrote {entry['hive']} -> {entry['name']}"}
            }]
            self._save_chain(reg_entry_id, placeholder)
            return placeholder

        chain, current, visited, depth = [], writer, set(), 0
        while current and depth < self.MAX_DEPTH:
            pid  = current["pid"]
            name = (current["process_name"] or "").lower()
            if pid in visited:
                break
            if pid in self.SYSTEM_PIDS or name in self.SYSTEM_PROCS:
                chain.append(self._make_node(current, depth, is_writer=False))
                break
            visited.add(pid)
            is_writer = (pid == writer["pid"])
            chain.append(self._make_node(current, depth, is_writer=is_writer,
                                         entry=entry if is_writer else None))
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

    def _make_node(self, proc, depth, is_writer, entry=None):
        proc_name = proc["process_name"] or "unknown"
        cmdline   = proc["command_line"] or ""
        node = {
            "pid": proc["pid"], "name": proc_name,
            "type": self._classify_node(proc), "user": proc["user_name"] or "",
            "path": proc["process_path"] or "", "cmdline": cmdline,
            "event_time": proc["event_time"] or "", "depth": depth,
            "source": proc.get("writer_source", "4688"),
            "techniques": tag_process(proc_name, cmdline), "action": None,
        }
        if is_writer and entry:
            node["action"] = {
                "type": "reg",
                "label": f"Wrote {entry['hive']} -> {entry['name']} = {entry['value_data'][:60]}"
            }
        return node

    def _save_chain(self, reg_entry_id, chain):
        self.conn.execute("""
            INSERT OR REPLACE INTO attack_chains (reg_entry_id, chain_json, built_at)
            VALUES (?, ?, ?)
        """, (reg_entry_id, json.dumps(chain), datetime.now().isoformat()))
        self.conn.commit()

    def _classify_node(self, proc):
        path = (proc.get("process_path") or "").lower()
        name = (proc.get("process_name") or "").lower()
        cmd  = (proc.get("command_line") or "").lower()
        if proc.get("pid") in (4, 0):
            return "system"
        if name in ("system", "smss.exe", "csrss.exe", "wininit.exe",
                    "winlogon.exe", "services.exe", "lsass.exe"):
            return "system"
        sev, _ = RegistryCollector._static_assess(path, cmd)
        return "malicious" if sev == "critical" else "suspicious" if sev == "high" else "normal"

    @staticmethod
    def _static_assess(path, cmd):
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

    def get_all_entries(self):
        rows = self.conn.execute(
            "SELECT * FROM registry_entries ORDER BY last_seen DESC"
        ).fetchall()
        result = []
        for r in rows:
            e = dict(r)
            e["techniques"] = json.loads(e.get("techniques") or "[]")
            result.append(e)
        return result

    def get_entry(self, entry_id):
        row = self.conn.execute(
            "SELECT * FROM registry_entries WHERE id = ?", (entry_id,)
        ).fetchone()
        if not row:
            return None
        e = dict(row)
        e["techniques"] = json.loads(e.get("techniques") or "[]")
        return e

    def get_chain(self, entry_id):
        row = self.conn.execute(
            "SELECT chain_json FROM attack_chains WHERE reg_entry_id = ?", (entry_id,)
        ).fetchone()
        return json.loads(row["chain_json"]) if row else self.build_attack_chain(entry_id)

    def get_stats(self):
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


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RegHunt -- Registry Persistence Collector")
    parser.add_argument("--scan",   action="store_true", help="Scan registry persistence keys")
    parser.add_argument("--events", action="store_true", help="Collect Event ID 4688")
    parser.add_argument("--sysmon", action="store_true", help="Collect Sysmon ID 12/13 via wevtutil")
    parser.add_argument("--hours",  type=int, default=24, help="Hours back (default 24)")
    parser.add_argument("--chain",  type=int, metavar="ID", help="Build attack chain for entry ID")
    parser.add_argument("--db",     default="reghunt.db")
    args = parser.parse_args()

    col = RegistryCollector(db_path=args.db)

    if args.scan:
        print("[*] Scanning registry persistence keys...")
        entries = col.collect_registry()
        print(f"[+] Found {len(entries)} entries")
        for e in entries:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(e["severity"], "⚪")
            print(f"  {icon} [{e['severity'].upper():8}] {e['name']:40} -> {e['value_data'][:60]}")

    if args.events:
        print(f"\n[*] Collecting process creation events (last {args.hours}h)...")
        print(f"[+] Stored {col.collect_process_events(hours_back=args.hours)} process creation events")

    if args.sysmon:
        print(f"\n[*] Collecting Sysmon registry write events (last {args.hours}h)...")
        print(f"[+] Stored {col.collect_registry_writes(hours_back=args.hours)} Sysmon registry write events")

    if args.chain:
        print(f"\n[*] Building attack chain for entry ID {args.chain}...")
        chain = col.build_attack_chain(args.chain)
        if chain:
            print(f"[+] Chain depth: {len(chain)} nodes")
            for i, node in enumerate(chain):
                indent = "  " * i
                icon   = {"system": "⚙️ ", "normal": "📦", "suspicious": "⚠️ ", "malicious": "💀"}.get(node["type"], "❓")
                src    = f"[{node.get('source','?')}]"
                print(f"{indent}{icon} {node['name']} (PID {node['pid']}) {src} -- {node['user']}")
                if node.get("action"):
                    print(f"{indent}   -> {node['action']['label']}")
                if node.get("techniques"):
                    print(f"{indent}   📌 {', '.join(t['id'] for t in node['techniques'])}")
        else:
            print("[!] No chain found. Run --scan and --events first.")

    stats = col.get_stats()
    print(f"\n[*] DB Stats: {stats['total']} entries | {stats['process_events']} process events | {stats['sysmon_writes']} sysmon writes")
    print(f"    Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}")

    col.close()