"""
service_collector.py
Collects Windows service persistence entries.
Correlates with Security Event 7045 (service installed) using time-based matching.
Extends BaseCollector.
"""

import os
import json
import hashlib
import winreg
from datetime import datetime, timedelta

from base_collector import (
    BaseCollector, Colors, assess_severity,
    tag_service, tag_process,
    LOLBINS, SUSPICIOUS_PATHS,
    debug_print, PYWIN32_AVAILABLE,
)

try:
    import win32evtlog
    import pywintypes
    import win32service
    import win32con
    WIN32_SERVICE_AVAILABLE = True
except ImportError:
    WIN32_SERVICE_AVAILABLE = False

# Seconds either side of a 7045 event to search for the installer process
SVC_CORRELATION_WINDOW_SECS = 60

# Services to ignore (known Windows built-ins that generate noise)
BUILTIN_SERVICE_PREFIXES = [
    "AeLookupSvc", "ALG", "AppIDSvc", "Appinfo", "AppMgmt",
    "AudioEndpointBuilder", "Audiosrv", "BFE", "BITS", "BrokerInfrastructure",
    "Browser", "CertPropSvc", "ClipSVC", "COMSysApp", "CryptSvc",
    "DcomLaunch", "DeviceAssociationService", "Dhcp", "DiagTrack",
    "DispBrokerDesktopSvc", "Dnscache", "DoSvc", "DPS", "DsmSvc",
    "EapHost", "EventLog", "EventSystem", "Fax", "fdPHost", "FDResPub",
    "FontCache", "gpsvc", "hidserv", "hns", "HomeGroupListener",
    "HomeGroupProvider", "IKEEXT", "iphlpsvc", "KeyIso", "KPSSVC",
    "KtmRm", "LanmanServer", "LanmanWorkstation", "lmhosts", "LSASS",
    "LSM", "MapsBroker", "MpsSvc", "MSDTC", "MSiSCSI", "msiserver",
    "NcbService", "Netlogon", "Netman", "netprofm", "NetSetupSvc",
    "NlaSvc", "nsi", "PcaSvc", "PerfHost", "pla", "PlugPlay",
    "PolicyAgent", "Power", "ProfSvc", "RasAuto", "RasMan", "RpcEptMapper",
    "RpcLocator", "RpcSs", "SamSs", "Schedule", "SCPolicySvc", "SDRSVC",
    "seclogon", "SENS", "SessionEnv", "SharedAccess", "ShellHWDetection",
    "SNMPTRAP", "Spooler", "sppsvc", "SSDPSRV", "SstpSvc", "StateRepository",
    "stisvc", "StorSvc", "svsvc", "SysMain", "SystemEventsBroker",
    "TabletInputService", "TapiSrv", "TermService", "Themes", "THREADORDER",
    "TrkWks", "TrustedInstaller", "UI0Detect", "UmRdpService", "upnphost",
    "UxSms", "VaultSvc", "vds", "VSS", "W32Time", "WbioSrvc", "Wcmsvc",
    "WdiServiceHost", "WdiSystemHost", "WebClient", "Wecsvc", "wercplsupport",
    "WerSvc", "WiaRpc", "WinDefend", "WinHttpAutoProxySvc", "Winmgmt",
    "WinRM", "Wlansvc", "wlidsvc", "wmiApSrv", "WMPNetworkSvc", "WPDBusEnum",
    "WPFFontCache_v0400", "wscsvc", "WSearch", "wuauserv", "wudfsvc",
    "XblAuthManager", "XblGameSave",
]


class ServiceCollector(BaseCollector):

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def collect_services(self, skip_builtin: bool = True) -> list[dict]:
        """Enumerate services from the registry (most reliable method)."""
        entries = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
        except Exception as e:
            print("[!] Cannot open Services registry key:", e)
            return []

        try:
            i = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(key, i)
                    i += 1

                    if skip_builtin and any(
                        svc_name.lower().startswith(b.lower())
                        for b in BUILTIN_SERVICE_PREFIXES
                    ):
                        continue

                    entry = self._read_service(svc_name)
                    if entry:
                        entries.append(entry)
                        self._upsert_service(entry)
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

        return entries

    def _read_service(self, svc_name: str) -> dict | None:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\\" + svc_name,
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
        except Exception:
            return None

        def _get(name, default=""):
            try:
                val, _ = winreg.QueryValueEx(key, name)
                return str(val)
            except Exception:
                return default

        binary_path  = _get("ImagePath", "")
        display_name = _get("DisplayName", svc_name)
        start_type   = _get("Start", "")
        svc_type     = _get("Type", "")
        obj_name     = _get("ObjectName", "LocalSystem")
        winreg.CloseKey(key)

        # Only include executable services (type 16=own process, 32=shared process)
        try:
            svc_type_int = int(svc_type)
            if svc_type_int not in (1, 2, 4, 8, 16, 32, 256, 272, 288):
                return None
        except ValueError:
            pass

        # Map start type to readable string
        start_map = {"0": "Boot", "1": "System", "2": "Automatic",
                     "3": "Manual", "4": "Disabled"}
        start_str = start_map.get(start_type, start_type)

        # Skip disabled services (reduce noise)
        if start_str == "Disabled":
            return None

        severity, ioc = assess_severity(svc_name, binary_path)

        # Extra check: services running as SYSTEM with suspicious binary path
        if "system" in obj_name.lower() and severity in ("medium", "low"):
            bp_lower = binary_path.lower()
            if any(sus in bp_lower for sus in SUSPICIOUS_PATHS):
                severity = "high"
                ioc      = "SYSTEM service with suspicious binary path"

        # Extra check: binary in Temp directories → always at least HIGH
        bp_lower = binary_path.lower()
        if any(t in bp_lower for t in [r"c:\windows\temp", r"c:\temp",
                                        r"\appdata\local\temp"]):
            if severity not in ("critical",):
                severity = "high"
                ioc      = "Service binary in Temp directory — strong IOC"

        # Extra check: service name mimics Windows services
        MIMIC_PATTERNS = ["svcupdate", "svchost32", "lsass32",
                          "windowsupdate", "winupdate", "svhost"]
        if any(p in svc_name.lower() for p in MIMIC_PATTERNS):
            severity = "critical"
            ioc      = "Service name mimics Windows built-in: " + svc_name

        hash_id = hashlib.md5(
            (svc_name + "|" + binary_path).encode()
        ).hexdigest()
        now = datetime.now().isoformat()

        return {
            "service_name": svc_name,
            "display_name": display_name,
            "binary_path":  binary_path,
            "start_type":   start_str,
            "service_type": svc_type,
            "run_as":       obj_name,
            "severity":     severity,
            "ioc_notes":    ioc,
            "techniques":   json.dumps(tag_service(svc_name)),
            "first_seen":   now,
            "last_seen":    now,
            "hash_id":      hash_id,
        }

    def _upsert_service(self, entry: dict):
        self.conn.execute("""
            INSERT INTO service_entries
                (service_name, display_name, binary_path, start_type, service_type,
                 run_as, severity, ioc_notes, techniques, first_seen, last_seen, hash_id)
            VALUES (:service_name, :display_name, :binary_path, :start_type, :service_type,
                    :run_as, :severity, :ioc_notes, :techniques, :first_seen, :last_seen, :hash_id)
            ON CONFLICT(hash_id) DO UPDATE SET
                severity     = excluded.severity,
                ioc_notes    = excluded.ioc_notes,
                start_type   = excluded.start_type,
                last_seen    = excluded.last_seen
        """, entry)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Event 7045 collection (service installed)
    # ------------------------------------------------------------------

    def collect_service_events(self, hours_back: int = None) -> int:
        """Collect System Event 7045 (New Service Installed)."""
        if hours_back is None:
            hours_back = self.collection_hours
        if not PYWIN32_AVAILABLE:
            return 0

        ms_back = hours_back * 3600000
        cutoff  = datetime.utcnow() - timedelta(hours=hours_back)
        xpath   = ("*[System[EventID=7045 and TimeCreated"
                   "[timediff(@SystemTime) <= " + str(ms_back) + "]]]")
        count   = 0
        try:
            qh = win32evtlog.EvtQuery(
                "System",
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None,
            )
        except Exception as e:
            debug_print("Cannot open System log for 7045:", e)
            return 0

        try:
            while True:
                try:
                    events = win32evtlog.EvtNext(qh, 100, -1, 0)
                except Exception:
                    break
                if not events:
                    break
                for eh in events:
                    try:
                        import xml.etree.ElementTree as ET
                        xml_str = win32evtlog.EvtRender(eh, win32evtlog.EvtRenderEventXml)
                        if self._store_service_event(xml_str, cutoff):
                            count += 1
                    except Exception:
                        pass
        finally:
            try:
                win32evtlog.EvtClose(qh)
            except Exception:
                pass
        return count

    def _store_service_event(self, xml_str: str, cutoff: datetime) -> bool:
        try:
            import xml.etree.ElementTree as ET
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

            svc_name    = fields.get("ServiceName", "")
            svc_file    = fields.get("ServiceFileName", "")
            account     = fields.get("ServiceAccount", "")
            start_type  = fields.get("StartType", "")

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS service_creation_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT,
                    service_file TEXT,
                    account      TEXT,
                    start_type   TEXT,
                    event_time   TEXT
                )
            """)
            self.conn.execute("""
                INSERT OR IGNORE INTO service_creation_events
                    (service_name, service_file, account, start_type, event_time)
                VALUES (?, ?, ?, ?, ?)
            """, (svc_name, svc_file, account, start_type, event_dt.isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print("Error storing service event:", e)
            return False

    # ------------------------------------------------------------------
    # Chain building (time-based correlation)
    # ------------------------------------------------------------------

    def build_attack_chain(self, svc_entry_id: int) -> list[dict]:
        entry = self.conn.execute(
            "SELECT * FROM service_entries WHERE id = ?", (svc_entry_id,)
        ).fetchone()
        if not entry:
            return []
        entry = dict(entry)

        writer = self._find_service_writer(entry)

        if writer.get("writer_source") == "unknown":
            chain = [{
                "pid":           None,
                "name":          "Unknown",
                "type":          "unknown",
                "user":          entry.get("run_as", "unknown"),
                "path":          entry.get("binary_path", "unknown"),
                "cmdline":       entry.get("binary_path", ""),
                "event_time":    entry.get("last_seen", ""),
                "depth":         0,
                "source":        "unknown",
                "unknown_reason": writer.get("unknown_reason", "No event log data"),
                "techniques":    tag_service(entry["service_name"]),
                "action": {
                    "type":  "service",
                    "label": "Installed Service: " + entry["service_name"],
                },
            }]
            self._save_chain("service", svc_entry_id, chain)
            return chain

        writer["_is_writer"] = True
        nodes = self._walk_chain(writer)

        for node in nodes:
            if node.get("_is_writer"):
                node["action"] = {
                    "type":  "service",
                    "label": ("Installed Service: " + entry["service_name"] +
                              " -> " + entry.get("binary_path", "")[:50]),
                }
                node["techniques"] = (
                    tag_process(node.get("process_name", ""), node.get("command_line", "")) +
                    tag_service(entry["service_name"])
                )
                break

        chain = self._nodes_to_display(nodes)
        self._save_chain("service", svc_entry_id, chain)
        return chain

    def _find_service_writer(self, entry: dict) -> dict:
        svc_name  = entry["service_name"]
        last_seen = entry.get("last_seen") or datetime.now().isoformat()

        # Check service_creation_events table
        try:
            row = self.conn.execute("""
                SELECT service_name, account, event_time
                FROM service_creation_events
                WHERE LOWER(service_name) = LOWER(?)
                ORDER BY event_time DESC LIMIT 1
            """, (svc_name,)).fetchone()
        except Exception:
            row = None

        if row:
            creation_time = row["event_time"]
            try:
                ct_dt      = datetime.fromisoformat(creation_time)
                window_low = (ct_dt - timedelta(seconds=SVC_CORRELATION_WINDOW_SECS)).isoformat()
                window_hi  = (ct_dt + timedelta(seconds=SVC_CORRELATION_WINDOW_SECS)).isoformat()
            except Exception:
                window_low = creation_time
                window_hi  = creation_time

            # Look for sc.exe, powershell.exe, or python.exe around that time
            # For sc.exe require the service name in cmdline to avoid false matches
            for tool in ("sc.exe", "powershell.exe", "cmd.exe", "pwsh.exe", "python.exe"):
                if tool == "sc.exe":
                    proc_row = self.conn.execute("""
                        SELECT pid, parent_pid, process_name, process_path,
                               command_line, user_name, event_time
                        FROM sysmon_process_events
                        WHERE LOWER(process_name) = ?
                          AND event_time BETWEEN ? AND ?
                          AND (LOWER(command_line) LIKE '%create%'
                               OR LOWER(command_line) LIKE ?)
                        ORDER BY ABS(JULIANDAY(event_time) - JULIANDAY(?))
                        LIMIT 1
                    """, (tool, window_low, window_hi,
                          "%" + svc_name.lower() + "%",
                          creation_time)).fetchone()
                else:
                    proc_row = self.conn.execute("""
                        SELECT pid, parent_pid, process_name, process_path,
                               command_line, user_name, event_time
                        FROM sysmon_process_events
                        WHERE LOWER(process_name) = ?
                          AND event_time BETWEEN ? AND ?
                        ORDER BY ABS(JULIANDAY(event_time) - JULIANDAY(?))
                        LIMIT 1
                    """, (tool, window_low, window_hi, creation_time)).fetchone()

                if proc_row:
                    result = dict(proc_row)
                    result["writer_source"] = "7045+sysmon"
                    return result

        # Fallback: match binary path in process cmdline
        binary = entry.get("binary_path", "")
        if binary:
            exe_name = os.path.basename(binary.strip('"').split()[0])
            proc_row = self.conn.execute("""
                SELECT pid, parent_pid, process_name, process_path,
                       command_line, user_name, event_time
                FROM sysmon_process_events
                WHERE (LOWER(command_line) LIKE ? OR LOWER(command_line) LIKE ?)
                  AND event_time <= ?
                ORDER BY event_time DESC LIMIT 1
            """, ("%" + svc_name.lower() + "%",
                  "%" + exe_name.lower() + "%",
                  last_seen)).fetchone()

            if proc_row:
                result = dict(proc_row)
                result["writer_source"] = "sysmon-cmdline"
                return result

        return {
            "writer_source":  "unknown",
            "unknown_reason": "No 7045 event or matching process found",
        }

    def _nodes_to_display(self, nodes: list[dict]) -> list[dict]:
        display = []
        for i, proc in enumerate(nodes):
            node_type = self._classify_node(proc)
            name      = proc.get("process_name", "unknown")
            pid       = proc.get("pid")
            if pid in self.SYSTEM_PIDS or name.lower() in {p.lower() for p in self.SYSTEM_PROCS}:
                node_type = "system"
            node = {
                "pid":        pid,
                "name":       name,
                "type":       node_type,
                "user":       proc.get("user_name", ""),
                "path":       proc.get("process_path", ""),
                "cmdline":    proc.get("command_line", ""),
                "event_time": proc.get("event_time", ""),
                "depth":      i,
                "source":     proc.get("writer_source", proc.get("_source_table", "?")),
                "techniques": tag_process(name, proc.get("command_line", "")),
                "action":     proc.get("action"),
            }
            display.append(node)
        return display

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_all_entries(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM service_entries ORDER BY last_seen DESC"
        ).fetchall()
        result = []
        for r in rows:
            e = dict(r)
            e["techniques"] = json.loads(e.get("techniques") or "[]")
            result.append(e)
        return result

    def get_chain(self, entry_id: int) -> list[dict]:
        row = self.conn.execute(
            "SELECT chain_json FROM attack_chains WHERE entry_type='service' AND entry_id=?",
            (entry_id,),
        ).fetchone()
        if row:
            return json.loads(row["chain_json"])
        return self.build_attack_chain(entry_id)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SvcHunt - Service Persistence Collector")
    parser.add_argument("--scan",         action="store_true", help="Scan Windows services")
    parser.add_argument("--scan-all",     action="store_true", help="Include built-in services")
    parser.add_argument("--events",       action="store_true", help="Collect Event 4688 + 7045")
    parser.add_argument("--sysmon",       action="store_true", help="Collect Sysmon events")
    parser.add_argument("--hours",        type=int, default=BaseCollector.DEFAULT_HOURS)
    parser.add_argument("--chain",        type=int, metavar="ID")
    parser.add_argument("--chain-all",    action="store_true")
    parser.add_argument("--no-color",     action="store_true")
    parser.add_argument("--db",           default="reghunt.db")
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    args.hours = max(1, min(args.hours, BaseCollector.MAX_HOURS))
    col = ServiceCollector(db_path=args.db, collection_hours=args.hours)

    if args.scan or args.scan_all:
        print("[*] Scanning Windows services...")
        entries = col.collect_services(skip_builtin=not args.scan_all)
        print("[+] Found " + str(len(entries)) + " services")
        for e in entries:
            icon      = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(e["severity"], "⚪")
            sev_color = {"critical": Colors.RED, "high": Colors.YELLOW,
                         "medium": Colors.WHITE, "low": Colors.GREEN}.get(e["severity"], Colors.RESET)
            print("  " + icon + " " + sev_color + "[" + e["severity"].upper() + "]" +
                  Colors.RESET + " " + e["service_name"][:40].ljust(40) +
                  " -> " + e["binary_path"][:60])

    if args.sysmon:
        print("[*] Collecting Sysmon events (last " + str(args.hours) + "h)...")
        count = col.collect_sysmon_events()
        print("[+] Stored " + str(count) + " Sysmon events")

    if args.events:
        print("[*] Collecting Security 4688 + System 7045 events (last " + str(args.hours) + "h)...")
        count  = col.collect_process_events()
        count2 = col.collect_service_events()
        print("[+] Stored " + str(count) + " 4688 events, " + str(count2) + " 7045 events")

    if args.chain:
        chain = col.build_attack_chain(args.chain)
        if chain:
            print("[+] Chain depth: " + str(len(chain)) + " nodes\n")
            from registry_collector import format_chain_node
            for i, node in enumerate(chain):
                print(format_chain_node(node, "  " * i))
                print()
        else:
            print("[!] No chain found.")

    if args.chain_all:
        rows = col.conn.execute(
            "SELECT id, service_name, severity FROM service_entries "
            "WHERE severity IN ('high','critical') ORDER BY severity DESC, id"
        ).fetchall()
        print("[*] Building chains for " + str(len(rows)) + " High/Critical services...")
        from registry_collector import format_chain_node
        for row in rows:
            sev_color = Colors.RED if row["severity"] == "critical" else Colors.YELLOW
            print("\n" + Colors.BOLD + "--- Service " + str(row["id"]) + ": " +
                  row["service_name"] + " [" + sev_color + row["severity"].upper() +
                  Colors.RESET + Colors.BOLD + "] ---" + Colors.RESET)
            chain = col.build_attack_chain(row["id"])
            if chain:
                print()
                for i, node in enumerate(chain):
                    print(format_chain_node(node, "  " * i))
                    print()
            else:
                print("    [!] No chain")

    stats = col.get_stats()
    svc   = stats["services"]
    print()
    print(Colors.BOLD + "[*] Service Stats: " + str(sum(svc.values())) + " entries" + Colors.RESET)
    print("    Critical: " + Colors.RED    + str(svc["critical"]) + Colors.RESET +
          " | High: "      + Colors.YELLOW + str(svc["high"])     + Colors.RESET +
          " | Medium: "    + str(svc["medium"]) +
          " | Low: "       + Colors.GREEN  + str(svc["low"])      + Colors.RESET)
    col.close()