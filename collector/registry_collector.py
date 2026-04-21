"""
registry_collector.py
Collects registry Run/RunOnce persistence entries.
Correlates with Sysmon Event 13 + Event 1 / Security 4688.
Extends BaseCollector — all DB/event ingestion logic lives there.
"""

import os
import json
import hashlib
import winreg
from datetime import datetime

from base_collector import (
    BaseCollector, Colors, assess_severity,
    tag_registry, tag_process,
    normalise_reg_path, LOLBINS, SUSPICIOUS_PATHS,
    debug_print,
)

PERSISTENCE_KEYS = [
    {"hive": winreg.HKEY_LOCAL_MACHINE, "hive_name": "HKLM",
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",      "key_type": "Run"},
    {"hive": winreg.HKEY_CURRENT_USER,  "hive_name": "HKCU",
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",      "key_type": "Run"},
    {"hive": winreg.HKEY_LOCAL_MACHINE, "hive_name": "HKLM",
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",  "key_type": "RunOnce"},
    {"hive": winreg.HKEY_CURRENT_USER,  "hive_name": "HKCU",
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",  "key_type": "RunOnce"},
]

REGISTRY_WRITERS = (
    "reg.exe", "powershell.exe", "cmd.exe", "regedit.exe",
    "regini.exe", "python.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
)


class RegistryCollector(BaseCollector):

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def collect_registry(self) -> list[dict]:
        results = []
        for key_info in PERSISTENCE_KEYS:
            results.extend(self._read_key(key_info))
        return results

    def _read_key(self, key_info: dict) -> list[dict]:
        entries = []
        try:
            key = winreg.OpenKey(
                key_info["hive"], key_info["path"],
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
        except (FileNotFoundError, PermissionError):
            return []
        try:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    full_path  = key_info["hive_name"] + "\\" + key_info["path"]
                    data_str   = str(data)
                    severity, ioc = assess_severity(name, data_str)
                    hash_id    = hashlib.md5(
                        (full_path + "|" + name + "|" + data_str).encode()
                    ).hexdigest()
                    now = datetime.now().isoformat()
                    entry = {
                        "name":       name,
                        "hive":       key_info["hive_name"] + "\\" + key_info["key_type"],
                        "reg_path":   full_path,
                        "value_data": data_str,
                        "severity":   severity,
                        "ioc_notes":  ioc,
                        "techniques": json.dumps(
                            tag_registry(key_info["hive_name"] + "\\" + key_info["key_type"],
                                         full_path)
                        ),
                        "first_seen": now,
                        "last_seen":  now,
                        "hash_id":    hash_id,
                    }
                    entries.append(entry)
                    self._upsert_entry(entry)
                    i += 1
                except OSError:
                    break
            # recurse into subkeys
            j = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, j)
                    sub_info    = {**key_info, "path": key_info["path"] + "\\" + subkey_name}
                    entries.extend(self._read_key(sub_info))
                    j += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)
        return entries

    def _upsert_entry(self, entry: dict):
        self.conn.execute("""
            INSERT INTO registry_entries
                (name, hive, reg_path, value_data, severity, ioc_notes,
                 techniques, first_seen, last_seen, hash_id)
            VALUES (:name, :hive, :reg_path, :value_data, :severity, :ioc_notes,
                    :techniques, :first_seen, :last_seen, :hash_id)
            ON CONFLICT(hash_id) DO UPDATE SET
                severity   = excluded.severity,
                ioc_notes  = excluded.ioc_notes,
                techniques = excluded.techniques,
                last_seen  = excluded.last_seen
        """, entry)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Chain building
    # ------------------------------------------------------------------

    def build_attack_chain(self, reg_entry_id: int) -> list[dict]:
        entry = self.conn.execute(
            "SELECT * FROM registry_entries WHERE id = ?", (reg_entry_id,)
        ).fetchone()
        if not entry:
            return []
        entry = dict(entry)

        writer = self._find_writer(entry)

        if writer.get("writer_source") == "unknown":
            chain = [self._make_node(writer, 0, is_writer=True, entry=entry)]
            self._save_chain("registry", reg_entry_id, chain)
            return chain

        writer["_is_writer"] = True
        nodes = self._walk_chain(writer)

        # annotate the writer node with the registry action
        for node in nodes:
            if node.get("_is_writer"):
                node["action"] = {
                    "type":  "reg",
                    "label": ("Wrote " + entry["hive"] + " -> " + entry["name"] +
                              " = " + entry["value_data"][:60]),
                }
                node["techniques"] = tag_process(
                    node.get("process_name", ""),
                    node.get("command_line", ""),
                )
                break

        # build display nodes
        chain = []
        for i, proc in enumerate(nodes):
            chain.append(self._make_node(proc, i,
                                         is_writer=proc.get("_is_writer", False),
                                         entry=entry if proc.get("_is_writer") else None))

        self._save_chain("registry", reg_entry_id, chain)
        return chain

    def get_chain(self, entry_id: int) -> list[dict]:
        row = self.conn.execute(
            "SELECT chain_json FROM attack_chains WHERE entry_type='registry' AND entry_id=?",
            (entry_id,),
        ).fetchone()
        if row:
            return json.loads(row["chain_json"])
        return self.build_attack_chain(entry_id)

    # ------------------------------------------------------------------
    # Writer finding (registry-specific, with PID-reuse fix)
    # ------------------------------------------------------------------

    def _find_writer(self, entry: dict) -> dict:
        reg_path   = entry["reg_path"]
        value_name = entry["name"]
        last_seen  = entry.get("last_seen") or datetime.now().isoformat()

        # 1. Sysmon Event 13 exact match (PID + timestamp)
        row = self.conn.execute("""
            SELECT sre.pid,
                   sre.process_path,
                   sre.process_name  AS reg_proc_name,
                   sre.event_time    AS reg_time,
                   spe.parent_pid,
                   spe.command_line,
                   spe.user_name,
                   spe.process_name  AS proc_name,
                   spe.event_time    AS proc_time
            FROM sysmon_registry_events sre
            LEFT JOIN sysmon_process_events spe
                   ON sre.pid = spe.pid AND spe.event_time <= sre.event_time
            WHERE LOWER(sre.key_path)   = LOWER(?)
              AND LOWER(sre.value_name) = LOWER(?)
            ORDER BY sre.event_time DESC, spe.event_time DESC
            LIMIT 1
        """, (reg_path, value_name)).fetchone()

        if row:
            result = dict(row)
            result["writer_source"] = "sysmon_exact"
            result["process_name"]  = result.get("proc_name") or result.get("reg_proc_name", "unknown")
            result["command_line"]  = result.get("command_line") or ""
            # Remap aliased columns to the standard names _walk_chain expects
            result["event_time"]    = result.get("proc_time") or result.get("reg_time")
            result["process_path"]  = result.get("process_path") or ""
            return result

        # 2. Fallback: match by executable name in process_events (timestamp-guarded)
        value_data = entry.get("value_data") or ""
        exe_token  = value_data.strip().split()[0] if value_data.strip() else ""
        exe_path   = exe_token.strip('"')
        exe_name   = os.path.basename(exe_path)

        if not exe_name:
            return self._create_unknown_writer(entry)

        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE LOWER(process_name) = LOWER(?) AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, (exe_name, last_seen)).fetchone()

        if row:
            result = dict(row)
            result["writer_source"] = "4688"
            return result

        row = self.conn.execute("""
            SELECT * FROM process_events
            WHERE LOWER(process_name) LIKE ? AND event_time <= ?
            ORDER BY event_time DESC LIMIT 1
        """, ("%" + exe_name.lower() + "%", last_seen)).fetchone()

        if row:
            result = dict(row)
            result["writer_source"] = "4688"
            return result

        # 3. Last resort: known registry writing tools with matching cmdline
        for tool in REGISTRY_WRITERS:
            row = self.conn.execute("""
                SELECT * FROM process_events
                WHERE LOWER(process_name) = ?
                  AND event_time <= ?
                  AND (LOWER(command_line) LIKE ? OR LOWER(command_line) LIKE ?)
                ORDER BY event_time DESC LIMIT 1
            """, (tool, last_seen,
                  "%" + value_name.lower() + "%",
                  "%" + exe_path.lower() + "%")).fetchone()
            if row:
                result = dict(row)
                result["writer_source"] = "4688-indirect(" + tool + ")"
                return result

        return self._create_unknown_writer(entry)

    def _create_unknown_writer(self, entry: dict) -> dict:
        value     = entry.get("value_data") or ""
        exe_token = value.strip().split()[0] if value.strip() else ""
        exe_path  = exe_token.strip('"')
        exe_name  = os.path.basename(exe_path) if exe_path else "unknown.exe"
        return {
            "pid":           None,
            "process_name":  exe_name,
            "process_path":  exe_path or "unknown",
            "command_line":  value,
            "user_name":     None,
            "event_time":    entry.get("last_seen"),
            "parent_pid":    None,
            "writer_source": "unknown",
            "unknown_reason": self._diagnose_unknown(entry),
            "first_seen":    entry.get("first_seen", "unknown"),
        }

    def _diagnose_unknown(self, entry: dict) -> str:
        from base_collector import PYWIN32_AVAILABLE
        if not PYWIN32_AVAILABLE:
            return "pywin32 not available"
        first_seen = entry.get("first_seen")
        if first_seen and first_seen != "unknown":
            try:
                from datetime import datetime, timedelta
                fs     = datetime.fromisoformat(first_seen)
                cutoff = datetime.utcnow() - timedelta(hours=self.collection_hours)
                if fs < cutoff:
                    return ("Entry created before monitoring window "
                            "(" + str(self.collection_hours) + "h)")
            except Exception:
                pass
        if entry.get("hive", "").startswith("HKLM"):
            return "System hive entry"
        sysmon_count = self.conn.execute(
            "SELECT COUNT(*) FROM sysmon_registry_events"
        ).fetchone()[0]
        if sysmon_count == 0:
            return "No Sysmon events in database"
        return "No matching event log entry found"

    # ------------------------------------------------------------------
    # Node display builder
    # ------------------------------------------------------------------

    def _make_node(self, proc: dict, depth: int,
                   is_writer: bool, entry: dict | None = None) -> dict:
        proc_name = proc.get("process_name") or "unknown"
        cmdline   = proc.get("command_line") or ""
        pid       = proc.get("pid")
        source    = proc.get("writer_source", "sysmon/4688")

        if source == "unknown":
            return {
                "pid":           None,
                "name":          proc_name,
                "type":          "unknown",
                "user":          proc.get("user_name") or "unknown",
                "path":          proc.get("process_path") or "unknown",
                "cmdline":       cmdline,
                "event_time":    proc.get("event_time") or "",
                "depth":         depth,
                "source":        "unknown",
                "unknown_reason": proc.get("unknown_reason", "No event log data"),
                "techniques":    tag_process(proc_name, cmdline),
                "action": {
                    "type":  "reg",
                    "label": "Wrote " + entry["hive"] + " -> " + entry["name"],
                } if entry else None,
            }

        node_type = self._classify_node(proc)
        # override: system processes
        name_l = proc_name.lower()
        if pid in self.SYSTEM_PIDS or name_l in {p.lower() for p in self.SYSTEM_PROCS}:
            node_type = "system"

        node = {
            "pid":        pid,
            "name":       proc_name,
            "type":       node_type,
            "user":       proc.get("user_name") or "",
            "path":       proc.get("process_path") or "",
            "cmdline":    cmdline,
            "event_time": proc.get("event_time") or "",
            "depth":      depth,
            "source":     source,
            "techniques": tag_process(proc_name, cmdline),
            "action":     None,
        }

        if is_writer and entry:
            node["action"] = {
                "type":  "reg",
                "label": ("Wrote " + entry["hive"] + " -> " + entry["name"] +
                          " = " + entry["value_data"][:60]),
            }

        return node

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Chain display (shared formatting used by CLI)
# ---------------------------------------------------------------------------

def format_chain_node(node: dict, indent: str, show_cmdline: bool = True) -> str:
    lines = []

    color_map = {
        "system":    Colors.GREY + Colors.DIM,
        "normal":    Colors.GREEN,
        "suspicious": Colors.YELLOW,
        "malicious": Colors.RED + Colors.BOLD,
        "unknown":   Colors.GREY,
    }
    icon_map = {
        "system": "⚙️", "normal": "📦",
        "suspicious": "⚠️", "malicious": "💀", "unknown": "❓",
    }
    color = color_map.get(node.get("type"), Colors.RESET)
    icon  = icon_map.get(node.get("type"), "❓")

    if node.get("source") == "unknown":
        main = indent + icon + " " + node["name"] + " (PID unknown) [unknown]"
        lines.append(color + main + Colors.RESET)
        if node.get("unknown_reason"):
            lines.append(indent + Colors.YELLOW + "   ⚠️  " + node["unknown_reason"] + Colors.RESET)
    else:
        src_badge = "[" + node.get("source", "?") + "]"
        user_str  = node.get("user", "")
        main      = (indent + icon + " " + node["name"] +
                     " (PID " + str(node["pid"]) + ") " + src_badge)
        if user_str:
            main += " - " + user_str
        lines.append(color + main + Colors.RESET)

    if show_cmdline and node.get("cmdline"):
        cmd = node["cmdline"]
        if len(cmd) > 80:
            cmd = cmd[:77] + "..."
        lines.append(indent + Colors.DIM + "   📝 " + cmd + Colors.RESET)

    if node.get("action"):
        lines.append(indent + Colors.CYAN + "   -> " + node["action"]["label"] + Colors.RESET)

    if node.get("techniques"):
        techs = ", ".join(t["id"] for t in node["techniques"])
        lines.append(indent + Colors.MAGENTA + "   📌 " + techs + Colors.RESET)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RegHunt - Registry Persistence Collector")
    parser.add_argument("--scan",      action="store_true", help="Scan registry persistence keys")
    parser.add_argument("--events",    action="store_true", help="Collect Event ID 4688")
    parser.add_argument("--sysmon",    action="store_true", help="Collect Sysmon events")
    parser.add_argument("--hours",     type=int, default=BaseCollector.DEFAULT_HOURS,
                        help="Hours back (default: 24)")
    parser.add_argument("--chain",     type=int, metavar="ID",
                        help="Build attack chain for entry ID")
    parser.add_argument("--chain-all", action="store_true",
                        help="Build chains for all High/Critical entries")
    parser.add_argument("--no-color",  action="store_true", help="Disable colored output")
    parser.add_argument("--no-cmdline",action="store_true", help="Hide command lines")
    parser.add_argument("--db",        default="reghunt.db", help="Database path")
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    args.hours = max(1, min(args.hours, BaseCollector.MAX_HOURS))

    col = RegistryCollector(db_path=args.db, collection_hours=args.hours)

    if args.scan:
        print("[*] Scanning registry persistence keys...")
        entries = col.collect_registry()
        print("[+] Found " + str(len(entries)) + " entries")
        for e in entries:
            icon      = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(e["severity"], "⚪")
            sev_color = {"critical": Colors.RED, "high": Colors.YELLOW,
                         "medium": Colors.WHITE, "low": Colors.GREEN}.get(e["severity"], Colors.RESET)
            print("  " + icon + " " + sev_color + "[" + e["severity"].upper() + "]" +
                  Colors.RESET + " " + e["name"][:40].ljust(40) + " -> " + e["value_data"][:60])

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
            print("[+] Chain depth: " + str(len(chain)) + " nodes\n")
            for i, node in enumerate(chain):
                print(format_chain_node(node, "  " * i,
                                        show_cmdline=not args.no_cmdline))
                print()
        else:
            print("[!] No chain found.")

    if args.chain_all:
        print("[*] Building chains for all High/Critical entries...")
        rows = col.conn.execute(
            "SELECT id, name, severity FROM registry_entries "
            "WHERE severity IN ('high','critical') ORDER BY severity DESC, id"
        ).fetchall()
        print("[+] Found " + str(len(rows)) + " High/Critical entries")
        for row in rows:
            sev_color = Colors.RED if row["severity"] == "critical" else Colors.YELLOW
            print("\n" + Colors.BOLD + "--- Entry " + str(row["id"]) + ": " +
                  row["name"] + " [" + sev_color + row["severity"].upper() +
                  Colors.RESET + Colors.BOLD + "] ---" + Colors.RESET)
            chain = col.build_attack_chain(row["id"])
            if chain:
                print()
                for i, node in enumerate(chain):
                    print(format_chain_node(node, "  " * i,
                                            show_cmdline=not args.no_cmdline))
                    print()
            else:
                print("    [!] No chain")

    stats = col.get_stats()
    print()
    reg = stats["registry"]
    print(Colors.BOLD + "[*] Registry Stats: " +
          str(sum(reg.values())) + " entries" + Colors.RESET)
    print("    Critical: " + Colors.RED   + str(reg["critical"]) + Colors.RESET +
          " | High: "      + Colors.YELLOW + str(reg["high"])     + Colors.RESET +
          " | Medium: "    + str(reg["medium"]) +
          " | Low: "       + Colors.GREEN  + str(reg["low"])      + Colors.RESET)
    print("    4688 events: " + str(stats["process_events"]) +
          " | Sysmon events: " + str(stats["sysmon_events"]))
    col.close()