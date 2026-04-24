"""
task_collector.py
Collects scheduled task persistence entries.
Correlates with Security Event 4698 (task created) using time-based matching.
Extends BaseCollector.
"""

import os
import json
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

from base_collector import (
    BaseCollector, Colors, assess_severity,
    tag_task, tag_process,
    LOLBINS, SUSPICIOUS_PATHS,
    debug_print, PYWIN32_AVAILABLE,
)

try:
    import win32evtlog
    import pywintypes
except ImportError:
    pass

# How many seconds either side of a task-created event to search for the creator process
TASK_CORRELATION_WINDOW_SECS = 60

# Task path prefixes that are Windows-provisioned at OS install time.
# These are never malicious chain-build candidates — skip chain building for them.
# COM handler tasks and System32-only binaries under these paths are pure noise.
BUILTIN_TASK_PREFIXES = (
    "\\microsoft\\windows\\",
    "\\microsoft\\office\\",
    "\\microsoft\\onecore\\",
    "\\microsoft\\xblgamesave\\",
)

# If a task's command is one of these it cannot be correlated — skip chain building.
UNCHAINABLE_COMMANDS = {"com handler", "multiple actions", "", None}

# Binaries that are always System32/SysWOW64 — not suspicious on their own.
# Only flag these HIGH if they have attack-grade flags in the arguments.
SYSTEM32_LOLBINS_TASK = {
    "rundll32.exe", "regsvr32.exe", "msiexec.exe",
    "dsregcmd.exe", "usoclient.exe", "sc.exe",
    "cleanmgr.exe", "defrag.exe", "sdbinst.exe",
}


class TaskCollector(BaseCollector):

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def collect_tasks(self) -> list[dict]:
        """Enumerate all scheduled tasks via schtasks /query."""
        entries = []
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                capture_output=True, text=True, timeout=30,
            )
            raw = result.stdout
        except Exception as e:
            print("[!] schtasks query failed:", e)
            return []

        # Also pull XML for each task to get richer data
        try:
            xml_result = subprocess.run(
                ["schtasks", "/query", "/fo", "XML", "/nh"],
                capture_output=True, text=True, timeout=30,
            )
            task_xmls = self._parse_task_xml_output(xml_result.stdout)
        except Exception:
            task_xmls = {}

        current = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                if current:
                    entry = self._process_task_record(current, task_xmls)
                    if entry:
                        entries.append(entry)
                        self._upsert_task(entry)
                    current = {}
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                current[key.strip()] = val.strip()

        if current:
            entry = self._process_task_record(current, task_xmls)
            if entry:
                entries.append(entry)
                self._upsert_task(entry)

        return entries

    def _parse_task_xml_output(self, xml_output: str) -> dict:
        """Parse schtasks XML output into a dict keyed by task name."""
        task_xmls = {}
        # schtasks /query /fo XML outputs multiple XML documents
        # split on <?xml
        parts = xml_output.split("<?xml")
        for part in parts:
            if not part.strip():
                continue
            try:
                root = ET.fromstring("<?xml" + part)
                ns   = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
                # Get RegistrationInfo/URI for task name
                uri_elem = root.find(".//" + ns + "URI")
                if uri_elem is None:
                    # Try without namespace
                    uri_elem = root.find(".//URI")
                if uri_elem is not None:
                    task_xmls[uri_elem.text] = root
            except Exception:
                pass
        return task_xmls

    def _process_task_record(self, record: dict, task_xmls: dict) -> dict | None:
        task_name = (record.get("TaskName") or record.get("Folder") or "").strip()
        if not task_name or task_name == "TaskName":
            return None

        # Extract command from "Task To Run" field
        command   = record.get("Task To Run", "").strip()
        run_as    = record.get("Run As User", "").strip()
        status    = record.get("Status", "").strip()
        enabled   = 0 if status.lower() in ("disabled",) else 1

        # Try to get richer data from XML
        trigger_type = "Unknown"
        arguments    = ""
        if task_name in task_xmls:
            root = task_xmls[task_name]
            ns   = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
            # Get arguments
            args_elem = root.find(".//" + ns + "Arguments")
            if args_elem is not None:
                arguments = args_elem.text or ""
            # Get trigger type
            triggers = root.find(".//" + ns + "Triggers")
            if triggers is not None and len(triggers):
                trigger_type = triggers[0].tag.replace(ns, "").replace("Trigger", "")

        full_value = (command + " " + arguments).strip()
        severity, ioc = assess_severity(task_name, full_value)

        # Escalate if run_as is SYSTEM and command is suspicious
        if "system" in run_as.lower() and severity in ("medium", "low"):
            cmd_lower = full_value.lower()
            if any(lol in cmd_lower for lol in LOLBINS):
                severity = "high"
                ioc = "SYSTEM-level task using LOLBin"

        hash_id  = hashlib.md5((task_name + "|" + full_value).encode()).hexdigest()
        now      = datetime.now().isoformat()

        return {
            "task_name":    task_name,
            "task_path":    task_name,
            "command":      command,
            "arguments":    arguments,
            "run_as":       run_as,
            "trigger_type": trigger_type,
            "enabled":      enabled,
            "severity":     severity,
            "ioc_notes":    ioc,
            "techniques":   json.dumps(tag_task(task_name)),
            "first_seen":   now,
            "last_seen":    now,
            "hash_id":      hash_id,
        }

    def _upsert_task(self, entry: dict):
        self.conn.execute("""
            INSERT INTO task_entries
                (task_name, task_path, command, arguments, run_as, trigger_type,
                 enabled, severity, ioc_notes, techniques, first_seen, last_seen, hash_id)
            VALUES (:task_name, :task_path, :command, :arguments, :run_as, :trigger_type,
                    :enabled, :severity, :ioc_notes, :techniques, :first_seen, :last_seen, :hash_id)
            ON CONFLICT(hash_id) DO UPDATE SET
                severity     = excluded.severity,
                ioc_notes    = excluded.ioc_notes,
                enabled      = excluded.enabled,
                last_seen    = excluded.last_seen
        """, entry)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Event 4698 collection (task created)
    # ------------------------------------------------------------------

    def collect_task_events(self, hours_back: int = None) -> int:
        """Collect Security Event 4698 (Scheduled Task Created)."""
        if hours_back is None:
            hours_back = self.collection_hours
        if not PYWIN32_AVAILABLE:
            return 0

        ms_back = hours_back * 3600000
        cutoff  = datetime.utcnow() - timedelta(hours=hours_back)
        xpath   = ("*[System[EventID=4698 and TimeCreated"
                   "[timediff(@SystemTime) <= " + str(ms_back) + "]]]")
        count   = 0
        try:
            qh = win32evtlog.EvtQuery(
                "Security",
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath, None,
            )
        except Exception as e:
            debug_print("Cannot open Security log for 4698:", e)
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
                        xml_str = win32evtlog.EvtRender(eh, win32evtlog.EvtRenderEventXml)
                        if self._store_task_event(xml_str, cutoff):
                            count += 1
                    except Exception:
                        pass
        finally:
            try:
                win32evtlog.EvtClose(qh)
            except Exception:
                pass
        return count

    def _store_task_event(self, xml_str: str, cutoff: datetime) -> bool:
        """Store a 4698 event in a dedicated table for task creation events."""
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

            task_name    = fields.get("TaskName", "")
            subject_user = fields.get("SubjectUserName", "")
            subject_sid  = fields.get("SubjectUserSid", "")

            # Ensure table exists
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS task_creation_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_name    TEXT,
                    subject_user TEXT,
                    subject_sid  TEXT,
                    event_time   TEXT
                )
            """)
            self.conn.execute("""
                INSERT OR IGNORE INTO task_creation_events
                    (task_name, subject_user, subject_sid, event_time)
                VALUES (?, ?, ?, ?)
            """, (task_name, subject_user, subject_sid, event_dt.isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            debug_print("Error storing task event:", e)
            return False

    # ------------------------------------------------------------------
    # Chain skip decision
    # ------------------------------------------------------------------

    def _should_skip_chain(self, entry: dict) -> str | None:
        """
        Return a skip reason string if chain building is pointless for this
        task, or None if we should proceed normally.
        """
        task_name = (entry.get("task_name") or "").lower().replace("/", "\\")
        # Ensure task_name starts with backslash for consistent prefix matching
        if task_name and not task_name.startswith("\\"):
            task_name = "\\" + task_name
        command   = (entry.get("command")   or "").strip().lower()

        # COM handler / multiple actions — no executable to correlate
        if command in {c.lower() for c in UNCHAINABLE_COMMANDS if c}:
            return "COM handler or multiple actions — no executable to correlate"

        # Windows-provisioned built-in task paths
        if any(task_name.startswith(p) for p in BUILTIN_TASK_PREFIXES):
            # Still chain if command has attack-grade flags — could be tampered
            attack_flags = ["-enc", "-nop", "bypass", "hidden",
                            "http://", "https://", "iex(", "downloadstring"]
            full_cmd = command + " " + (entry.get("arguments") or "").lower()
            if not any(f in full_cmd for f in attack_flags):
                return "Windows built-in task — pre-provisioned at OS install"

        return None

    # ------------------------------------------------------------------
    # Chain building (time-based correlation)
    # ------------------------------------------------------------------

    def build_attack_chain(self, task_entry_id: int) -> list[dict]:
        entry = self.conn.execute(
            "SELECT * FROM task_entries WHERE id = ?", (task_entry_id,)
        ).fetchone()
        if not entry:
            return []
        entry = dict(entry)

        # Check if chain building is pointless for this task
        skip_reason = self._should_skip_chain(entry)
        if skip_reason:
            chain = [{
                "pid":           None,
                "name":          "Skipped",
                "type":          "system",
                "user":          entry.get("run_as", ""),
                "path":          entry.get("command", ""),
                "cmdline":       entry.get("command", ""),
                "event_time":    entry.get("last_seen", ""),
                "depth":         0,
                "source":        "skipped",
                "unknown_reason": skip_reason,
                "techniques":    tag_task(entry["task_name"]),
                "action": {
                    "type":  "task",
                    "label": "Created Task: " + entry["task_name"],
                },
            }]
            self._save_chain("task", task_entry_id, chain)
            return chain

        writer = self._find_task_writer(entry)

        if writer.get("writer_source") == "unknown":
            chain = [{
                "pid":           None,
                "name":          "Unknown",
                "type":          "unknown",
                "user":          entry.get("run_as", "unknown"),
                "path":          entry.get("command", "unknown"),
                "cmdline":       entry.get("command", ""),
                "event_time":    entry.get("last_seen", ""),
                "depth":         0,
                "source":        "unknown",
                "unknown_reason": writer.get("unknown_reason", "No event log data"),
                "techniques":    tag_task(entry["task_name"]),
                "action": {
                    "type":  "task",
                    "label": "Created Task: " + entry["task_name"],
                },
            }]
            self._save_chain("task", task_entry_id, chain)
            return chain

        writer["_is_writer"] = True
        nodes = self._walk_chain(writer)

        for node in nodes:
            if node.get("_is_writer"):
                node["action"] = {
                    "type":  "task",
                    "label": "Created Task: " + entry["task_name"] +
                             " -> " + entry.get("command", "")[:50],
                }
                node["techniques"] = (
                    tag_process(node.get("process_name", ""), node.get("command_line", "")) +
                    tag_task(entry["task_name"])
                )
                break

        chain = self._nodes_to_display(nodes)
        self._save_chain("task", task_entry_id, chain)
        return chain

    def _find_task_writer(self, entry: dict) -> dict:
        """
        Find the process that created this task.
        Strategy (in order):
          0. Sysmon Event 11 FileCreate on Tasks folder — most reliable,
             fires while creator is still alive, no race condition.
          1. Security Event 4698 + Sysmon process match by time window.
          2. Cmdline token fallback across sysmon + 4688.
        """
        task_name = entry["task_name"]
        last_seen = entry.get("last_seen") or datetime.now().isoformat()
        task_leaf = task_name.split("\\")[-1]

        # ------------------------------------------------------------------
        # Pass 0 — Sysmon Event 11 FileCreate (best source)
        # Task XML is written to C:\Windows\System32\Tasks\<name> at creation
        # time. The writer PID is captured while the process is still alive.
        # ------------------------------------------------------------------
        try:
            row = self.conn.execute("""
                SELECT sfe.pid,
                       sfe.process_name,
                       sfe.process_path,
                       sfe.event_time,
                       spe.parent_pid,
                       spe.command_line,
                       spe.user_name
                FROM sysmon_file_events sfe
                LEFT JOIN sysmon_process_events spe
                       ON sfe.pid = spe.pid
                      AND spe.event_time <= sfe.event_time
                      AND spe.event_time >= datetime(sfe.event_time, '-300 seconds')
                WHERE LOWER(sfe.target_file) LIKE ?
                ORDER BY sfe.event_time DESC LIMIT 1
            """, ("%" + task_leaf.lower() + "%",)).fetchone()

            if row:
                result = dict(row)
                result["writer_source"] = "sysmon-filecreate"
                result["process_name"]  = result.get("process_name") or "unknown"
                result["event_time"]    = result.get("event_time") or last_seen
                return result
        except Exception as e:
            debug_print("FileCreate lookup failed:", e)

        # Check task_creation_events table
        try:
            row = self.conn.execute("""
                SELECT task_name, subject_user, event_time
                FROM task_creation_events
                WHERE LOWER(task_name) LIKE ?
                ORDER BY event_time DESC LIMIT 1
            """, ("%" + task_name.lower() + "%",)).fetchone()
        except Exception:
            row = None

        if row:
            creation_time = row["event_time"]
            user          = row["subject_user"]

            # Window: TASK_CORRELATION_WINDOW_SECS before and after creation
            try:
                ct_dt      = datetime.fromisoformat(creation_time)
                window_low = (ct_dt - timedelta(seconds=TASK_CORRELATION_WINDOW_SECS)).isoformat()
                window_hi  = (ct_dt + timedelta(seconds=TASK_CORRELATION_WINDOW_SECS)).isoformat()
            except Exception:
                window_low = creation_time
                window_hi  = creation_time

            # Look for schtasks.exe or powershell.exe that ran around that time
            # For schtasks.exe we additionally require the task name in cmdline to avoid false matches
            for tool in ("schtasks.exe", "powershell.exe", "cmd.exe", "pwsh.exe"):
                if tool == "schtasks.exe":
                    # Must have task name or /create in cmdline for schtasks
                    proc_row = self.conn.execute("""
                        SELECT pid, parent_pid, process_name, process_path,
                               command_line, user_name, event_time
                        FROM sysmon_process_events
                        WHERE LOWER(process_name) = ?
                          AND event_time BETWEEN ? AND ?
                          AND (LOWER(command_line) LIKE '%/create%'
                               OR LOWER(command_line) LIKE ?)
                        ORDER BY ABS(JULIANDAY(event_time) - JULIANDAY(?))
                        LIMIT 1
                    """, (tool, window_low, window_hi,
                          "%" + task_name.split("\\")[-1].lower() + "%",
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
                    result["writer_source"] = "4698+sysmon"
                    return result

            # Removed: loose "any process in window" fallback — caused false attributions

        # No 4698 event — try matching by task command tokens in process cmdline.
        # Tokenize the full command so "cmd.exe /c nvm.exe" extracts "nvm.exe"
        # rather than just "cmd.exe" which is in the skip list.
        cmd = entry.get("command", "")
        args = entry.get("arguments", "")
        full_cmd = (cmd + " " + args).strip()

        # Extract all .exe tokens from the command, skip generic LOLBins
        import re as _re
        exe_tokens = _re.findall(r'[\w\-.]+\.exe', full_cmd, _re.IGNORECASE)
        _generic = {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe",
                    "regsvr32.exe", "msiexec.exe", "wscript.exe", "cscript.exe"}
        specific_tokens = [t.lower() for t in exe_tokens
                           if t.lower() not in _generic]

        # Also try the task name leaf as a search token
        task_leaf = task_name.split("\\")[-1].lower()

        search_tokens = specific_tokens or ([task_leaf] if task_leaf else [])

        for token in search_tokens:
            proc_row = self.conn.execute("""
                SELECT pid, parent_pid, process_name, process_path,
                       command_line, user_name, event_time
                FROM sysmon_process_events
                WHERE LOWER(command_line) LIKE ?
                  AND event_time <= ?
                ORDER BY event_time DESC LIMIT 1
            """, ("%" + token + "%", last_seen)).fetchone()

            if not proc_row:
                proc_row = self.conn.execute("""
                    SELECT pid, parent_pid, process_name, process_path,
                           command_line, user_name, event_time
                    FROM process_events
                    WHERE LOWER(command_line) LIKE ?
                      AND event_time <= ?
                    ORDER BY event_time DESC LIMIT 1
                """, ("%" + token + "%", last_seen)).fetchone()

            if proc_row:
                result = dict(proc_row)
                result["writer_source"] = "sysmon-cmdline"
                return result

        return {
            "writer_source":  "unknown",
            "unknown_reason": self._diagnose_task_unknown(entry),
        }

    def _diagnose_task_unknown(self, entry: dict) -> str:
        """Explain why no chain could be built for this task."""
        first_seen = entry.get("first_seen")
        if first_seen:
            try:
                fs     = datetime.fromisoformat(first_seen)
                cutoff = datetime.utcnow() - timedelta(hours=self.collection_hours)
                if fs < cutoff:
                    age_hours = int((datetime.utcnow() - fs).total_seconds() / 3600)
                    return (
                        f"Pre-monitoring install (~{age_hours}h old) — "
                        f"outside the {self.collection_hours}h window. "
                        "Re-run with --hours, or enable Security audit policy: "
                        "'auditpol /set /subcategory:\"Other Object Access Events\" /success:enable'"
                    )
            except Exception:
                pass

        ev4698 = 0
        try:
            ev4698 = self.conn.execute(
                "SELECT COUNT(*) FROM task_creation_events"
            ).fetchone()[0]
        except Exception:
            pass

        if ev4698 == 0:
            return (
                "No Security Event 4698 (task created) in DB — "
                "enable audit policy: "
                "'auditpol /set /subcategory:\"Other Object Access Events\" /success:enable'"
            )

        sysmon = self.conn.execute(
            "SELECT COUNT(*) FROM sysmon_process_events"
        ).fetchone()[0]
        if sysmon == 0:
            return "No Sysmon process events in DB — install Sysmon or check config"

        return (
            "4698 event found but no matching process in window — "
            "creator process may have exited before Sysmon captured it"
        )

    def _nodes_to_display(self, nodes: list[dict]) -> list[dict]:
        """Convert raw process dicts to display nodes."""
        display = []
        for i, proc in enumerate(nodes):
            node_type = self._classify_node(proc)
            name      = proc.get("process_name", "unknown")
            pid       = proc.get("pid")
            source    = proc.get("writer_source") or proc.get("_source_table") or "?"

            # Override classification for known boundary types
            name_l = name.lower()
            if pid in self.SYSTEM_PIDS or name_l in {p.lower() for p in self.SYSTEM_PROCS}:
                node_type = "system"
            elif name_l in {p.lower() for p in self.SHELL_PROCS}:
                node_type = "normal"
            elif source == "stub":
                node_type = "normal"

            node = {
                "pid":        pid,
                "name":       name,
                "type":       node_type,
                "user":       proc.get("user_name", ""),
                "path":       proc.get("process_path", ""),
                "cmdline":    proc.get("command_line", ""),
                "event_time": proc.get("event_time", ""),
                "depth":      i,
                "source":     source,
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
            "SELECT * FROM task_entries ORDER BY last_seen DESC"
        ).fetchall()
        result = []
        for r in rows:
            e = dict(r)
            e["techniques"] = json.loads(e.get("techniques") or "[]")
            result.append(e)
        return result

    def get_chain(self, entry_id: int) -> list[dict]:
        row = self.conn.execute(
            "SELECT chain_json FROM attack_chains WHERE entry_type='task' AND entry_id=?",
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

    parser = argparse.ArgumentParser(description="TaskHunt - Scheduled Task Persistence Collector")
    parser.add_argument("--scan",      action="store_true", help="Scan scheduled tasks")
    parser.add_argument("--events",    action="store_true", help="Collect Event ID 4688 + 4698")
    parser.add_argument("--sysmon",    action="store_true", help="Collect Sysmon events")
    parser.add_argument("--hours",     type=int, default=BaseCollector.DEFAULT_HOURS)
    parser.add_argument("--chain",     type=int, metavar="ID")
    parser.add_argument("--chain-all", action="store_true")
    parser.add_argument("--no-color",  action="store_true")
    parser.add_argument("--db",        default="reghunt.db")
    parser.add_argument("--baseline",  action="store_true",
                        help="Snapshot current entries as new baseline")
    parser.add_argument("--diff",      action="store_true",
                        help="Only show entries NEW since last baseline")
    parser.add_argument("--mark-safe", type=str, metavar="HASH_ID",
                        help="Mark entry hash as safe in active baseline")
    parser.add_argument("--baselines", action="store_true",
                        help="List all saved baselines")
    parser.add_argument("--json",      action="store_true",
                        help="Export results to JSON file")
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    args.hours = max(1, min(args.hours, BaseCollector.MAX_HOURS))
    col = TaskCollector(db_path=args.db, collection_hours=args.hours)

    # ── Baseline management ──────────────────────────────────────────
    if args.baselines:
        bls = col.list_baselines()
        if not bls:
            print("[*] No baselines saved yet. Run --baseline after a scan.")
        else:
            print("[*] Saved baselines:")
            for b in bls:
                print("  [" + str(b["id"]) + "] " + b["name"] +
                      " | " + b["created_at"][:19] +
                      " | " + str(b["entry_count"]) + " entries" +
                      (" | " + b["note"] if b["note"] else ""))

    if args.mark_safe:
        if col.mark_safe("task", args.mark_safe):
            print("[+] Marked hash " + args.mark_safe + " as safe in active baseline.")
        else:
            print("[!] Failed to mark safe.")

    if args.scan:
        print("[*] Scanning scheduled tasks...")
        entries = col.collect_tasks()

        if args.diff:
            new_entries = col.get_new_entries("task", "task_entries")
            new_hashes  = {e["hash_id"] for e in new_entries}
            entries     = [e for e in entries if e["hash_id"] in new_hashes]
            bl = col.get_active_baseline()
            bl_date = bl["created_at"][:19] if bl else "never"
            print("[+] Found " + str(len(entries)) +
                  " NEW tasks since baseline (" + bl_date + ")")
            if not entries:
                print("    ✅ No new scheduled tasks since last baseline.")
        else:
            print("[+] Found " + str(len(entries)) + " tasks")

        for e in entries:
            icon      = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(e["severity"], "⚪")
            sev_color = {"critical": Colors.RED, "high": Colors.YELLOW,
                         "medium": Colors.WHITE, "low": Colors.GREEN}.get(e["severity"], Colors.RESET)
            new_badge = Colors.CYAN + " [NEW]" + Colors.RESET if args.diff else ""
            print("  " + icon + " " + sev_color + "[" + e["severity"].upper() + "]" +
                  Colors.RESET + new_badge + " " + e["task_name"][:50].ljust(50) +
                  " -> " + e["command"][:50])

    if args.baseline:
        bl_id = col.create_baseline(note="manual snapshot")
        count = col.conn.execute(
            "SELECT COUNT(*) FROM baseline_entries WHERE baseline_id = ?", (bl_id,)
        ).fetchone()[0]
        print("[+] Baseline #" + str(bl_id) + " saved — " + str(count) + " entries snapshotted.")

    if args.sysmon:
        print("[*] Collecting Sysmon events (last " + str(args.hours) + "h)...")
        count = col.collect_sysmon_events()
        print("[+] Stored " + str(count) + " Sysmon events")

    if args.events:
        print("[*] Collecting Security 4688 + 4698 events (last " + str(args.hours) + "h)...")
        count  = col.collect_process_events()
        count2 = col.collect_task_events()
        print("[+] Stored " + str(count) + " 4688 events, " + str(count2) + " 4698 events")

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
            "SELECT id, task_name, severity FROM task_entries "
            "WHERE severity IN ('high','critical') ORDER BY severity DESC, id"
        ).fetchall()
        print("[*] Building chains for " + str(len(rows)) + " High/Critical tasks...")
        from registry_collector import format_chain_node
        try:
            from ps_decode import decode_ps_command, format_decoded
        except ImportError:
            decode_ps_command = lambda x: None
            format_decoded = lambda x: x or ""
        for row in rows:
            sev_color = Colors.RED if row["severity"] == "critical" else Colors.YELLOW
            print("\n" + Colors.BOLD + "--- Task " + str(row["id"]) + ": " +
                  row["task_name"] + " [" + sev_color + row["severity"].upper() +
                  Colors.RESET + Colors.BOLD + "] ---" + Colors.RESET)
            chain = col.build_attack_chain(row["id"])
            if chain and chain[0].get("source") == "skipped":
                continue  # silently skip built-in tasks
            if chain:
                print()
                for i, node in enumerate(chain):
                    print(format_chain_node(node, "  " * i))
                    # Inline PS decode for any node with encoded command
                    cmdline = node.get("cmdline", "") or ""
                    decoded = decode_ps_command(cmdline)
                    if decoded:
                        print("  " * i + "  " + Colors.CYAN +
                              "🔓 Decoded: " + format_decoded(decoded) + Colors.RESET)
                    print()
            else:
                print("    [!] No chain")

    stats = col.get_stats()
    tsk   = stats["tasks"]
    print()
    print(Colors.BOLD + "[*] Task Stats: " + str(sum(tsk.values())) + " entries" + Colors.RESET)
    print("    Critical: " + Colors.RED    + str(tsk["critical"]) + Colors.RESET +
          " | High: "      + Colors.YELLOW + str(tsk["high"])     + Colors.RESET +
          " | Medium: "    + str(tsk["medium"]) +
          " | Low: "       + Colors.GREEN  + str(tsk["low"])      + Colors.RESET)

    if getattr(args, 'json', False):
        import json as _json
        try:
            from ps_decode import decode_ps_command, format_decoded
        except ImportError:
            decode_ps_command = lambda x: None
            format_decoded = lambda x: x or ""
        all_entries = col.get_all_entries()
        export = []
        for e in all_entries:
            chain = col.get_chain(e["id"]) if e["severity"] in ("high", "critical") else []
            decoded = decode_ps_command(e.get("command", ""))
            record = dict(e)
            record["chain"] = chain
            if decoded:
                record["decoded_command"] = format_decoded(decoded, max_len=500)
            export.append(record)
        out = "task_export.json"
        with open(out, "w") as f:
            _json.dump(export, f, indent=2, default=str)
        print("[+] JSON exported to " + out + " (" + str(len(export)) + " entries)")

    col.close()