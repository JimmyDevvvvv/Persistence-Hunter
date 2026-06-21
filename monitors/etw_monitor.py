"""
monitors/etw_monitor.py
=======================
Real-time persistence and process monitoring.

Three watcher classes, each in its own daemon thread:
  RegistryWatcher  — RegNotifyChangeKeyValue on Run / RunOnce keys
  ProcessWatcher   — WMI Win32_Process creation events
  FileWatcher      — Polls suspicious dirs for new .exe / .dll drops

All events share the same schema:
  {
    "type"      : "registry_write" | "process_create" | "file_create"
    "timestamp" : float        (time.time())
    "process"   : str          (process name; "unknown" if unavailable)
    "pid"       : int
    "parent_pid": int          (process_create only; 0 otherwise)
    "path"      : str          (key path / exe path / directory)
    "detail"    : str          (value data / cmdline / full file path)
  }

Standalone entry point (started as subprocess by service_wrapper):
    python monitors/etw_monitor.py
"""
from __future__ import annotations

import os
import sys
import time
import queue
import threading

# ── Optional win32 imports ──────────────────────────────────────────────────
try:
    import win32api
    import win32con
    import win32event
    import pywintypes
    _WIN32      = True
    _KEY_ACCESS = win32con.KEY_READ | 0x0100   # KEY_READ | KEY_WOW64_64KEY
except ImportError:
    _WIN32 = False

try:
    import pythoncom
    import wmi as _wmi_lib
    _WMI = True
except ImportError:
    _WMI = False

_NOTIFY_LAST_SET = 4   # REG_NOTIFY_CHANGE_LAST_SET — watch value writes


# ===========================================================================
# Registry Watcher
# ===========================================================================

class RegistryWatcher:
    """
    Watches HKCU/HKLM Run and RunOnce keys via RegNotifyChangeKeyValue.
    Emits one registry_write event per added or changed value.
    """

    _WATCH = [
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    def __init__(self, on_event, stop_event: threading.Event):
        self._emit = on_event
        self._stop = stop_event

    # -- helpers ------------------------------------------------------------

    def _read_values(self, hkey) -> dict:
        """Return {lower_name: (original_name, data_str)} for every value."""
        result: dict = {}
        i = 0
        while True:
            try:
                name, data, _ = win32api.RegEnumValue(hkey, i)
                result[name.lower()] = (name, str(data))
                i += 1
            except pywintypes.error:
                break
        return result

    # -- main loop ----------------------------------------------------------

    def run(self):
        if not _WIN32:
            print("[RegistryWatcher] win32api not available — skipping")
            return

        hive_map = {
            "HKCU": win32con.HKEY_CURRENT_USER,
            "HKLM": win32con.HKEY_LOCAL_MACHINE,
        }

        key_handles: list = []
        evt_handles: list = []
        meta:        list = []      # [(hive_label, subkey)]
        snaps:       dict = {}

        for hive_label, subkey in self._WATCH:
            try:
                hk = win32api.RegOpenKey(
                    hive_map[hive_label], subkey, 0, _KEY_ACCESS
                )
                he = win32event.CreateEvent(None, True, False, None)  # manual-reset
                win32api.RegNotifyChangeKeyValue(
                    hk, False, _NOTIFY_LAST_SET, he, True
                )
                snaps[subkey]  = self._read_values(hk)
                key_handles.append(hk)
                evt_handles.append(he)
                meta.append((hive_label, subkey))
                short = subkey.rsplit("\\", 1)[-1]
                print(f"[RegistryWatcher] Watching {hive_label}\\...\\{short}")
            except Exception as exc:
                print(f"[RegistryWatcher] Cannot open {hive_label}\\{subkey}: {exc}")

        if not evt_handles:
            print("[RegistryWatcher] No keys available — registry watching disabled")
            return

        try:
            while not self._stop.is_set():
                try:
                    result = win32event.WaitForMultipleObjects(
                        evt_handles, False, 1000
                    )
                except Exception:
                    time.sleep(0.5)
                    continue

                if result == win32event.WAIT_TIMEOUT:
                    continue

                idx = result - win32event.WAIT_OBJECT_0
                if not (0 <= idx < len(evt_handles)):
                    continue

                hive_label, subkey = meta[idx]
                hk = key_handles[idx]
                he = evt_handles[idx]

                # Re-arm BEFORE reading to avoid missing rapid consecutive changes
                win32event.ResetEvent(he)
                try:
                    win32api.RegNotifyChangeKeyValue(
                        hk, False, _NOTIFY_LAST_SET, he, True
                    )
                except Exception:
                    pass

                new_snap = self._read_values(hk)
                old_snap = snaps.get(subkey, {})

                for name_l, (name, data) in new_snap.items():
                    if name_l not in old_snap:
                        verb = "added"
                    elif old_snap[name_l][1] != data:
                        verb = "changed"
                    else:
                        continue

                    print(f"[RegistryWatcher] {verb}: {hive_label}\\...\\Run\\{name}")
                    self._emit({
                        "type":       "registry_write",
                        "timestamp":  time.time(),
                        "process":    "unknown",
                        "pid":        0,
                        "parent_pid": 0,
                        "path":       f"{hive_label}\\{subkey}",
                        "detail":     f"{name} = {data[:200]}",
                    })

                snaps[subkey] = new_snap

        finally:
            for h in evt_handles:
                try: win32event.CloseHandle(h)
                except Exception: pass
            for h in key_handles:
                try: win32api.RegCloseKey(h)
                except Exception: pass


# ===========================================================================
# Process Watcher
# ===========================================================================

class ProcessWatcher:
    """
    Watches for process creations via WMI Win32_Process.
    Emits process_create events including pid, parent_pid, exe path, cmdline.
    """

    def __init__(self, on_event, stop_event: threading.Event):
        self._emit = on_event
        self._stop = stop_event

    def run(self):
        if not _WMI:
            print("[ProcessWatcher] wmi / pythoncom not available — skipping")
            return

        try:
            pythoncom.CoInitialize()
        except Exception:
            pass

        try:
            c       = _wmi_lib.WMI()
            watcher = c.Win32_Process.watch_for("creation")
            print("[ProcessWatcher] Watching process creations via WMI")

            while not self._stop.is_set():
                try:
                    proc = watcher(timeout_ms=1000)
                    if proc:
                        print(f"[ProcessWatcher] {proc.Name} PID={proc.ProcessId}")
                        self._emit({
                            "type":       "process_create",
                            "timestamp":  time.time(),
                            "process":    proc.Name or "",
                            "pid":        proc.ProcessId or 0,
                            "parent_pid": proc.ParentProcessId or 0,
                            "path":       proc.ExecutablePath or "",
                            "detail":     (proc.CommandLine or "")[:500],
                        })
                except Exception as exc:
                    if self._stop.is_set():
                        break
                    msg = str(exc).lower()
                    if "timed out" in msg or "0x80043001" in msg:
                        continue   # normal WMI poll timeout
                    print(f"[ProcessWatcher] Error: {exc}")
                    time.sleep(1)
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass


# ===========================================================================
# File Watcher
# ===========================================================================

class FileWatcher:
    """
    Polls suspicious directories every 2 seconds for new executable drops.
    Emits file_create events for new .exe, .dll, .bat, .ps1, .vbs, .js files.
    """

    _POLL = 2          # seconds between polls
    _EXTS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"}

    def __init__(self, on_event, stop_event: threading.Event):
        self._emit  = on_event
        self._stop  = stop_event
        self._dirs  = self._build_dirs()
        self._known: set = set()

    @staticmethod
    def _build_dirs() -> list:
        appdata   = os.environ.get("APPDATA", "")
        localtemp = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp")
        candidates = [appdata, localtemp, r"C:\Users\Public", r"C:\Windows\Temp"]
        return [d for d in candidates if d and os.path.isdir(d)]

    def _scan(self) -> set:
        found: set = set()
        for d in self._dirs:
            try:
                for fn in os.listdir(d):
                    if os.path.splitext(fn)[1].lower() in self._EXTS:
                        found.add(os.path.join(d, fn))
            except OSError:
                pass
        return found

    def run(self):
        self._known = self._scan()
        print(
            f"[FileWatcher] Watching {len(self._dirs)} dirs "
            f"({len(self._known)} existing executables)"
        )

        while not self._stop.is_set():
            self._stop.wait(self._POLL)
            if self._stop.is_set():
                break

            current   = self._scan()
            new_files = current - self._known

            for fp in new_files:
                print(f"[FileWatcher] New file: {fp}")
                self._emit({
                    "type":       "file_create",
                    "timestamp":  time.time(),
                    "process":    "unknown",
                    "pid":        0,
                    "parent_pid": 0,
                    "path":       os.path.dirname(fp),
                    "detail":     fp,
                })

            self._known = current


# ===========================================================================
# ETW Monitor — orchestrates the three watchers
# ===========================================================================

class ETWMonitor:
    """
    Starts RegistryWatcher, ProcessWatcher, and FileWatcher in daemon threads.
    All events flow through a thread-safe queue to the caller's on_event()
    callback, which is always called from a single dispatcher thread.

    Usage:
        monitor = ETWMonitor(on_event=my_callback)
        monitor.start()
        ...
        monitor.stop()
    """

    def __init__(self, on_event):
        self._callback = on_event
        self._stop     = threading.Event()
        self._q: queue.Queue = queue.Queue()
        self._threads: list[threading.Thread] = []

    def _dispatcher(self):
        while True:
            try:
                event = self._q.get(timeout=1)
            except queue.Empty:
                if self._stop.is_set():
                    break
                continue
            if event is None:
                break
            try:
                self._callback(event)
            except Exception as exc:
                print(f"[ETWMonitor] on_event error: {exc}")

    def start(self):
        dt = threading.Thread(
            target=self._dispatcher, name="ETW-Dispatcher", daemon=True
        )
        dt.start()
        self._threads.append(dt)

        for name, cls in [
            ("ETW-Registry", RegistryWatcher),
            ("ETW-Process",  ProcessWatcher),
            ("ETW-File",     FileWatcher),
        ]:
            watcher = cls(self._q.put, self._stop)
            t = threading.Thread(target=watcher.run, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        self._q.put(None)   # unblock dispatcher
        for t in self._threads:
            t.join(timeout=5)


# ===========================================================================
# Standalone entry point — subprocess of service_wrapper
# ===========================================================================

if __name__ == "__main__":
    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)

    from monitors.correlator import EventCorrelator

    correlator = EventCorrelator()

    _SKIP_PROCS = {
        "antimalware service executable",
        "windows security health service",
        "searchindexer.exe",
        "searchprotocolhost.exe",
        "svchost.exe",
        "wuauclt.exe",
        "trustedinstaller.exe",
        "msiexec.exe",
    }

    _TYPE_LABEL = {
        "process_create": "PROC",
        "registry_write": "REG ",
        "file_create":    "FILE",
    }

    def _on_event(event: dict):
        if (event.get("process") or "").lower() in _SKIP_PROCS:
            return

        label  = _TYPE_LABEL.get(event["type"], event["type"][:4].upper())
        proc   = (event.get("process") or "?")[:28]
        detail = event.get("detail", "")[:80]
        print(f"[{label}] {proc:<28} {detail}")

        for rule in correlator.ingest(event):
            _handle_fired(rule)

    def _handle_fired(rule: dict):
        sep = "=" * 64
        print(f"\n{sep}")
        print(f"[ALERT] {rule['id']} — {rule['name']}")
        print(f"[ALERT] Severity : {rule.get('severity', 'critical').upper()}")
        print(f"[ALERT] MITRE    : {', '.join(rule.get('mitre', []))}")
        for ev in rule.get("matched_events", []):
            print(f"[ALERT]   {ev['type']:16s} {ev.get('detail','')[:70]}")

        score  = 85
        reg_ev = next(
            (e for e in rule.get("matched_events", []) if e["type"] == "registry_write"),
            None,
        )
        if reg_ev:
            try:
                from core.threat_scorer import score_entry, load_signatures
                name_part, _, data_part = reg_ev["detail"].partition(" = ")
                synthetic = {
                    "name":       name_part.strip(),
                    "value_data": data_part.strip(),
                    "reg_path":   reg_ev["path"],
                    "entry_type": "registry",
                }
                score = score_entry(synthetic, [], None, load_signatures())["score"]
            except Exception:
                pass

        payload = {**rule, "threat_score": score}
        payload.pop("matched_events", None)
        payload["matched_events"] = rule.get("matched_events", [])

        try:
            import requests
            r = requests.post(
                "http://127.0.0.1:8000/api/alerts/realtime",
                json=payload,
                timeout=5,
            )
            print(f"[ALERT] Stored via API: HTTP {r.status_code}")
        except Exception as exc:
            print(f"[ALERT] API post failed ({exc}) — alert logged to console only")

        print(sep + "\n")

    monitor = ETWMonitor(on_event=_on_event)
    monitor.start()
    print("\n[ETWMonitor] All watchers running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[ETWMonitor] Stopping...")
        monitor.stop()
        print("[ETWMonitor] Stopped")
