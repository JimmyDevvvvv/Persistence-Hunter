"""
service_wrapper.py
==================
Registers Persistence Hunter as a native Windows service.
Starts on boot, runs the FastAPI backend and tray app together.

Requirements:
    pip install pywin32

Install service:
    python service_wrapper.py install
    python service_wrapper.py start

Remove service:
    python service_wrapper.py stop
    python service_wrapper.py remove

Runs automatically on next boot after install.
"""

from __future__ import annotations

import os
import sys
import time
import threading
import subprocess
import logging
import servicemanager
import win32event
import win32service
import win32serviceutil

# ---------------------------------------------------------------------------
# Paths — resolve relative to the installed app directory
# ---------------------------------------------------------------------------

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR    = os.path.dirname(BASE_DIR)
LOG_DIR     = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
                           "PersistenceHunter", "logs")
LOG_FILE    = os.path.join(LOG_DIR, "service.log")
API_SCRIPT  = os.path.join(ROOT_DIR, "api", "main.py")
PYTHON_EXE  = sys.executable

os.makedirs(LOG_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("PersistenceHunterService")

# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class PersistenceHunterService(win32serviceutil.ServiceFramework):
    _svc_name_         = "PersistenceHunter"
    _svc_display_name_ = "Persistence Hunter"
    _svc_description_  = (
        "Real-time protection against malware persistence and credential theft. "
        "Monitors startup entries, scheduled tasks, and browser session access."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._threads: list[threading.Thread] = []
        self._procs:   list[subprocess.Popen] = []

    # ------------------------------------------------------------------
    # Service lifecycle
    # ------------------------------------------------------------------

    def SvcStop(self):
        log.info("Stop signal received")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        self._shutdown()

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        log.info("Persistence Hunter service starting")
        self._startup()

        # Block until stop signal
        win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
        log.info("Persistence Hunter service stopped")

    # ------------------------------------------------------------------
    # Start subsystems
    # ------------------------------------------------------------------

    def _startup(self):
        """Start each subsystem in its own thread."""
        subsystems = [
            ("API",     self._run_api),
            ("Tray",    self._run_tray),
        ]
        for name, target in subsystems:
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)
            log.info(f"Started subsystem: {name}")

    def _shutdown(self):
        """Terminate all child processes cleanly."""
        for proc in self._procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception as e:
                log.warning(f"Error terminating process: {e}")
        log.info("All subsystems shut down")

    # ------------------------------------------------------------------
    # Subsystem runners
    # ------------------------------------------------------------------

    def _run_api(self):
        """Run the FastAPI backend on localhost:8000."""
        cmd = [
            PYTHON_EXE, "-m", "uvicorn",
            "api.main:app",
            "--host", "127.0.0.1",
            "--port", "8000",
            "--log-level", "warning",
        ]
        log.info(f"Starting API: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=ROOT_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self._procs.append(proc)
            _, stderr = proc.communicate()
            if stderr:
                log.error(f"API stderr: {stderr.decode(errors='replace')}")
        except Exception as e:
            log.error(f"API failed to start: {e}")

    def _run_tray(self):
        """Launch the tray app (separate process so it has its own event loop)."""
        tray_script = os.path.join(BASE_DIR, "tray.py")
        cmd = [PYTHON_EXE, tray_script]
        log.info(f"Starting tray: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=ROOT_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self._procs.append(proc)
            _, stderr = proc.communicate()
            if stderr:
                log.error(f"Tray stderr: {stderr.decode(errors='replace')}")
        except Exception as e:
            log.error(f"Tray failed to start: {e}")


# ---------------------------------------------------------------------------
# CLI helper — called by installer
# ---------------------------------------------------------------------------

def _print_usage():
    print("""
Persistence Hunter — Service Manager

  install   Register as Windows service (run as Administrator)
  start     Start the service
  stop      Stop the service
  restart   Restart the service
  remove    Unregister the service
  status    Show current service status
  debug     Run in foreground (for development)
""")

def _service_status() -> str:
    try:
        status = win32serviceutil.QueryServiceStatus("PersistenceHunter")
        states = {
            win32service.SERVICE_STOPPED:          "Stopped",
            win32service.SERVICE_START_PENDING:    "Starting",
            win32service.SERVICE_STOP_PENDING:     "Stopping",
            win32service.SERVICE_RUNNING:          "Running",
            win32service.SERVICE_CONTINUE_PENDING: "Resuming",
            win32service.SERVICE_PAUSE_PENDING:    "Pausing",
            win32service.SERVICE_PAUSED:           "Paused",
        }
        return states.get(status[1], "Unknown")
    except Exception:
        return "Not installed"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _print_usage()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "status":
        print(f"Persistence Hunter service: {_service_status()}")

    elif command == "debug":
        # Run subsystems directly — bypasses ServiceFramework which
        # requires a real Windows SCM context to initialise
        print("[DEBUG] Running Persistence Hunter in foreground mode")
        print(f"[DEBUG] API  → http://127.0.0.1:8000")
        print(f"[DEBUG] Tray → system tray (bottom right)")
        print(f"[DEBUG] Press Ctrl+C to stop\n")

        procs: list[subprocess.Popen] = []

        # Start FastAPI
        api_cmd = [
            PYTHON_EXE, "-m", "uvicorn",
            "api.main:app",
            "--host", "127.0.0.1",
            "--port", "8000",
            "--log-level", "info",
        ]
        print(f"[DEBUG] Starting API...")
        api_proc = subprocess.Popen(api_cmd, cwd=ROOT_DIR)
        procs.append(api_proc)

        # Give API a moment to bind
        time.sleep(2)

        # Start tray
        tray_script = os.path.join(BASE_DIR, "tray.py")
        print(f"[DEBUG] Starting tray...")
        tray_proc = subprocess.Popen(
            [PYTHON_EXE, tray_script], cwd=ROOT_DIR
        )
        procs.append(tray_proc)

        print(f"[DEBUG] All subsystems running. Open http://127.0.0.1:8000 in your browser.")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[DEBUG] Stopping...")
            for p in procs:
                try:
                    p.terminate()
                    p.wait(timeout=3)
                except Exception:
                    pass
            print("[DEBUG] Stopped")

    else:
        # Delegate install/start/stop/remove/restart to pywin32
        win32serviceutil.HandleCommandLine(PersistenceHunterService)