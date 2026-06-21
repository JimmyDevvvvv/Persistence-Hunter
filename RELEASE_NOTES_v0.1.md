# Persistence Hunter v0.1 — Release Notes

First public release. Core detection pipeline is functional end-to-end on Windows 10/11.
This is a developer preview — the installer and auto-update system are planned for v0.2.

---

## What's in this release

**Detection engine**
- Threat scorer (0–100 composite score) with per-factor breakdown and APT attribution
- 27 signature rules covering commodity stealers (Lumma, Redline, Stealc, Vidar, Raccoon)
  and APT groups (APT29, APT41, Lazarus, Kimsuky, FIN7)
- Behavioral correlation engine: event-chain rules evaluated over a 30-second rolling window
- BEH-001: Info Stealer Full Chain (process drop → Run key → file/credential access)
- BEH-002: Suspicious Process Writes Run Key (lighter, 60-second window)
- LEGIT_APPDATA_DIRS trust list with parent-directory check: Squirrel updaters
  (Discord, Slack, Notion, Spotify, etc.) do not trigger stealer signatures

**Collectors**
- Registry Run / RunOnce scanner (HKCU + HKLM)
- Scheduled task scanner with PowerShell -enc decode
- Windows service scanner with binary path extraction and ghost service detection

**Real-time monitor (ETW)**
- `RegistryWatcher`: RegNotifyChangeKeyValue on all 4 Run/RunOnce keys — sub-second notification
- `ProcessWatcher`: WMI Win32_Process creation events with PID and parent PID
- `FileWatcher`: 2-second poll of AppData, Temp, C:\Users\Public for new executables

**API and service**
- FastAPI backend on localhost:8000 with Swagger docs at /docs
- Windows service wrapper — installs as a native service, starts on boot
- System tray icon: green (clean) / amber (high) / red (critical) / grey (error)
- Native toast notifications via winotify
- POST /api/alerts/realtime — stores correlated ETW alerts from the monitor
- GET /api/alerts/realtime — serves stored real-time alerts to the dashboard

**UI**
- Consumer dashboard: plain-English alert cards, threat status hero zone
- Analyst mode: attack chain visualizer, MITRE tags, score breakdowns
- Switch modes with the `</>` button

---

## Known limitations

**PID attribution is probabilistic**

`RegNotifyChangeKeyValue` notifies that a Run key changed but cannot report which
process wrote it. When a registry_write event arrives with pid=0, the correlator
does temporal proximity attribution: it looks for a suspicious process in the
30-second buffer and, if found, attributes the write to it with confidence="probable".

This means:
- True positive rate is high when malware runs and writes a Run key in quick succession.
- False negative possible if malware writes the Run key more than 30 seconds after
  launching. Increase `window_seconds` in `rules/behavior_rules.json` if needed.
- Known-legitimate apps (Discord, Slack, Notion, etc.) that manage their own Run keys
  are excluded from attribution via `_LEGIT_DIRS` in `monitors/correlator.py`.

**WMI process watcher requires COM**

`ProcessWatcher` uses `pythoncom.CoInitialize()` per thread. On some Windows
configurations, WMI subscriptions need the Windows Management Instrumentation
service to be running. If `[ProcessWatcher] wmi/pythoncom not available` appears
in the log, install: `pip install wmi`.

**No packaged installer yet**

v0.1 requires manual Python environment setup. NSIS installer via Tauri is planned
for v0.2. Until then, run from source with `python service/service_wrapper.py debug`.

**HKLM Run keys need admin**

Monitoring `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` for
changes requires the process to run as Administrator. Without elevation, only the
HKCU Run keys are watched. The service installer (`python service_wrapper.py install`)
registers as a local system service which has the required rights.

**Frontend requires separate npm run dev**

The Tauri shell is scaffolded but not yet built into a standalone app. Run
`cd frontend && npm install && npm run dev` separately for the UI, or use the
API directly at http://127.0.0.1:8000.

---

## How to test it

**Verify the scorer on a clean machine:**
```
python collector/registry_collector.py --scan
python -m core.threat_scorer --summary
```
Expected: all entries score 0–10. If anything scores 50+, investigate and report it.

**Verify the real-time monitor starts:**
```
python service/service_wrapper.py debug
```
Expected output within 5 seconds:
```
[RegistryWatcher] Watching HKCU\...\Run
[RegistryWatcher] Watching HKCU\...\RunOnce
[RegistryWatcher] Watching HKLM\...\Run
[RegistryWatcher] Watching HKLM\...\RunOnce
[ProcessWatcher] Watching process creations via WMI
[FileWatcher] Watching 4 dirs (N existing executables)
```

**Verify behavioral detection (no live malware needed):**
```python
# paste into a Python REPL with the repo root on sys.path
import time
from monitors.correlator import EventCorrelator
c = EventCorrelator()
base = time.time()
c.ingest({'type':'process_create','timestamp':base,'process':'test.exe',
          'pid':9999,'parent_pid':0,
          'path':r'C:\Users\Test\AppData\Local\Temp\test.exe','detail':''})
fired = c.ingest({'type':'registry_write','timestamp':base+5,'process':'unknown',
                  'pid':0,'parent_pid':0,
                  'path':r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                  'detail':'TestPersist = C:\\Users\\Test\\AppData\\Local\\Temp\\test.exe'})
print([r['id'] for r in fired])  # expected: ['BEH-002']
```

---

## How to report false positives

Open a GitHub issue with the label `false-positive` and include:

1. The entry that triggered: name, value_data, and score from `--summary`
2. The software that owns it (vendor, version, install path)
3. Output of `python -m core.threat_scorer --entry registry/<id>` for the full breakdown
4. Your Windows version (`winver`)

**Before reporting:** check that the binary path is in a standard install location
(`Program Files`, `Program Files (x86)`, a drive root like `D:\Steam`). If it is,
the fix is usually adding the parent directory to `LEGIT_APPDATA_DIRS` or
`LEGIT_APPDATA_APPS` in `core/threat_scorer.py`.

---

## What's coming in v0.2

- NSIS installer via Tauri — one-click install, no Python required
- Auto-update for detection rules from GitHub on startup
- Network monitor (Phase 4): detect beacon callbacks from persistence processes
- "Submit Detection" button in analyst mode → pre-filled GitHub PR for community rules
- Exclusion system: global path/hash/signer exclusions, rule-level suppression,
  temporary protection pause
- Rule versioning: rules shipped separately from the app binary
