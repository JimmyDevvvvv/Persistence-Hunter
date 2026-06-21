# Persistence Hunter — Claude Code Context

Read this file first before touching anything. It captures the full
project vision, current state, and decisions made in the planning session.

---

## What This Project Is

Open source Windows security software to protect regular people from
info stealers (Lumma, Redline, Stealc), malware persistence, and
credential theft. Goal: production-quality tool on par with Malwarebytes.
Free forever, community-driven detection rules.

Full plan is in PLAN.md at the repo root. Read that too.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Real-time monitor | Python + ETW (Phase 3) |
| Detection engine | Python (existing collectors + new scorer) |
| Database | SQLite (reghunt.db) |
| API | FastAPI (localhost:8000) |
| UI shell | Tauri (Rust) — Phase 2, scaffold exists in src-tauri/ |
| Frontend | React (existing in frontend/) |
| Installer | Tauri built-in NSIS |

---

## Current State — What's Done

### Phase 1 ✅
- `threat_scorer.py` — reworked with bug fixes:
  - Fixed val_pat fall-through bug in match_apt_signatures()
  - Added negative weights for trusted software
  - Added T1555.003 credential theft signals (browser_db_access, dpapi_abuse, wallet_access)
  - Expanded LEGIT_APPDATA_APPS to 50+ entries
  - Expanded SYSTEM_TASK_PREFIXES
  - Fixed Python 3.9+ type hint issue
  - Added score floor at 0
- `apt_signatures.json` — expanded from 12 to 27 signatures:
  - APT-SIG-013 to 020: Cobalt Strike, WMI, COM hijacking, certutil, mshta, etc.
  - STL-SIG-001 to 007: Lumma, Redline, Stealc, Vidar, Raccoon — commodity stealers
- `alert_translator.py` — converts technical findings to plain English for consumer UI

### Phase 2 ✅ (mostly)
- `service/service_wrapper.py` — Windows service wrapper using pywin32
  - debug mode runs subsystems directly (bypasses SCM)
  - `python service/service_wrapper.py debug` works
- `service/tray.py` — system tray icon (green/amber/red/grey) using pystray + PIL
  - polls /api/status every 10 seconds
  - dynamic icon color based on threat status
- `service/toast.py` — native Windows toast notifications via winotify
- `frontend/src/pages/ConsumerDashboard.jsx` — consumer-facing UI
  - dark navy + cyan theme
  - hero zone changes color with threat status
  - plain English alert cards
  - `</>` button (bottom right) switches to analyst mode
- `src-tauri/` — Tauri scaffold (tauri.conf.json, Cargo.toml, src/main.rs)
  - window close hides to tray
  - IPC for tray icon updates from React
- `/api/status` endpoint added to `api/routes/stats.py`
  - drives tray icon color and consumer dashboard hero zone
  - gracefully handles missing threat_scores table

### What's Working Right Now
- `python service/service_wrapper.py debug` starts everything
- API running on localhost:8000
- Tray icon running, polling /api/status, getting 200 OK
- Registry scan works: `python collector/registry_collector.py --scan --events --hours 24`
- Found 13 entries on clean machine, all legit software

---

## Current Issues to Fix

### 1. Enrichment System — NEEDS REWORK (top priority)
The enrichment module fails to import at startup:
```
[!] Startup init warning: No module named 'enrichment'
```

Running `python threat_scorer.py` crashes because `enrichment_results`
table doesn't exist.

**Agreed approach — rework enrichment to be optional and async:**

```
New architecture:
  enrichment/
    local.py   — PE signature check via PowerShell (sync, always runs, no API)
    vt.py      — VirusTotal (async, optional, needs API key)
    mb.py      — MalwareBazaar (async, optional, no key needed)
    engine.py  — orchestrates all three, graceful fallback

Scorer change:
  _load_enrichment() never crashes
  Returns local PE data always
  Returns cached VT/MB data if available in DB
  Returns empty dict if nothing available
```

Local PE signature check via PowerShell (highest priority, zero deps):
```python
import subprocess, json
def check_signature(path):
    ps = f'Get-AuthenticodeSignature "{path}" | ConvertTo-Json'
    out = subprocess.check_output(["powershell", "-Command", ps])
    data = json.loads(out)
    return {
        "signed":    data["Status"] == 0,
        "publisher": data.get("SignerCertificate", {}).get("Subject", ""),
    }
```

### 2. ETW Migration — Phase 3 (next after enrichment)
No Sysmon on current machine. Need to replace Sysmon event log polling
with ETW real-time monitoring.

**Agreed approach:**
- `monitors/etw_monitor.py` — subscribes to ETW providers
- `monitors/correlator.py` — time window event correlation
- Use WMI for process creation (reliable, Python 3.14 compatible)
- Use `win32api.RegNotifyChangeKeyValue` for registry watching
- Correlated detection: event A + event B within 30s = alert (not single events)

Three ETW providers needed:
- `Microsoft-Windows-Kernel-Registry` — Run key writes in real-time
- `Microsoft-Windows-Kernel-Process` — process creation, replaces Sysmon Event 1
- `Microsoft-Windows-Kernel-File` — dropper file creation in suspicious paths

**pip install wmi** (needed for WMI process monitoring)

### 3. Security Log Access Denied
Event ID 4688 requires admin. Running as Administrator fixes it.
ETW migration (above) resolves this properly for the service.

### 4. task_entries / service_entries may not exist
Only registry collector has been run. score_all() tries to query all
three tables. Wrap in try/except or check table existence first.

---

## UI / UX Decisions (locked in)

- **Theme**: dark navy + cyan
  - bg: #0f1117, surface: #1a1f2e, accent: #06b6d4
  - success: #22c55e, warning: #f59e0b, danger: #ef4444
- **Two modes**:
  - Consumer: clean hero zone, plain English alerts, stat cards
  - Analyst: existing dashboard + chain visualizer, MITRE tags, rule manager
  - Switch: `</>` button bottom-left sidebar (hidden from regular users)
- **Notification levels**:
  - Critical: persistent toast until dismissed
  - High: 8 second toast
  - Medium: 4 second toast
  - Low: history only, never shown
- **Tray icon**: green=clean, amber=warning/high, red=critical, grey=error

---

## Detection Rule System (designed, not yet built)

Three rule types:
1. Signature rules — apt_signatures.json (existing, extended)
2. Behavioral correlation rules — behavior_rules.json (Phase 3)
3. Custom rules — user-written, local only

Behavioral rule format (for Phase 3):
```json
{
  "id": "BEH-001",
  "type": "correlation",
  "window_seconds": 30,
  "events": [
    {"event": "process_create", "filters": {"path_contains": ["\\appdata\\"], "not_signed": true}},
    {"event": "registry_write", "filters": {"key_contains": ["\\Run\\"], "same_process_tree": true}},
    {"event": "file_read",      "filters": {"path_contains": ["cookies", "login data"], "same_process_tree": true}}
  ],
  "condition": "ALL",
  "mitre": ["T1547.001", "T1555.003"],
  "severity": "critical"
}
```

---

## Exclusion System (designed, not yet built — Phase 4)

Three levels:
1. Global: path, process, hash, signer exclusions
2. Rule-level: suppress one rule for one program
3. Temporary: pause protection for N minutes

---

## Community Model (Phase 4)

- Rules versioned separately from app
- GitHub as rule store, community PRs
- Auto-update rules on startup
- "Submit Detection" button in analyst mode → pre-filled GitHub PR
- Discord for analyst community

---

## Environment

- Python 3.14 (pythoncore-3.14-64)
- Windows 11, no Sysmon installed
- Installed packages: fastapi, uvicorn, pywin32, pystray, Pillow, winotify, requests
- Missing: wmi (needed for ETW Phase 3)
- DB: reghunt.db (SQLite, in repo root)
- Running location: C:\Users\Moham\OneDrive\Documents\GitHub\Persistence-Hunter

---

## Suggested First Task for Claude Code

Fix the enrichment system first:

1. Read the current enrichment/ directory to understand what's there
2. Read threat_scorer.py _load_enrichment() and score_all()
3. Build enrichment/local.py with PE signature checking
4. Make _load_enrichment() never crash (graceful fallback)
5. Make sure score_all() handles missing task_entries and service_entries tables
6. Run python threat_scorer.py and verify it completes without errors
7. Run python threat_scorer.py --summary and show the results
