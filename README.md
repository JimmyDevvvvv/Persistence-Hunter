# Persistence Hunter

Open-source Windows security tool protecting regular users from info stealers (Lumma, Redline, Stealc), malware persistence, and credential theft. Free forever, community-driven detection rules.

Most tools give you a list. This gives you a chain — and tells you whether a persistence entry was dropped by a legitimate installer, a user action, or something that shouldn't be there at all.

---

## What it detects

**Persistence mechanisms**
- Registry run keys across HKCU and HKLM, including RunOnce and common persistence subkeys
- Scheduled tasks — full enumeration with command parsing and PowerShell decode
- Windows services — all entries with binary path extraction and signature verification

**Real-time signals (Phase 3 — ETW)**
- Registry writes to Run keys as they happen
- Process creation events
- Dropper file creation in suspicious paths

**Threat analysis**
- 0–100 threat score per entry with per-factor breakdown
- APT/stealer signature matching — 27 signatures covering APT29, Cobalt Strike, Lumma, Redline, Stealc, Vidar, Raccoon, and more
- MITRE ATT&CK technique tagging
- Info stealer fingerprinting — browser credential path access (T1555.003), DPAPI abuse, crypto wallet targeting
- LOLBin detection, process masquerading, encoded PowerShell decode
- Attack chain reconstruction — who wrote the persistence entry, and what wrote that

**Binary verification**
- Authenticode status via PowerShell
- SHA256 per service binary
- Ghost service detection when binary is missing from disk

---

## Architecture

```
core/
    threat_scorer.py      scoring engine (0-100 composite score)
    alert_translator.py   plain English translation for consumer UI

collector/
    base_collector.py         shared DB, event ingestion, chain building
    registry_collector.py     registry run key scanner
    task_collector.py         scheduled task scanner
    service_collector.py      service scanner

enrichment/
    local.py              Authenticode PE signature check (no API key)
    vt.py                 VirusTotal lookup (optional, needs API key)
    mb.py                 MalwareBazaar lookup (optional, no key needed)

api/
    main.py               FastAPI app (localhost:8000)
    scan_worker.py        background scan pipeline
    routes/               REST endpoints

service/
    service_wrapper.py    Windows service wrapper (pywin32)
    tray.py               system tray icon (green/amber/red/grey)
    toast.py              native Windows toast notifications

rules/
    apt_signatures.json   27 APT/stealer detection signatures

tools/
    check_signatures.py   CLI binary signature checker
    scan_summary.py       CLI cross-collector summary
    ps_decode.py          PowerShell -enc decoder utility
    fix_base.py           one-shot baseline patch utility
    inject_baseline.py    one-shot baseline injection utility

frontend/
    src/
        pages/
            Dashboard.jsx         telemetry overview, charts, recent alerts
            ConsumerDashboard.jsx  plain-English consumer UI
            Alerts.jsx             alert feed with attack chain visualizer
            EntryDetail.jsx        per-entry tabs: Summary, Attack Chain, Intel, Details
            Entries.jsx            full entry table with filters
            Baseline.jsx           snapshot management and diff view
            Search.jsx             free-text search

src-tauri/               Tauri shell (window hides to tray, IPC for tray updates)
```

---

## Threat scoring

Entries are scored 0–100. The score is a weighted composite of risk signals, not a single flag.

| Score | Label | Meaning |
|---|---|---|
| 80–100 | Critical | High confidence. Investigate immediately. |
| 60–79 | High | Suspicious. Likely malicious or high-risk. |
| 35–59 | Medium | Indicators present. Review recommended. |
| 0–34 | Low | Informational. Probably not worth your time. |

Key signals: encoded PowerShell payload, temp/user-writable paths, LOLBin abuse, process masquerading, malicious chain node, APT signature match, unsigned binary, browser credential path references, DPAPI abuse.

---

## UI modes

**Consumer mode** — clean hero zone, plain English alert cards, one-click block/trust.
- Hero zone colour changes with threat status (green → amber → red)
- Critical alerts show as persistent toasts until dismissed
- Switch to analyst mode with the `</>` button (bottom right)

**Analyst mode** — full dashboard, MITRE tags, attack chain visualizer, rule manager, score breakdowns.

**Tray icon** — green = clean, amber = warning/high, red = critical, grey = error.

---

## Requirements

- Windows 10/11 or Server 2016+
- Python 3.11+
- Node.js 18+ for the frontend
- Admin rights for service enumeration and event log access

Python packages: `fastapi uvicorn pywin32 pystray Pillow winotify requests`

Frontend packages: `react vite @tanstack/react-query axios react-router-dom framer-motion`

---

## Setup

Start all subsystems:
```
python service/service_wrapper.py debug
```

This starts the FastAPI backend (localhost:8000) and the system tray icon.

Take a baseline on a known-clean system:
```
python collector/registry_collector.py --scan --events --hours 72 --baseline
python collector/task_collector.py --scan --events --hours 72 --baseline
python collector/service_collector.py --scan --events --hours 72 --baseline
```

Start the frontend:
```
cd frontend
npm install
npm run dev
```

---

## Daily scan workflow

```
python collector/registry_collector.py --scan --events --hours 1 --diff --chain-all
python collector/task_collector.py --scan --events --hours 1 --diff --chain-all
python collector/service_collector.py --scan --events --hours 1 --diff --chain-all
python tools/scan_summary.py --chains
```

Score all entries:
```
python -m core.threat_scorer --summary
```

Check binary signatures:
```
python tools/check_signatures.py --unsigned-only
```

---

## CLI flags

| Flag | Description |
|---|---|
| `--scan` | Enumerate current persistence entries |
| `--events` | Collect Security and System event logs |
| `--hours N` | Event lookback window in hours (default 24) |
| `--baseline` | Snapshot current entries as the active baseline |
| `--diff` | Output only entries not present in the last baseline |
| `--chain-all` | Build attack chains for all High and Critical entries |
| `--json` | Export results to JSON |

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | DB connectivity check |
| `/api/status` | GET | Current threat status (drives tray icon) |
| `/api/stats` | GET | Aggregated counts across all types |
| `/api/summary` | GET | New High/Critical entries since baseline |
| `/api/alerts` | GET | Full alert feed |
| `/api/entries` | GET | All entries with type and severity filters |
| `/api/chains/{type}/{id}` | GET | Attack chain for one entry |
| `/api/scores` | GET | All threat scores |
| `/api/scores/run` | POST | Run scorer across all entries |
| `/api/scan` | POST | Trigger full background scan |
| `/api/baseline` | GET/POST | List or create baselines |
| `/api/search` | GET | Search entries and process events |

---

## Detection rules

Rules live in `rules/apt_signatures.json` — 27 signatures covering:
- APT groups: APT29 (Cozy Bear), APT41, Lazarus, Kimsuky, FIN7
- Commodity stealers: Lumma, Redline, Stealc, Vidar, Raccoon, Laplas Clipper
- Red team tools: Cobalt Strike beacons, Meterpreter, WMI persistence, COM hijacking, certutil abuse, MSHTA/HTA

Behavioral correlation rules (Phase 3): event A + event B within 30 seconds = alert.

Community rule submission via GitHub PR is planned for Phase 4.

---

## Limitations

- Windows only — tightly coupled to Windows event log structure
- Service enumeration and some event log queries require admin rights (running without elevation produces incomplete results silently)
- No Sysmon required — ETW-based monitoring (Phase 3) replaces Sysmon dependency
- Signature checking runs a PowerShell subprocess per binary — not designed for real-time use
- Do not expose port 8000 to a network without a reverse proxy
