# RegHunt — Registry Persistence Hunter

A blue-team tool that scans Windows registry persistence keys,
correlates entries with process creation events (Event ID 4688),
and visualizes the full parent→child attack chain in a browser UI.

---

## Architecture

```
reghunt/
├── collector/
│   └── registry_collector.py   # Reads registry + event logs → SQLite
├── api/
│   └── api_server.py           # FastAPI REST layer
├── frontend/
│   └── index.html              # Attack chain visualizer (drop the HTML from Claude here)
└── requirements.txt
```

**Data flow:**
```
Windows Registry Keys
        ↓
registry_collector.py  ←→  reghunt.db (SQLite)
        ↓
api_server.py (FastAPI :8000)
        ↓
frontend/index.html (Attack Chain UI)
```

---

## Setup

### 1. Requirements

```
Windows 10/11 or Windows Server 2016+
Python 3.11+
Administrator rights (for HKLM keys + Security event log)
```

### 2. Install dependencies

```cmd
pip install -r requirements.txt
```

### 3. Enable audit policy (one-time, run as Admin)

This makes Event ID 4688 appear with process creation details:

```cmd
:: Enable Process Creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable

:: Enable command-line logging in process events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Without this, 4688 events exist but have no command-line data.

---

## Usage

### CLI (direct scan)

```cmd
:: Scan the 4 main Run keys
python collector/registry_collector.py --scan

:: Scan Run keys + extended set (Winlogon, Services...)
python collector/registry_collector.py --scan --extended

:: Pull last 24h of process creation events
python collector/registry_collector.py --events --hours 24

:: Full workflow: scan + events + build chain for entry ID 1
python collector/registry_collector.py --scan --events --chain 1
```

### API Server

```cmd
:: Start the API (from the api/ directory)
cd api
uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload
```

Then open: http://localhost:8000/ui  (after placing index.html in frontend/)

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/stats | Dashboard summary counts |
| GET | /api/entries | All registry entries |
| GET | /api/entries/{id} | Single entry |
| GET | /api/entries/{id}/chain | Attack chain for entry |
| POST | /api/scan | Trigger registry scan |
| POST | /api/collect-events | Collect Event ID 4688 |
| POST | /api/rebuild-chain/{id} | Rebuild chain for entry |
| GET | /api/processes | List stored process events |

---

## Persistence Keys Monitored

### Primary (4 core keys)
| Key | Description |
|-----|-------------|
| HKLM\SOFTWARE\...\CurrentVersion\Run | Machine-wide autorun |
| HKCU\SOFTWARE\...\CurrentVersion\Run | User-specific autorun |
| HKLM\SOFTWARE\...\CurrentVersion\RunOnce | One-time machine autorun |
| HKCU\SOFTWARE\...\CurrentVersion\RunOnce | One-time user autorun |

### Extended (--extended flag)
- HKLM\...\RunServices
- HKLM\...\Winlogon (Userinit, Shell hijacking)
- HKLM\SYSTEM\CurrentControlSet\Services

---

## Severity Heuristics

| Severity | Triggers |
|----------|---------|
| **Critical** | LOLBin with suspicious flags, remote URL in value, encoded command (-enc / -encodedcommand) |
| **High** | Executable in suspicious path (Public, Temp, AppData\Local\Temp) |
| **Medium** | Not in a known-good path — manual review |
| **Low** | Path under C:\Windows\System32, C:\Program Files\Microsoft, etc. |

LOLBins checked: `mshta, wscript, cscript, regsvr32, rundll32, certutil, bitsadmin, msiexec, wmic, powershell, cmd, regsvcs, regasm, installutil`

---

## Attack Chain Logic

1. Registry entry found → extract executable name from value data
2. Query `process_events` table for most recent matching process
3. Walk `parent_pid` chain upward until reaching a system root process
4. Each node classified: `system` → `normal` → `suspicious` → `malicious`
5. Chain stored in `attack_chains` table, served via API

**Limitation:** The process that *wrote* the registry key and the process
*referenced in* the key value may be different. Event ID 4688 tells us
what ran — not what touched the registry. For full registry write attribution,
Sysmon Event ID 13 (RegistryEvent) gives you the writing process directly.

---

## Sysmon (Optional but Recommended)

If you have Sysmon installed, Event ID 13 gives you the exact process
that modified a registry key. You can extend `registry_collector.py`
to correlate Sysmon logs for much higher-confidence attack chains.

```
Sysmon Event ID 1  → Process creation (richer than 4688)
Sysmon Event ID 13 → Registry value set (GOLD — direct write attribution)
```

Install Sysmon: https://docs.microsoft.com/sysinternals/downloads/sysmon

---

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|-----------|----|-------------|
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Primary detection target |
| Hijack Execution Flow | T1574 | Partial (via path analysis) |
| Living off the Land Binaries | T1218 | LOLBin detection in values |

---

## Known Limitations

- Event ID 4688 must be explicitly enabled (disabled by default on many systems)
- Without Sysmon, command-line data may be missing for some events
- Attack chain walks process parent/child — does not directly track which
  process wrote the registry key (needs Sysmon Event ID 13 for that)
- HKLM keys require Administrator rights
- WOW64 (32-bit registry) is read with KEY_WOW64_64KEY by default
 
 