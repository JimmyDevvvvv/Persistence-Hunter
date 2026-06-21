# Persistence Hunter

**Info stealers steal your accounts in seconds. Persistence Hunter catches them in real time.**

Free, open-source, no telemetry. Runs locally on Windows 10/11.

---

## Why this exists

Info stealers (Lumma, Redline, Stealc, Vidar) are the #1 way accounts get compromised in 2024.
They run silently, steal every saved password, session cookie, and crypto wallet in under 10 seconds,
and then install themselves to survive reboots.

Chrome's DBSC protects cookies *after* infection. No free tool catches the infection itself —
the moment malware drops a file, writes a Run key, and phones home with your credentials.

**Persistence Hunter does.** It watches the exact kill chain that every commodity stealer follows
and alerts you before exfiltration completes.

---

## What it detects

**The info stealer kill chain**

| Stage | What happens | How we detect it |
|---|---|---|
| Drop | Unsigned .exe lands in %Temp% or %AppData% | Real-time file watcher |
| Persist | Run key written so malware survives reboot | RegNotifyChangeKeyValue (instant) |
| Steal | Process reads Chrome cookies, Login Data | Behavioral correlation (BEH-001) |
| Exfil | Beacon phones home | (Phase 4 — network monitor) |

**Persistence mechanisms scanned**
- Registry Run / RunOnce keys (HKCU + HKLM)
- Scheduled tasks — full command parsing, PowerShell -enc decode
- Windows services — binary path extraction, ghost service detection

**Threat signatures** — 27 rules covering:
- Commodity stealers: Lumma Stealer, Redline, Stealc, Vidar, Raccoon
- APT groups: APT29 (Cozy Bear), APT41, Lazarus, Kimsuky, FIN7
- Red team tools: Cobalt Strike, WMI persistence, COM hijacking, certutil, MSHTA

---

## How it works

A background service watches your registry Run keys and process list in real time using
native Windows APIs (no kernel driver, no Sysmon required). When it sees the sequence
`suspicious process → Run key write → credential file access` within 30 seconds, it fires
an alert — a native Windows toast notification in plain English, not a 400-line log file.

---

## Quick Start

**Requirements:** Windows 10/11, Python 3.11+, admin rights

```
pip install fastapi uvicorn pywin32 pystray Pillow winotify requests wmi
python service/service_wrapper.py debug
```

This starts three things: the API backend (http://127.0.0.1:8000), the system tray icon,
and the real-time ETW monitor.

**Take a baseline on your clean machine:**
```
python collector/registry_collector.py --scan --baseline
python collector/task_collector.py     --scan --baseline
python collector/service_collector.py  --scan --baseline
```

**Score and review what's on your system:**
```
python -m core.threat_scorer --summary
```

**Open the dashboard:**
http://127.0.0.1:8000

---

## Screenshots

*Screenshots coming — UI is functional but pre-release polish in progress.*

Consumer mode: clean hero zone, plain-English alert cards, threat status indicator.
Analyst mode: full dashboard, attack chain visualizer, MITRE tags, score breakdowns.
Switch between them with the `</>` button.

---

## Detection coverage

| MITRE Technique | Description | Source |
|---|---|---|
| T1547.001 | Registry Run Keys | Registry collector + real-time watcher |
| T1053.005 | Scheduled Task/Job | Task collector |
| T1543.003 | Windows Service | Service collector |
| T1555.003 | Credentials from Web Browsers | Scorer (credential path signals) |
| T1140 | Deobfuscate/Decode Files | PowerShell -enc decoder |
| T1059.001 | PowerShell | Chain analysis (LOLBin detection) |
| T1036 | Masquerading | Name masquerade detection |
| T1574.001 | DLL Search Order Hijacking | Signature rules APT-SIG-009 |
| T1546.001 | Change Default File Association | Signature rules APT-SIG-010 |
| T1218 | System Binary Proxy Execution | LOLBin signatures (certutil, mshta, regsvr32) |
| T1055 | Process Injection | Behavioral rules (BEH-001 chain) |
| BEH-001 | Info Stealer Full Chain | Real-time correlator (30s window) |
| BEH-002 | Suspicious Process Writes Run Key | Real-time correlator (60s window) |

Full signature list: `rules/apt_signatures.json`, `rules/behavior_rules.json`

---

## Contributing

**Report false positives** — open an issue with:
- Entry name and value from `python -m core.threat_scorer --summary`
- The software that owns it
- Your Windows version

**Improve detection rules** — `rules/apt_signatures.json` and `rules/behavior_rules.json`
follow a documented schema. New signatures welcome via PR.

**Test on infected VMs** — if you have access to malware samples in a controlled
environment, scan results + VirusTotal links help validate detection coverage.

**Code** — see open issues. The project follows standard Python conventions.
No external testing framework required — run `python -m core.threat_scorer --summary`
to verify scorer changes don't produce false positives on a clean machine.

---

## Roadmap

See [PLAN.md](PLAN.md) for the full roadmap. Summary:

| Phase | Status | What |
|---|---|---|
| 1 | Done | Threat scorer, APT/stealer signatures, alert translator |
| 2 | Done | Windows service, tray icon, consumer UI, Tauri shell |
| 3 | Done | ETW real-time monitor, behavioral correlation |
| 4 | Planned | Network monitor, rule auto-update, community submission |
| 5 | Planned | Packaged installer, Microsoft Store |

---

## Limitations

- Windows only (Windows 10 / 11 / Server 2016+)
- Admin rights needed for service enumeration and HKLM key monitoring
- PID attribution for registry writes is probabilistic (RegNotifyChangeKeyValue
  does not report which process wrote a key — temporal correlation is used instead)
- Binary signature check uses a PowerShell subprocess — not for real-time use
- Port 8000 is localhost only; do not expose to a network without a reverse proxy
- No kernel driver, no Sysmon dependency
