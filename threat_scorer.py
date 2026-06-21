"""
threat_scorer.py
================
Threat scoring engine for Persistence-Hunter.

Produces a 0-100 score for each persistence entry with:
- Breakdown of scoring factors
- APT group attribution (from apt_signatures.json)
- Process hashes surfaced from sysmon_process_events into chain nodes
- Risk indicators for the enrichment panel

Usage:
    python threat_scorer.py               # score all entries
    python threat_scorer.py --entry registry/6   # score single entry
    python threat_scorer.py --summary     # print top 10 by score

Changes from original:
    - Fixed val_pat fall-through bug in match_apt_signatures()
    - Moved os import to top level (was inside functions)
    - Added negative weights for trusted/clean indicators
    - Fixed list[dict] type hints for Python < 3.9 compatibility
    - Expanded LEGIT_APPDATA_APPS and SYSTEM_TASK_PREFIXES
    - Added T1555.003 credential theft scoring signals
    - Added stealer-specific path and name patterns
"""

from __future__ import annotations

import os
import json
import sqlite3
import argparse
from pathlib import Path
from typing import List, Dict, Optional

DB_PATH  = "reghunt.db"
SIG_PATH = Path(__file__).parent / "apt_signatures.json"

# ---------------------------------------------------------------------------
# Score weights — positive = more suspicious, negative = more trusted
# ---------------------------------------------------------------------------

WEIGHTS = {
    # Binary / file properties
    "unsigned_binary":           +30,
    "suspicious_path":           +20,
    "temp_path":                 +25,
    "appdata_path":              +15,
    "nonexistent_file":          +10,

    # FIX: Added negative weights — missing entirely from original
    "signed_system32_binary":    -20,   # signed binary in System32 = likely legit
    "known_vendor_binary":       -15,   # recognised software vendor
    "program_files_binary":      -10,   # installed to Program Files properly

    # Chain properties
    "written_by_lolbin":         +25,
    "written_by_powershell":     +28,
    "written_by_script_engine":  +22,
    "deep_chain":                +15,   # 4+ hops
    "chain_contains_malicious":  +35,
    "chain_contains_lolbin":     +15,
    "unknown_writer":            +5,

    # Command line signals
    "encoded_command":           +30,
    "hidden_window":             +25,
    "download_cradle":           +35,
    "bypass_execution_policy":   +20,
    "no_profile_flag":           +10,

    # Credential theft signals (T1555.003) — NEW
    "browser_db_access":         +40,
    "dpapi_abuse":               +30,
    "credential_path_reference": +35,
    "post_access_exfil":         +40,
    "wallet_access":             +35,

    # Threat intel (from enrichment)
    "vt_detections_high":        +40,
    "vt_detections_low":         +20,
    "malwarebazaar_hit":         +40,

    # Name signals
    "masquerade_name":           +25,
    "suspicious_name_pattern":   +20,
    "stealer_name_pattern":      +30,   # NEW — commodity stealer naming patterns

    # Entry type modifiers
    "ifeo_key":                  +35,
    "winlogon_key":              +25,
    "run_key_base":              +5,

    # APT / stealer signature match
    "apt_sig_high":              +35,
    "apt_sig_medium":            +20,
    "apt_sig_low":               +10,
}

LOLBINS = {
    "powershell.exe", "cmd.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "wscript.exe", "cscript.exe",
    "reg.exe", "msiexec.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "odbcconf.exe", "msbuild.exe", "cmstp.exe",
    "schtasks.exe", "sc.exe", "forfiles.exe", "bitsadmin.exe",
    "desktopimgdownldr.exe", "esentutl.exe",
}

SCRIPT_ENGINES = {
    "python.exe", "python3.exe", "python3.11.exe", "node.exe",
    "ruby.exe", "perl.exe", "wscript.exe", "cscript.exe",
}

# ---------------------------------------------------------------------------
# EXPANDED: Known-legitimate apps that legitimately self-register in AppData
# ---------------------------------------------------------------------------
LEGIT_APPDATA_APPS = {
    # Communication
    "spotify.exe", "discord.exe", "slack.exe", "teams.exe",
    "zoom.exe", "telegram.exe", "signal.exe", "whatsapp.exe",
    "skype.exe", "viber.exe", "threema.exe", "element.exe",
    # Productivity
    "notion.exe", "grammarly.exe", "obsidian.exe", "logseq.exe",
    "todoist.exe", "evernote.exe", "onenote.exe",
    # Cloud storage
    "onedrive.exe", "dropbox.exe", "googledrivesync.exe",
    "googledrive.exe", "box.exe", "mega.exe",
    # Gaming
    "steam.exe", "epicgameslauncher.exe", "origin.exe", "eadesktop.exe",
    "battle.net.exe", "overwolf.exe", "gog.exe", "goggalaxy.exe",
    "uplay.exe", "ubisoft connect.exe", "rockstargameslauncher.exe",
    "xbox.exe",
    # Browsers (sometimes self-register updaters)
    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
    "opera.exe", "vivaldi.exe",
    # Dev tools
    "code.exe", "cursor.exe", "githubdesktop.exe", "gitkraken.exe",
    "sourcetree.exe", "windowsterminal.exe",
    # Other common
    "bittorrent.exe", "utorrent.exe", "qbittorrent.exe",
    "fractal.exe", "parsec.exe", "anydesk.exe",
    # Password managers (legit)
    "1password.exe", "bitwarden.exe", "keepass.exe", "lastpass.exe",
}

# ---------------------------------------------------------------------------
# System task path prefixes — skip APT signature matching for these
# ---------------------------------------------------------------------------
SYSTEM_TASK_PREFIXES = [
    r"\microsoft\windows",
    r"\microsoft\office",
    r"\microsoft\onecore",
    r"\microsoft\visualstudio",
    r"\microsoft\net",
    r"\lenovo",
    r"\dell",
    r"\hp",
    r"\intel",
    r"\nvidia",
    r"\amd",
    r"\avast software",
    r"\avg",
    r"\eset",
    r"\kaspersky",
    r"\malwarebytes",
    r"\google",
    r"\mozilla",
    r"\apple",
    r"\adobe",
    r"\softlanding",
]

# Known trusted vendors — binary signed by these in Program Files = negative score
TRUSTED_VENDORS = {
    "microsoft", "google", "mozilla", "apple", "adobe",
    "oracle", "intel", "nvidia", "amd", "realtek",
    "malwarebytes", "eset", "kaspersky", "avast", "avg",
    "dropbox", "slack", "zoom", "spotify",
}

MASQUERADE_NAMES = [
    "windowsupdate", "winupdate", "wuauserv", "wuauclt",
    "svchost32", "lsass32", "svcupdate32", "svchosts",
    "lsasss", "csrss32", "services32", "explorer32",
    "taskmgr32", "regedit32",
]

# NEW: Commodity stealer name patterns
STEALER_NAME_PATTERNS = [
    "helper", "updater", "update", "sync", "loader",
    "runtime", "host", "service", "agent", "client",
]

SUSPICIOUS_PATHS = [
    r"\appdata\roaming",
    r"\appdata\local\temp",
    r"c:\users\public",
    r"c:\temp",
    r"c:\windows\temp",
    r"\downloads",
    r"c:\malware",
    r"c:\perflogs",
    r"\appdata\local\microsoft\windows\inetcache",
]

# NEW: Browser credential paths — presence in persistence value = very suspicious
BROWSER_CREDENTIAL_PATHS = [
    r"google\chrome\user data",
    r"microsoft\edge\user data",
    r"mozilla\firefox\profiles",
    r"brave-browser\user data",
    r"yandex\yandexbrowser\user data",
    r"opera software\opera stable",
    r"network\cookies",
    r"login data",
    r"web data",
]

# NEW: Crypto wallet paths
WALLET_PATHS = [
    r"ethereum\keystore",
    r"bitcoin\wallet.dat",
    r"electrum\wallets",
    r"\exodus",
    r"\atomic",
    r"\metamask",
    r"\phantom",
]

# ---------------------------------------------------------------------------
# Hash enrichment
# ---------------------------------------------------------------------------

def enrich_chain_with_hashes(
    chain: List[Dict], conn: sqlite3.Connection
) -> List[Dict]:
    """
    For each node in the chain, look up the process hash from
    sysmon_process_events and attach it to the node dict.
    """
    for node in chain:
        pid        = node.get("pid")
        event_time = node.get("event_time")
        if not pid or not event_time:
            continue

        row = conn.execute("""
            SELECT hashes, integrity_level
            FROM   sysmon_process_events
            WHERE  pid = ? AND event_time <= ?
            ORDER  BY event_time DESC
            LIMIT  1
        """, (pid, event_time)).fetchone()

        if row and row["hashes"]:
            hashes_dict: Dict[str, str] = {}
            for part in row["hashes"].split(","):
                part = part.strip()
                if "=" in part:
                    algo, val = part.split("=", 1)
                    hashes_dict[algo.upper()] = val.lower()
            node["hashes"] = hashes_dict

        if row and row["integrity_level"]:
            node["integrity_level"] = row["integrity_level"]

    return chain

# ---------------------------------------------------------------------------
# APT signature matching — BUG FIX: val_pat fall-through corrected
# ---------------------------------------------------------------------------

def load_signatures() -> List[Dict]:
    if SIG_PATH.exists():
        with open(SIG_PATH) as f:
            return json.load(f)
    return []


def match_apt_signatures(
    entry: Dict, chain: List[Dict], sigs: List[Dict]
) -> List[Dict]:
    """
    Return list of matched signature dicts with an added 'matched_reasons' key.

    BUG FIX from original:
    The original code had a fall-through where signatures with val_pat that
    didn't match could still register as hits when chain_pattern was also
    present. The logic now correctly requires ALL specified pattern types
    to match before a signature fires.
    """
    matches = []

    name  = (entry.get("name") or entry.get("task_name") or
             entry.get("service_name") or "").lower()
    value = (entry.get("value_data") or entry.get("command") or
             entry.get("binary_path") or "").lower()

    _parts   = value.split('"') if value.startswith('"') else value.split()
    _bin     = os.path.basename(
        _parts[1] if len(_parts) > 1 else (_parts[0] if _parts else "")
    ).lower()
    is_legit = _bin in LEGIT_APPDATA_APPS

    chain_names  = [n.get("name", "").lower() for n in chain]
    all_cmdlines = " ".join((n.get("cmdline") or "").lower() for n in chain)

    for sig in sigs:
        if is_legit and sig.get("id") in ("APT-SIG-007",):
            continue

        matched_reasons: List[str] = []

        # ── chain_pattern ────────────────────────────────────────────────
        chain_pat = sig.get("chain_pattern", [])
        if chain_pat:
            for pat in chain_pat:
                if any(pat.lower() in cn for cn in chain_names):
                    matched_reasons.append(f"chain contains '{pat}'")
                    break
            else:
                continue  # required but nothing matched

        # ── child_pattern ────────────────────────────────────────────────
        child_pat = sig.get("child_pattern", [])
        if child_pat:
            found_child = False
            for pat in child_pat:
                if any(pat.lower() in cn for cn in chain_names):
                    matched_reasons.append(f"spawned '{pat}'")
                    found_child = True
                    break
            if not found_child:
                continue  # required but nothing matched

        # ── value_pattern ────────────────────────────────────────────────
        val_pat = sig.get("value_pattern", [])
        if val_pat:
            matched_val = False
            for pat in val_pat:
                if pat.lower() in value or pat.lower() in all_cmdlines:
                    matched_reasons.append(f"value contains '{pat}'")
                    matched_val = True
                    break
            # FIX: was falling through here — now always skip if val_pat
            # was specified but nothing matched, regardless of other patterns
            if not matched_val:
                continue

        # ── name_pattern ─────────────────────────────────────────────────
        name_pat = sig.get("name_pattern", [])
        if name_pat:
            matched_name = False
            for pat in name_pat:
                if pat.lower() in name or pat.lower() in value:
                    matched_reasons.append(f"name matches '{pat}'")
                    matched_name = True
                    break
            if not matched_name:
                continue

        # ── target_pattern ───────────────────────────────────────────────
        target_pat = sig.get("target_pattern", [])
        if target_pat:
            target_str = (
                (entry.get("reg_path")   or "") + " " +
                (entry.get("task_path")  or "") + " " +
                value
            ).lower()
            if not any(p.lower() in target_str for p in target_pat):
                continue
            matched_reasons.append("target path matches signature")

        # ── must have matched something ───────────────────────────────────
        if not matched_reasons:
            continue

        matches.append({**sig, "matched_reasons": matched_reasons})

    return matches

# ---------------------------------------------------------------------------
# Core scorer
# ---------------------------------------------------------------------------

def score_entry(
    entry: Dict,
    chain: List[Dict],
    enrichment: Optional[Dict],
    sigs: List[Dict],
) -> Dict:
    """
    Returns {
        score:           int (0-100),
        breakdown:       list of {factor, delta, description},
        apt_matches:     list of matched signature dicts,
        risk_indicators: list of {type, severity, description}
    }
    """
    breakdown:       List[Dict] = []
    risk_indicators: List[Dict] = []
    score = 0

    def add(factor: str, delta: int, description: str) -> None:
        nonlocal score
        score += delta
        breakdown.append({
            "factor": factor, "delta": delta, "description": description
        })

    name  = (entry.get("name") or entry.get("task_name") or
             entry.get("service_name") or "").lower()
    value = (entry.get("value_data") or entry.get("command") or
             entry.get("binary_path") or "").lower()

    # ── 1. Base entry type ───────────────────────────────────────────────
    reg_path = (entry.get("reg_path") or "").lower()
    if "ifeo" in reg_path or "image file execution" in value:
        add("ifeo_key", WEIGHTS["ifeo_key"],
            "IFEO Debugger key — attacker gains SYSTEM when accessibility "
            "tool is triggered")
        risk_indicators.append({
            "type": "ifeo_hijack", "severity": "critical",
            "description": "Image File Execution Options debugger key — "
                           "classic accessibility tool hijack for SYSTEM access",
        })
    elif "winlogon" in reg_path:
        add("winlogon_key", WEIGHTS["winlogon_key"],
            "Winlogon persistence — executed at every user logon")
    else:
        add("run_key_base", WEIGHTS["run_key_base"],
            "Standard Run key persistence")

    # ── 2. Path analysis ─────────────────────────────────────────────────
    _parts   = value.split('"') if value.startswith('"') else value.split()
    _bin     = os.path.basename(
        _parts[1] if len(_parts) > 1 else (_parts[0] if _parts else "")
    ).lower()

    if r"\windows\temp" in value or (r"\temp\\" in value and
                                      r"\appdata\local\temp" not in value):
        add("temp_path", WEIGHTS["temp_path"],
            "Binary in Windows Temp — common dropper placement")
        risk_indicators.append({
            "type": "temp_directory_binary", "severity": "high",
            "description": f"Executable in Temp directory: {value[:60]}",
        })

    elif r"\appdata\roaming" in value and _bin not in LEGIT_APPDATA_APPS:
        add("appdata_path", WEIGHTS["appdata_path"],
            "Binary in AppData\\Roaming — non-admin persistence used by malware")
        risk_indicators.append({
            "type": "appdata_persistence", "severity": "medium",
            "description": "Binary installed in AppData\\Roaming without admin rights",
        })

    elif any(p in value for p in [r"c:\users\public", r"c:\temp",
                                   r"c:\malware", r"c:\perflogs"]):
        add("suspicious_path", WEIGHTS["suspicious_path"],
            "Binary in suspicious world-writable path")
        risk_indicators.append({
            "type": "suspicious_path", "severity": "high",
            "description": f"Binary in suspicious path: {value[:60]}",
        })

    elif r"\program files" in value or r"\windows\system32" in value:
        # FIX: Negative weight for properly installed binaries
        add("program_files_binary", WEIGHTS["program_files_binary"],
            "Binary in Program Files or System32 — expected install location")

    # ── 3. Name signals ──────────────────────────────────────────────────
    for masq in MASQUERADE_NAMES:
        if masq in name or masq in value:
            add("masquerade_name", WEIGHTS["masquerade_name"],
                f"Name masquerades as system process: '{masq}'")
            risk_indicators.append({
                "type": "masquerading", "severity": "high",
                "description": f"Entry mimics legitimate system process: '{masq}'",
            })
            break

    # NEW: Commodity stealer naming pattern + suspicious path combo
    if any(pat in name for pat in STEALER_NAME_PATTERNS):
        if any(p in value for p in [r"\appdata", r"\temp", r"\users\public"]):
            add("stealer_name_pattern", WEIGHTS["stealer_name_pattern"],
                "Generic name (update/helper/host) combined with suspicious "
                "path — common commodity stealer pattern")
            risk_indicators.append({
                "type": "stealer_name_pattern", "severity": "high",
                "description": f"Generic name '{name}' with suspicious binary "
                               f"path — matches commodity stealer fingerprint",
            })

    # ── 4. Command line signals ──────────────────────────────────────────
    all_cmd = value + " " + " ".join(
        (n.get("cmdline") or "").lower() for n in chain
    )

    if "-enc " in all_cmd or "-encodedcommand" in all_cmd or \
            "frombase64" in all_cmd:
        add("encoded_command", WEIGHTS["encoded_command"],
            "Base64-encoded PowerShell command detected")
        risk_indicators.append({
            "type": "encoded_payload", "severity": "critical",
            "description": "Base64-encoded command — typical of obfuscated "
                           "malware stagers and APT beacons",
        })

    if "-w hidden" in all_cmd or "-windowstyle hidden" in all_cmd:
        add("hidden_window", WEIGHTS["hidden_window"],
            "Hidden window flag — process runs invisibly")
        risk_indicators.append({
            "type": "hidden_execution", "severity": "high",
            "description": "Process launched with hidden window — "
                           "typical of stealth persistence",
        })

    if ("downloadstring" in all_cmd or "webclient" in all_cmd or
            "invoke-webrequest" in all_cmd or "curl" in all_cmd):
        add("download_cradle", WEIGHTS["download_cradle"],
            "Download cradle — fetches payload from network")
        risk_indicators.append({
            "type": "download_cradle", "severity": "critical",
            "description": "Command downloads payload from remote server",
        })

    if "bypass" in all_cmd:
        add("bypass_execution_policy", WEIGHTS["bypass_execution_policy"],
            "ExecutionPolicy bypass flag")

    if "-nop" in all_cmd or "-noprofile" in all_cmd:
        add("no_profile_flag", WEIGHTS["no_profile_flag"],
            "NoProfile flag — avoids profile-based detection")

    # ── 5. Credential theft signals (T1555.003) — NEW ───────────────────
    if any(p in value or p in all_cmd for p in BROWSER_CREDENTIAL_PATHS):
        add("browser_db_access", WEIGHTS["browser_db_access"],
            "References browser credential store — info stealer fingerprint "
            "(T1555.003)")
        risk_indicators.append({
            "type": "browser_credential_access", "severity": "critical",
            "description": "Persistence value references browser password/cookie "
                           "database — direct indicator of info stealer "
                           "(Lumma, Redline, Stealc)",
        })

    if "cryptunprotectdata" in all_cmd or "dpapi" in all_cmd:
        add("dpapi_abuse", WEIGHTS["dpapi_abuse"],
            "DPAPI references detected — credential decryption attempt")
        risk_indicators.append({
            "type": "dpapi_abuse", "severity": "critical",
            "description": "DPAPI function references found — used by info "
                           "stealers to decrypt browser-stored credentials",
        })

    if any(p in value or p in all_cmd for p in WALLET_PATHS):
        add("wallet_access", WEIGHTS["wallet_access"],
            "References crypto wallet path — crypto stealer indicator")
        risk_indicators.append({
            "type": "crypto_wallet_access", "severity": "critical",
            "description": "Persistence references crypto wallet location — "
                           "common in stealers targeting crypto holders",
        })

    # ── 6. Chain analysis ────────────────────────────────────────────────
    if chain:
        chain_names = [n.get("name", "").lower() for n in chain]
        writer_name = chain[-1].get("name", "").lower() if chain else ""
        source      = chain[0].get("source", "unknown") if chain else "unknown"

        if "powershell.exe" in writer_name:
            add("written_by_powershell", WEIGHTS["written_by_powershell"],
                "Persistence written directly by PowerShell")
            risk_indicators.append({
                "type": "powershell_writer", "severity": "high",
                "description": "Persistence entry written by PowerShell — "
                               "common in fileless attacks",
            })
        elif any(eng in writer_name for eng in SCRIPT_ENGINES):
            add("written_by_script_engine", WEIGHTS["written_by_script_engine"],
                f"Written by script engine: {writer_name}")
        elif (writer_name in {l.lower() for l in LOLBINS} and
              writer_name not in {"reg.exe", "sc.exe", "schtasks.exe"}):
            add("written_by_lolbin", WEIGHTS["written_by_lolbin"],
                f"Persistence written by LOLBin: {writer_name}")

        if len(chain) >= 4:
            add("deep_chain", WEIGHTS["deep_chain"],
                f"Deep execution chain: {len(chain)} hops — "
                "suggests multi-stage attack")

        has_malicious = any(
            n.get("type") == "malicious" and
            n.get("name", "").lower() not in LEGIT_APPDATA_APPS
            for n in chain
        )
        if has_malicious:
            add("chain_contains_malicious", WEIGHTS["chain_contains_malicious"],
                "Chain contains a malicious-classified process")
            risk_indicators.append({
                "type": "malicious_chain_node", "severity": "critical",
                "description": "Attack chain contains a process classified "
                               "as malicious",
            })

        lolbin_in_chain = [
            n["name"] for n in chain
            if n.get("name", "").lower() in {l.lower() for l in LOLBINS}
        ]
        if lolbin_in_chain:
            add("chain_contains_lolbin", WEIGHTS["chain_contains_lolbin"],
                f"LOLBins in chain: {', '.join(set(lolbin_in_chain))}")

        if source == "unknown":
            add("unknown_writer", WEIGHTS["unknown_writer"],
                "Cannot trace process that wrote this entry")

    # ── 7. Enrichment signals ────────────────────────────────────────────
    if enrichment:
        vt_malicious = enrichment.get("vt_malicious", 0) or 0
        vt_total     = enrichment.get("vt_total",     0) or 0
        mb_found     = enrichment.get("mb_found",  False)
        pe_signed    = enrichment.get("pe_signed",  None)
        pe_is_pe     = enrichment.get("pe_is_pe",  False)
        pe_vendor    = (enrichment.get("pe_vendor") or "").lower()

        if vt_malicious > 5:
            add("vt_detections_high", WEIGHTS["vt_detections_high"],
                f"VirusTotal: {vt_malicious}/{vt_total} engines flagged this")
            risk_indicators.append({
                "type": "vt_high_detection", "severity": "critical",
                "description": f"VirusTotal: {vt_malicious}/{vt_total} "
                               "AV engines flagged this file",
            })
        elif vt_malicious > 0:
            add("vt_detections_low", WEIGHTS["vt_detections_low"],
                f"VirusTotal: {vt_malicious}/{vt_total} engines flagged this")
            risk_indicators.append({
                "type": "vt_low_detection", "severity": "high",
                "description": f"VirusTotal: {vt_malicious} engine(s) "
                               "flagged this file",
            })

        if mb_found:
            add("malwarebazaar_hit", WEIGHTS["malwarebazaar_hit"],
                f"MalwareBazaar hit: {enrichment.get('mb_signature', 'unknown')}")
            risk_indicators.append({
                "type": "malwarebazaar_match", "severity": "critical",
                "description": f"Hash in MalwareBazaar: "
                               f"{enrichment.get('mb_signature', 'unknown family')}",
            })

        if pe_is_pe and pe_signed is False:
            add("unsigned_binary", WEIGHTS["unsigned_binary"],
                "Unsigned PE executable")
            risk_indicators.append({
                "type": "unsigned_executable", "severity": "high",
                "description": "PE is unsigned — legitimate software is "
                               "almost always signed",
            })
        elif pe_is_pe and pe_signed and \
                any(v in pe_vendor for v in TRUSTED_VENDORS):
            # FIX: Negative weight for known trusted vendor signature
            add("known_vendor_binary", WEIGHTS["known_vendor_binary"],
                f"Binary signed by trusted vendor: {pe_vendor}")

    # ── 8. APT / stealer signature matching ─────────────────────────────
    task_path    = (entry.get("task_path") or entry.get("task_name") or "").lower()
    is_sys_task  = any(task_path.startswith(p) for p in SYSTEM_TASK_PREFIXES)
    apt_matches  = [] if is_sys_task else match_apt_signatures(entry, chain, sigs)

    for match in apt_matches:
        confidence = match.get("confidence", "medium")
        weight_key = f"apt_sig_{confidence}"
        boost      = match.get("severity_boost", WEIGHTS.get(weight_key, 15))
        add(
            f"apt_match_{match['id']}", boost,
            f"Matches {match['name']} — "
            f"attributed to: {', '.join(match['apt_groups'])}",
        )
        risk_indicators.append({
            "type":        "apt_signature_match",
            "severity":    "critical" if confidence == "high" else "high",
            "description": f"[{match['id']}] {match['name']}: matches TTPs "
                           f"of {', '.join(match['apt_groups'][:3])}",
            "apt_groups":  match["apt_groups"],
            "mitre":       match["mitre"],
        })

    # ── Cap at 100, floor at 0 ───────────────────────────────────────────
    score = max(0, min(score, 100))

    return {
        "score":           score,
        "breakdown":       breakdown,
        "apt_matches":     apt_matches,
        "risk_indicators": risk_indicators,
    }

# ---------------------------------------------------------------------------
# DB integration
# ---------------------------------------------------------------------------

def _load_enrichment(
    conn: sqlite3.Connection, entry_type: str, entry_id: int
) -> Optional[Dict]:
    row = conn.execute("""
        SELECT * FROM enrichment_results
        WHERE  entry_type = ? AND entry_id = ?
    """, (entry_type, entry_id)).fetchone()
    return dict(row) if row else None


def _load_chain(
    conn: sqlite3.Connection, entry_type: str, entry_id: int
) -> List[Dict]:
    row = conn.execute("""
        SELECT chain_json FROM attack_chains
        WHERE  entry_type = ? AND entry_id = ?
    """, (entry_type, entry_id)).fetchone()
    if not row or not row["chain_json"]:
        return []
    return json.loads(row["chain_json"])


def _ensure_score_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_scores (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_type    TEXT    NOT NULL,
            entry_id      INTEGER NOT NULL,
            score         INTEGER NOT NULL,
            breakdown_json TEXT,
            apt_json      TEXT,
            risk_json     TEXT,
            scored_at     TEXT,
            UNIQUE(entry_type, entry_id)
        )
    """)
    conn.commit()


def score_all(db_path: str = DB_PATH, verbose: bool = True) -> int:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_score_table(conn)
    sigs = load_signatures()

    tables = [
        ("registry", "registry_entries", "name"),
        ("task",     "task_entries",     "task_name"),
        ("service",  "service_entries",  "service_name"),
    ]
    total_scored = 0

    for entry_type, table, name_col in tables:
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        for row in rows:
            entry              = dict(row)
            entry["entry_type"] = entry_type
            chain              = _load_chain(conn, entry_type, entry["id"])
            chain              = enrich_chain_with_hashes(chain, conn)
            enrichment         = _load_enrichment(conn, entry_type, entry["id"])
            result             = score_entry(entry, chain, enrichment, sigs)

            conn.execute("""
                INSERT OR REPLACE INTO threat_scores
                    (entry_type, entry_id, score, breakdown_json,
                     apt_json, risk_json, scored_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """, (
                entry_type, entry["id"],
                result["score"],
                json.dumps(result["breakdown"]),
                json.dumps(result["apt_matches"]),
                json.dumps(result["risk_indicators"]),
            ))

            if chain:
                conn.execute("""
                    UPDATE attack_chains SET chain_json = ?
                    WHERE  entry_type = ? AND entry_id = ?
                """, (json.dumps(chain), entry_type, entry["id"]))

            conn.commit()
            total_scored += 1

            if verbose:
                name    = entry.get(name_col, "?")
                apts    = [m["name"] for m in result["apt_matches"]]
                apt_str = f" → APT: {', '.join(apts[:2])}" if apts else ""
                print(f"  [{result['score']:3d}] [{entry_type:8s}] "
                      f"{name[:40]}{apt_str}")

    conn.close()
    if verbose:
        print(f"\n[+] Scored {total_scored} entries")
    return total_scored


def score_single(db_path: str, entry_type: str, entry_id: int) -> None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _ensure_score_table(conn)
    sigs = load_signatures()

    table_map = {
        "registry": "registry_entries",
        "task":     "task_entries",
        "service":  "service_entries",
    }
    table = table_map.get(entry_type)
    if not table:
        print(f"[!] Unknown entry type: {entry_type}")
        return

    row = conn.execute(f"SELECT * FROM {table} WHERE id=?", (entry_id,)).fetchone()
    if not row:
        print(f"[!] Entry not found: {entry_type}/{entry_id}")
        return

    entry              = dict(row)
    entry["entry_type"] = entry_type
    chain              = _load_chain(conn, entry_type, entry_id)
    chain              = enrich_chain_with_hashes(chain, conn)
    enrichment         = _load_enrichment(conn, entry_type, entry_id)
    result             = score_entry(entry, chain, enrichment, sigs)

    print(f"\n{'='*60}")
    print(f"  Score: {result['score']}/100")
    print(f"{'='*60}")
    print("\nBreakdown:")
    for b in result["breakdown"]:
        sign = "+" if b["delta"] > 0 else ""
        print(f"  {sign}{b['delta']:+3d}  {b['factor']}")
        print(f"         {b['description']}")

    if result["apt_matches"]:
        print(f"\nAPT Matches ({len(result['apt_matches'])}):")
        for m in result["apt_matches"]:
            print(f"  [{m['id']}] {m['name']}")
            print(f"    Groups : {', '.join(m['apt_groups'])}")
            print(f"    MITRE  : {', '.join(m['mitre'])}")
            print(f"    Matched: {'; '.join(m['matched_reasons'])}")

    if result["risk_indicators"]:
        print("\nRisk Indicators:")
        for r in result["risk_indicators"]:
            print(f"  [{r['severity'].upper():8s}] {r['type']}")
            print(f"             {r['description'][:80]}")

    conn.close()


def print_summary(db_path: str = DB_PATH, top_n: int = 15) -> None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT ts.entry_type, ts.entry_id, ts.score, ts.apt_json,
               COALESCE(r.name, t.task_name, s.service_name, '?') AS name
        FROM   threat_scores ts
        LEFT   JOIN registry_entries r
               ON ts.entry_type='registry' AND ts.entry_id=r.id
        LEFT   JOIN task_entries t
               ON ts.entry_type='task'     AND ts.entry_id=t.id
        LEFT   JOIN service_entries s
               ON ts.entry_type='service'  AND ts.entry_id=s.id
        ORDER  BY ts.score DESC
        LIMIT  ?
    """, (top_n,)).fetchall()
    conn.close()

    print(f"\n{'='*65}")
    print(f"  TOP {top_n} THREAT SCORES")
    print(f"{'='*65}")
    for row in rows:
        apts = []
        try:
            apt_data = json.loads(row["apt_json"] or "[]")
            apts = list({g for m in apt_data for g in m.get("apt_groups", [])})[:3]
        except Exception:
            pass
        apt_str = f"  [{', '.join(apts)}]" if apts else ""
        print(f"  {row['score']:3d}/100  [{row['entry_type']:8s}]  "
              f"{row['name'][:35]:35s}{apt_str}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Persistence-Hunter Threat Scorer")
    parser.add_argument("--db",      default=DB_PATH, help="Path to reghunt.db")
    parser.add_argument("--entry",   help="Score single entry, e.g. registry/6")
    parser.add_argument("--summary", action="store_true",
                        help="Print top entries by score")
    parser.add_argument("--top",     type=int, default=15,
                        help="Number of entries to show in summary")
    args = parser.parse_args()

    if args.entry:
        parts = args.entry.split("/")
        if len(parts) != 2:
            print("[!] Use --entry <type>/<id>, e.g. registry/6")
        else:
            score_single(args.db, parts[0], int(parts[1]))
    elif args.summary:
        print_summary(args.db, args.top)
    else:
        print("[*] Scoring all entries...")
        score_all(args.db, verbose=True)
        print_summary(args.db)