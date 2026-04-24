"""
check_signatures.py
Checks service binary signatures (Authenticode) and SHA256 hashes.
Run from project root: python check_signatures.py [--critical] [--all] [--exe-only] [--json]

Outputs:
  - SHA256 hash of each binary
  - Authenticode signature status (Signed / Unsigned / Missing)
  - Signer name if signed
  - VirusTotal search URL (no API key needed)
  - Highlights unsigned binaries in suspicious paths
"""

import os
import sys
import json
import sqlite3
import hashlib
import re
import subprocess
import argparse
from pathlib import Path

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    ORANGE = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def crit(s):   return f"{C.RED}{C.BOLD}{s}{C.RESET}"
def warn(s):   return f"{C.ORANGE}{s}{C.RESET}"
def ok(s):     return f"{C.GREEN}{s}{C.RESET}"
def info(s):   return f"{C.CYAN}{s}{C.RESET}"
def gray(s):   return f"{C.GRAY}{s}{C.RESET}"

# ── Path extraction ────────────────────────────────────────────────────────────
def extract_exe_path(binary_path: str) -> str | None:
    """Extract the actual .exe path from a service ImagePath."""
    if not binary_path:
        return None

    bp = binary_path.strip()

    # Expand %SystemRoot%, %windir%, etc.
    bp = os.path.expandvars(bp)

    # Remove kernel driver style paths like \SystemRoot\...
    if bp.startswith("\\SystemRoot\\"):
        bp = bp.replace("\\SystemRoot\\", os.environ.get("SystemRoot", "C:\\Windows") + "\\")
    if bp.startswith("System32\\") or bp.startswith("system32\\"):
        bp = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), bp)

    # Handle quoted paths: "C:\path\to\exe.exe" args
    m = re.match(r'^"([^"]+\.exe)"', bp, re.IGNORECASE)
    if m:
        return m.group(1)

    # Handle unquoted with args: C:\path\to\exe.exe -args
    m = re.match(r'^([A-Za-z]:[^\s]*\.exe)', bp, re.IGNORECASE)
    if m:
        return m.group(1)

    # Handle svchost-style: %SystemRoot%\system32\svchost.exe -k ...
    m = re.match(r'^(\S+\.exe)', bp, re.IGNORECASE)
    if m:
        candidate = m.group(1)
        if os.path.exists(candidate):
            return candidate

    return None


# ── SHA256 hash ────────────────────────────────────────────────────────────────
def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ── Authenticode via PowerShell ────────────────────────────────────────────────
def check_signature(path: str) -> dict:
    """
    Returns dict with keys:
      status: 'Valid' | 'NotSigned' | 'HashMismatch' | 'UnknownError' | 'Missing'
      signer: str or None
      issuer: str or None
      timestamp: str or None
    """
    if not os.path.exists(path):
        return {"status": "Missing", "signer": None, "issuer": None, "timestamp": None}

    ps_cmd = (
        f'$sig = Get-AuthenticodeSignature -FilePath "{path}"; '
        f'$sig | Select-Object Status, '
        f'@{{n="Signer";e={{$_.SignerCertificate.Subject}}}}, '
        f'@{{n="Issuer";e={{$_.SignerCertificate.Issuer}}}}, '
        f'@{{n="Timestamp";e={{$_.SignerCertificate.NotAfter}}}} | '
        f'ConvertTo-Json'
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"status": "UnknownError", "signer": None, "issuer": None, "timestamp": None}

        data = json.loads(result.stdout.strip())
        status = data.get("Status", "UnknownError")
        # Status is an int in some PS versions
        status_map = {0: "Valid", 1: "HashMismatch", 2: "NotSigned", 3: "UnknownError",
                      4: "NotSupportedFileFormat", 5: "Incompatible"}
        if isinstance(status, int):
            status = status_map.get(status, f"Unknown({status})")

        signer = data.get("Signer") or ""
        # Extract CN= from subject
        cn_match = re.search(r'CN=([^,]+)', signer)
        signer_name = cn_match.group(1).strip() if cn_match else signer

        issuer = data.get("Issuer") or ""
        cn_match2 = re.search(r'CN=([^,]+)', issuer)
        issuer_name = cn_match2.group(1).strip() if cn_match2 else issuer

        return {
            "status": status,
            "signer": signer_name or None,
            "issuer": issuer_name or None,
            "timestamp": str(data.get("Timestamp", "") or ""),
        }
    except json.JSONDecodeError:
        return {"status": "UnknownError", "signer": None, "issuer": None, "timestamp": None}
    except Exception as e:
        return {"status": f"Error: {e}", "signer": None, "issuer": None, "timestamp": None}


# ── Suspicious path check ──────────────────────────────────────────────────────
SUSPICIOUS_DIRS = [
    r"c:\windows\temp", r"c:\temp", r"c:\users",
    r"\appdata\local\temp", r"\appdata\roaming",
    r"c:\recycler",
]

# ProgramData paths that are legitimately used by known vendors — not suspicious
PROGRAMDATA_WHITELIST = [
    r"c:\programdata\microsoft\windows defender",
    r"c:\programdata\microsoft\windows security",
    r"c:\programdata\avast",
    r"c:\programdata\avg",
    r"c:\programdata\malwarebytes",
    r"c:\programdata\bitdefender",
    r"c:\programdata\eset",
    r"c:\programdata\kaspersky",
]

def is_suspicious_path(path: str) -> bool:
    pl = path.lower()
    # Check whitelist first — known-safe ProgramData paths
    if any(pl.startswith(w) for w in PROGRAMDATA_WHITELIST):
        return False
    # Flag generic ProgramData and other suspicious locations
    suspicious = SUSPICIOUS_DIRS + [r"c:\programdata"]
    return any(s in pl for s in suspicious)

def is_system_path(path: str) -> bool:
    pl = path.lower()
    system_dirs = [
        "c:\\windows\\system32", "c:\\windows\\syswow64",
        "c:\\windows\\sysmon", "c:\\windows\\",
        "c:\\program files\\", "c:\\program files (x86)\\",
    ]
    return any(pl.startswith(s) for s in system_dirs)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Check service binary signatures and hashes")
    parser.add_argument("--critical", action="store_true", help="Only show Critical/High severity")
    parser.add_argument("--all", action="store_true", help="Include all services (not just High/Critical)")
    parser.add_argument("--exe-only", action="store_true", help="Skip drivers/COM handlers with no parseable exe path")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--unsigned-only", action="store_true", help="Only show unsigned binaries")
    parser.add_argument("--db", default="reghunt.db", help="Path to database")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"[!] Database not found: {args.db}")
        print("[!] Run a scan first: python collector/service_collector.py --scan")
        sys.exit(1)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    # Build query
    if args.all:
        rows = conn.execute(
            "SELECT * FROM service_entries ORDER BY severity DESC, service_name"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM service_entries WHERE severity IN ('critical','high') "
            "ORDER BY severity DESC, service_name"
        ).fetchall()

    if not rows:
        print("[*] No services found. Run --scan first.")
        conn.close()
        return

    results = []
    unsigned_count = 0
    missing_count = 0
    valid_count = 0

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    print()
    print(f"{C.BOLD}{'='*80}{C.RESET}")
    print(f"{C.BOLD}  Service Binary Signature & Hash Check{C.RESET}")
    print(f"{C.BOLD}{'='*80}{C.RESET}")
    print()

    for row in rows:
        svc = dict(row)
        name = svc["service_name"]
        bp = svc["binary_path"]
        severity = svc["severity"]
        ioc = svc.get("ioc_notes", "")

        exe_path = extract_exe_path(bp)

        result = {
            "service_name": name,
            "binary_path": bp,
            "exe_path": exe_path,
            "severity": severity,
            "ioc_notes": ioc,
            "sha256": None,
            "sig_status": None,
            "signer": None,
            "issuer": None,
            "vt_url": None,
            "suspicious_path": False,
            "file_exists": False,
        }

        if exe_path:
            result["file_exists"] = os.path.exists(exe_path)
            result["suspicious_path"] = is_suspicious_path(exe_path)

            sha256 = sha256_file(exe_path)
            result["sha256"] = sha256
            if sha256:
                result["vt_url"] = f"https://www.virustotal.com/gui/file/{sha256}"

            sig = check_signature(exe_path)
            result["sig_status"] = sig["status"]
            result["signer"] = sig["signer"]
            result["issuer"] = sig["issuer"]
        else:
            # Binary path is a driver, COM handler, or unparseable
            sig = {"status": "N/A (no exe path)", "signer": None, "issuer": None}
            result["sig_status"] = sig["status"]

        # Count stats
        if result["sig_status"] == "Valid":
            valid_count += 1
        elif result["sig_status"] == "NotSigned":
            unsigned_count += 1
        elif result["sig_status"] == "Missing":
            missing_count += 1

        results.append(result)

        # Filter for unsigned-only mode
        if args.unsigned_only and result["sig_status"] not in ("NotSigned", "Missing", "HashMismatch"):
            continue

        # Filter: skip drivers/COM handlers if --exe-only
        if getattr(args, 'exe_only', False) and not exe_path:
            continue

        # ── Print result ──
        sev_color = {
            "critical": C.RED + C.BOLD,
            "high": C.ORANGE,
            "medium": C.CYAN,
            "low": C.GRAY,
        }.get(severity, "")

        print(f"{sev_color}[{severity.upper()}]{C.RESET} {C.BOLD}{name}{C.RESET}")
        print(f"  Binary  : {bp[:100]}")

        if exe_path:
            if not result["file_exists"]:
                print(f"  Exe     : {warn('FILE NOT FOUND')} — {exe_path}")
            else:
                path_warn = warn(" ⚠ SUSPICIOUS PATH") if result["suspicious_path"] else ""
                print(f"  Exe     : {exe_path}{path_warn}")

            # Signature
            status = result["sig_status"]
            if status == "Valid":
                sig_str = ok(f"✅ Signed — {result['signer'] or 'Unknown signer'}")
            elif status == "NotSigned":
                sig_str = crit("❌ UNSIGNED")
            elif status == "HashMismatch":
                sig_str = crit("⚠️  HASH MISMATCH — signature tampered!")
            elif status == "Missing":
                sig_str = warn("📁 File missing")
            else:
                sig_str = warn(f"? {status}")
            print(f"  Sig     : {sig_str}")

            if result["signer"] and status == "Valid":
                print(f"  Issuer  : {gray(result['issuer'] or 'N/A')}")

            # Hash
            if result["sha256"]:
                print(f"  SHA256  : {gray(result['sha256'])}")
                print(f"  VT URL  : {info(result['vt_url'])}")
            else:
                print(f"  SHA256  : {warn('Could not compute hash')}")
        else:
            print(f"  Exe     : {gray('(driver / COM handler / unparseable path)')}")

        if ioc:
            print(f"  IOC     : {warn(ioc)}")

        print()

    # ── Summary ──
    driver_count = sum(1 for r in results if r["sig_status"] and r["sig_status"].startswith("N/A"))
    exe_count = len(results) - driver_count

    print(f"{C.BOLD}{'='*80}{C.RESET}")
    print(f"{C.BOLD}  Summary{C.RESET}")
    print(f"{'='*80}")
    print(f"  Services checked : {len(rows)}")
    print(f"  {gray(f'Drivers/no-exe   : {driver_count} (skipped)')}")
    print(f"  Exe binaries     : {exe_count}")
    print(f"  {ok(f'Signed           : {valid_count}')}")
    print(f"  {crit(f'Unsigned         : {unsigned_count}')}")
    print(f"  {warn(f'File missing     : {missing_count}')}")
    print()

    unsigned = [r for r in results if r["sig_status"] in ("NotSigned", "HashMismatch")]
    if unsigned:
        print(f"{crit('⚠️  UNSIGNED SERVICES (investigate these):')} ")
        for r in unsigned:
            path_flag = " [SUSPICIOUS PATH]" if r["suspicious_path"] else ""
            vt = f"\n      VT: {r['vt_url']}" if r["vt_url"] else ""
            print(f"    🔴 {r['service_name']}{path_flag}")
            print(f"       {r['exe_path']}")
            if r["sha256"]:
                print(f"       SHA256: {r['sha256']}{vt}")
        print()

    missing_files = [r for r in results if r["sig_status"] == "Missing"]
    if missing_files:
        print(f"{warn('⚠️  MISSING BINARY FILES (ghost services):')}")
        for r in missing_files:
            print(f"    👻 {r['service_name']} → {r['exe_path']}")
        print()

    # JSON output
    if args.json:
        out_path = "signature_results.json"
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] JSON results written to {out_path}")

    conn.close()


if __name__ == "__main__":
    main()