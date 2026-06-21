"""
enrichment/local.py
===================
Local PE signature check using PowerShell Get-AuthenticodeSignature.
No API key required. Runs synchronously. Always available.

Returns a dict suitable for use as the `enrichment` argument to score_entry():
    {
        "pe_is_pe":  bool   — True if path resolved to an .exe
        "pe_signed": bool   — True if Authenticode status is Valid
        "pe_vendor": str    — CN from signer certificate subject, or ""
    }
"""

from __future__ import annotations

import os
import re
import json
import subprocess
from typing import Optional


def _extract_exe_path(value: str) -> Optional[str]:
    """Pull the first .exe path out of a persistence value / binary path."""
    if not value:
        return None
    v = os.path.expandvars(value.strip())

    m = re.match(r'^"([^"]+\.exe)"', v, re.IGNORECASE)
    if m:
        return m.group(1)

    m = re.match(r'^([A-Za-z]:[^\s"]+\.exe)', v, re.IGNORECASE)
    if m:
        return m.group(1)

    m = re.match(r'^(\S+\.exe)', v, re.IGNORECASE)
    if m and os.path.exists(m.group(1)):
        return m.group(1)

    return None


def check_signature(path: str) -> dict:
    """
    Run Get-AuthenticodeSignature on *path* via PowerShell.
    Returns:
        {"signed": bool, "publisher": str, "status": str}
    Never raises — returns {"signed": False, "publisher": "", "status": "error"} on failure.
    """
    if not os.path.isfile(path):
        return {"signed": False, "publisher": "", "status": "missing"}

    ps = (
        f'$s = Get-AuthenticodeSignature -FilePath "{path}"; '
        f'$s | Select-Object Status, '
        f'@{{n="Signer";e={{$_.SignerCertificate.Subject}}}} | ConvertTo-Json'
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"signed": False, "publisher": "", "status": "ps_error"}

        data = json.loads(result.stdout.strip())
        status = data.get("Status", "")
        status_map = {0: "Valid", 1: "HashMismatch", 2: "NotSigned",
                      3: "UnknownError", 4: "NotSupportedFileFormat"}
        if isinstance(status, int):
            status = status_map.get(status, f"Unknown({status})")

        signer_subject = data.get("Signer") or ""
        cn_match = re.search(r"CN=([^,]+)", signer_subject)
        publisher = cn_match.group(1).strip() if cn_match else signer_subject.strip()

        return {
            "signed":    status == "Valid",
            "publisher": publisher,
            "status":    status,
        }
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return {"signed": False, "publisher": "", "status": "error"}


def enrich_entry(entry: dict) -> dict:
    """
    Given a persistence entry dict, resolve the binary path and check
    its Authenticode signature.

    Returns a dict with keys expected by score_entry():
        pe_is_pe  — whether we found an .exe to check
        pe_signed — whether it has a valid signature
        pe_vendor — signer CN (empty string if unsigned/unknown)
    """
    value = (
        entry.get("value_data") or
        entry.get("command") or
        entry.get("binary_path") or
        ""
    )

    exe_path = _extract_exe_path(value)
    if not exe_path:
        return {"pe_is_pe": False, "pe_signed": False, "pe_vendor": ""}

    sig = check_signature(exe_path)
    return {
        "pe_is_pe":  True,
        "pe_signed": sig["signed"],
        "pe_vendor": sig["publisher"],
    }
