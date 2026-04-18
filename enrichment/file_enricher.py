"""
enrichment/file_enricher.py
---------------------------
File-level enrichment for persistence entries.
Extracts: MD5, SHA1, SHA256, file size, PE metadata (compile time,
signed/unsigned, publisher, imports), and existence check.

Dependencies:
    pip install pefile
    pip install pywin32   (already required by collectors)
"""

import os
import hashlib
import json
from datetime import datetime, timezone

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import win32api
    import win32con
    import wintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_exe_path(value: str) -> str:
    """Pull the executable path out of a raw persistence value string."""
    if not value:
        return ""
    value = value.strip()
    # quoted path
    if value.startswith('"'):
        end = value.find('"', 1)
        if end != -1:
            return value[1:end]
    # expand common env vars
    for env_var, replacement in [
        ("%windir%",      os.environ.get("WINDIR", r"C:\Windows")),
        ("%systemroot%",  os.environ.get("SYSTEMROOT", r"C:\Windows")),
        ("%programdata%", os.environ.get("PROGRAMDATA", r"C:\ProgramData")),
        ("%programfiles%",os.environ.get("PROGRAMFILES", r"C:\Program Files")),
    ]:
        value = value.replace(env_var, replacement)
        value = value.replace(env_var.upper(), replacement)
    # unquoted — take up to first space that is not inside a path separator
    parts = value.split()
    return parts[0] if parts else ""


def hash_file(path: str) -> dict:
    """Return MD5, SHA1, SHA256 hashes of a file. Returns empty dict on error."""
    result = {"md5": None, "sha1": None, "sha256": None}
    try:
        md5    = hashlib.md5()
        sha1   = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        result["md5"]    = md5.hexdigest()
        result["sha1"]   = sha1.hexdigest()
        result["sha256"] = sha256.hexdigest()
    except Exception:
        pass
    return result


def get_file_info(path: str) -> dict:
    """Return basic file metadata."""
    info = {
        "exists":        False,
        "size_bytes":    None,
        "modified_time": None,
        "created_time":  None,
    }
    try:
        stat = os.stat(path)
        info["exists"]        = True
        info["size_bytes"]    = stat.st_size
        info["modified_time"] = datetime.fromtimestamp(
            stat.st_mtime, tz=timezone.utc).isoformat()
        info["created_time"]  = datetime.fromtimestamp(
            stat.st_ctime, tz=timezone.utc).isoformat()
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# PE metadata
# ---------------------------------------------------------------------------

def get_pe_metadata(path: str) -> dict:
    """
    Extract PE metadata using pefile.
    Returns dict with: is_pe, compile_time, is_64bit, imports, exports,
                       sections, suspicious_compile_time.
    """
    meta = {
        "is_pe":                   False,
        "compile_time":            None,
        "compile_time_suspicious": False,
        "is_64bit":                None,
        "imports":                 [],
        "exports":                 [],
        "sections":                [],
        "entry_point":             None,
        "is_dll":                  False,
        "pefile_error":            None,
    }

    if not PEFILE_AVAILABLE:
        meta["pefile_error"] = "pefile not installed"
        return meta

    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
        meta["is_pe"] = True

        # Compile timestamp
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            meta["compile_time"] = compile_dt.isoformat()
            # Suspicious if: before year 2000 OR in the future
            now = datetime.now(tz=timezone.utc)
            if compile_dt.year < 2000 or compile_dt > now:
                meta["compile_time_suspicious"] = True
        except Exception:
            meta["compile_time"] = str(ts)

        # Architecture
        meta["is_64bit"] = (
            pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
        )

        # Is DLL (0x2000 = IMAGE_FILE_DLL — using raw value for pefile version compatibility)
        meta["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)

        # Entry point
        meta["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode("utf-8", errors="replace"))
                meta["imports"].append({"dll": dll_name, "functions": funcs[:20]})

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    meta["exports"].append(exp.name.decode("utf-8", errors="replace"))
            meta["exports"] = meta["exports"][:50]

        # Sections
        for section in pe.sections:
            try:
                name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            except Exception:
                name = "?"
            meta["sections"].append({
                "name":    name,
                "size":    section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 2),
            })

        pe.close()

    except pefile.PEFormatError:
        meta["is_pe"]        = False
        meta["pefile_error"] = "Not a PE file"
    except Exception as e:
        meta["pefile_error"] = str(e)

    return meta


# ---------------------------------------------------------------------------
# Digital signature check (Windows only)
# ---------------------------------------------------------------------------

def get_signature_info(path: str) -> dict:
    """
    Check if a file is digitally signed using WinVerifyTrust via ctypes.
    Returns: signed (bool), publisher (str), valid (bool)
    """
    result = {
        "signed":    False,
        "valid":     False,
        "publisher": None,
        "error":     None,
    }

    if os.name != "nt":
        result["error"] = "Not Windows"
        return result

    try:
        import ctypes
        import ctypes.wintypes
        import struct

        # Use PowerShell to get signature info — most reliable approach
        import subprocess
        ps_cmd = (
            f'Get-AuthenticodeSignature -FilePath "{path}" | '
            'Select-Object -Property Status,SignerCertificate | '
            'ConvertTo-Json'
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            status = data.get("Status", {})
            # Status value: 0 = Valid, others = invalid/unsigned
            status_val = status.get("value__", -1) if isinstance(status, dict) else -1
            result["valid"]  = (status_val == 0)
            result["signed"] = (status_val != -1 and status_val != 2)  # 2 = NotSigned

            # Only extract publisher if actually signed — prevents false attribution
            # of OS publisher to unsigned files
            if result["signed"]:
                cert = data.get("SignerCertificate")
                if cert and isinstance(cert, dict):
                    subject = cert.get("Subject", "")
                    for part in subject.split(","):
                        part = part.strip()
                        if part.startswith("CN="):
                            result["publisher"] = part[3:]
                            break
    except Exception as e:
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# High-entropy section detector (packer / obfuscation indicator)
# ---------------------------------------------------------------------------

def has_high_entropy_sections(pe_meta: dict, threshold: float = 7.0) -> bool:
    """Return True if any PE section has entropy above threshold (packed/encrypted)."""
    for section in pe_meta.get("sections", []):
        if section.get("entropy", 0) >= threshold:
            return True
    return False


# ---------------------------------------------------------------------------
# Main enricher class
# ---------------------------------------------------------------------------

class FileEnricher:
    """
    Enriches a persistence entry with file-level intelligence.
    Call enrich(entry) where entry is a dict with a 'value_data',
    'binary_path', or 'command' field containing the executable path.
    """

    def enrich(self, entry: dict, entry_type: str = "registry") -> dict:
        """
        Returns an enrichment dict to be stored in the DB.
        entry_type: 'registry', 'task', or 'service'
        """
        # Extract raw path based on entry type
        if entry_type == "registry":
            raw = entry.get("value_data", "")
        elif entry_type == "task":
            raw = entry.get("command", "") + " " + entry.get("arguments", "")
        elif entry_type == "service":
            raw = entry.get("binary_path", "")
        else:
            raw = ""

        exe_path = _extract_exe_path(raw)

        enrichment = {
            "exe_path":      exe_path,
            "enriched_at":   datetime.now(tz=timezone.utc).isoformat(),
            "file_info":     {},
            "hashes":        {},
            "pe_metadata":   {},
            "signature":     {},
            "risk_indicators": [],
        }

        if not exe_path:
            enrichment["error"] = "Could not extract executable path"
            return enrichment

        # File existence + metadata
        file_info = get_file_info(exe_path)
        enrichment["file_info"] = file_info

        if not file_info["exists"]:
            enrichment["risk_indicators"].append({
                "type":        "file_not_found",
                "description": "Executable does not exist on disk — deleted after persistence install",
                "severity":    "high",
            })
            return enrichment

        # Hashes
        enrichment["hashes"] = hash_file(exe_path)

        # PE metadata
        pe_meta = get_pe_metadata(exe_path)
        enrichment["pe_metadata"] = pe_meta

        # Signature
        sig = get_signature_info(exe_path)
        enrichment["signature"] = sig

        # --- Risk indicators ---

        # Unsigned binary
        if not sig.get("signed") and pe_meta.get("is_pe"):
            enrichment["risk_indicators"].append({
                "type":        "unsigned_binary",
                "description": "PE file is not digitally signed",
                "severity":    "high",
            })

        # Invalid signature (signed but tampered)
        if sig.get("signed") and not sig.get("valid"):
            enrichment["risk_indicators"].append({
                "type":        "invalid_signature",
                "description": "File has a signature but it failed validation (tampered?)",
                "severity":    "critical",
            })

        # Suspicious compile timestamp
        if pe_meta.get("compile_time_suspicious"):
            enrichment["risk_indicators"].append({
                "type":        "suspicious_compile_time",
                "description": "PE compile timestamp is in the future or before year 2000 — timestomping indicator",
                "severity":    "high",
            })

        # High entropy sections (packed/encrypted)
        if has_high_entropy_sections(pe_meta):
            enrichment["risk_indicators"].append({
                "type":        "high_entropy_sections",
                "description": "PE has high-entropy sections — possible packing or encryption",
                "severity":    "medium",
            })

        # Not a PE but has .exe extension
        ext = os.path.splitext(exe_path)[1].lower()
        if ext in (".exe", ".dll", ".sys") and not pe_meta.get("is_pe"):
            enrichment["risk_indicators"].append({
                "type":        "fake_extension",
                "description": f"File has {ext} extension but is not a valid PE — possible disguise",
                "severity":    "critical",
            })

        # Small file size (< 10KB) — dropper/stub indicator
        size = file_info.get("size_bytes", 0) or 0
        if pe_meta.get("is_pe") and 0 < size < 10240:
            enrichment["risk_indicators"].append({
                "type":        "tiny_executable",
                "description": f"PE is only {size} bytes — may be a dropper stub",
                "severity":    "medium",
            })

        return enrichment