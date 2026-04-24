"""
ps_decode.py
Decode PowerShell -EncodedCommand / -enc payloads.
Import this in any collector with: from ps_decode import decode_ps_command
"""

import re
import base64


def decode_ps_command(cmdline: str) -> str | None:
    """
    Detect and decode a PowerShell -EncodedCommand/-enc payload.
    Returns decoded string, or None if no encoded command found.
    """
    if not cmdline:
        return None

    # Match -enc / -EncodedCommand / -e (shortest unambiguous prefix) followed by base64
    m = re.search(
        r'-(?:EncodedCommand|enc?)\s+([A-Za-z0-9+/=]{8,})',
        cmdline,
        re.IGNORECASE
    )
    if not m:
        return None

    b64 = m.group(1).strip()

    # Pad if needed
    missing = len(b64) % 4
    if missing:
        b64 += "=" * (4 - missing)

    try:
        raw = base64.b64decode(b64)
        # PowerShell encodes as UTF-16 LE
        decoded = raw.decode("utf-16-le")
        return decoded.strip()
    except Exception:
        try:
            # Fallback: plain UTF-8 (rare but happens)
            decoded = base64.b64decode(b64).decode("utf-8")
            return decoded.strip()
        except Exception:
            return None


def format_decoded(decoded: str, max_len: int = 200) -> str:
    """Format decoded payload for display — truncate and clean whitespace."""
    if not decoded:
        return ""
    cleaned = " ".join(decoded.split())
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "…"
    return cleaned