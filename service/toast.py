"""
toast.py
========
Native Windows toast notifications for Persistence Hunter.
Severity-aware — each level has different behaviour and styling.

Requirements:
    pip install winotify

Notification behaviour by severity:
    critical → persists until dismissed, action buttons
    high     → 8 second toast, action buttons
    medium   → 4 second toast, dismiss only
    low      → silent, never shown (logged to history only)
"""

from __future__ import annotations

import threading
from typing import Callable, Optional
from winotify import Notification, audio

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

APP_NAME    = "Persistence Hunter"
APP_ID      = "PersistenceHunter"

# Duration constants (winotify uses "short" or "long")
DURATION = {
    "critical": "long",    # stays until dismissed
    "high":     "long",
    "medium":   "short",
    "low":      None,      # never shown
}

AUDIO = {
    "critical": audio.Default,
    "high":     audio.Default,
    "medium":   audio.SMS,
    "low":      None,
}

# ---------------------------------------------------------------------------
# Toast builder
# ---------------------------------------------------------------------------

def _make_toast(
    title:        str,
    body:         str,
    severity:     str,
    on_click:     Optional[Callable] = None,
    action_label: Optional[str]      = None,
    action_url:   Optional[str]      = None,
) -> Optional[Notification]:
    """
    Build a winotify Notification.
    Returns None for low severity (no notification).
    """
    duration = DURATION.get(severity)
    if duration is None:
        return None

    # Severity prefix in title
    prefix = {
        "critical": "🚨 ",
        "high":     "⚠️  ",
        "medium":   "🔍 ",
    }.get(severity, "")

    toast = Notification(
        app_id   = APP_ID,
        title    = f"{prefix}{title}",
        msg      = body,
        duration = duration,
        icon     = "",   # Tauri will handle app icon registration
    )

    snd = AUDIO.get(severity)
    if snd:
        toast.set_audio(snd, loop=False)

    if action_label and action_url:
        toast.add_actions(label=action_label, launch=action_url)

    return toast


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def notify_threat(
    entry_name: str,
    plain_reason: str,
    severity: str,
    entry_type: str = "startup program",
    on_click_url: str = "http://127.0.0.1:8000",
) -> None:
    """
    Fire a toast notification for a detected threat.
    Non-blocking — dispatched in a background thread.

    Parameters
    ----------
    entry_name    : name of the suspicious entry ("WindowsUpdater")
    plain_reason  : one plain-English reason ("It's hiding what it does")
    severity      : "critical" / "high" / "medium" / "low"
    entry_type    : "startup program" / "scheduled task" / "service"
    on_click_url  : URL opened when user clicks the notification
    """
    if severity == "low":
        return

    title = {
        "critical": f"Dangerous {entry_type} detected",
        "high":     f"Suspicious {entry_type} found",
        "medium":   f"Unusual {entry_type} found",
    }.get(severity, "New detection")

    body  = f'"{entry_name}" — {plain_reason}'

    action_label = "Review Now" if severity in ("critical", "high") else "View"

    toast = _make_toast(
        title        = title,
        body         = body,
        severity     = severity,
        action_label = action_label,
        action_url   = on_click_url,
    )

    if toast:
        threading.Thread(target=toast.show, daemon=True).start()


def notify_scan_complete(threats_found: int) -> None:
    """Notify when an on-demand scan finishes."""
    if threats_found == 0:
        toast = _make_toast(
            title    = "Scan complete",
            body     = "No threats found. Your system looks clean.",
            severity = "medium",
        )
    else:
        label = f"{threats_found} threat{'s' if threats_found > 1 else ''}"
        toast = _make_toast(
            title        = "Scan complete",
            body         = f"{label} found. Review recommended.",
            severity     = "high",
            action_label = "Review",
            action_url   = "http://127.0.0.1:8000",
        )
    if toast:
        threading.Thread(target=toast.show, daemon=True).start()


def notify_rules_updated(new_rules: int, version: str) -> None:
    """Notify when community rules are updated."""
    if new_rules == 0:
        return
    toast = _make_toast(
        title    = "Detection rules updated",
        body     = f"{new_rules} new rule{'s' if new_rules > 1 else ''} "
                   f"added in {version}.",
        severity = "medium",
    )
    if toast:
        threading.Thread(target=toast.show, daemon=True).start()


def notify_protection_paused(minutes: int) -> None:
    """Notify that protection has been paused."""
    toast = _make_toast(
        title    = "Protection paused",
        body     = f"Real-time monitoring paused for {minutes} minutes. "
                   "It will resume automatically.",
        severity = "medium",
    )
    if toast:
        threading.Thread(target=toast.show, daemon=True).start()


def notify_service_error(message: str) -> None:
    """Notify if the background service encounters an error."""
    toast = _make_toast(
        title    = "Persistence Hunter — Service error",
        body     = message,
        severity = "high",
    )
    if toast:
        threading.Thread(target=toast.show, daemon=True).start()
