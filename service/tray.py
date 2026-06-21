"""
tray.py
=======
Persistence Hunter system tray icon.

- Green  → protected, no threats
- Amber  → medium/high alerts pending review
- Red    → critical threat, action required
- Grey   → service error or stopped
- Animated pulse while scanning

Requirements:
    pip install pystray pillow requests
"""

from __future__ import annotations

import os
import sys
import time
import threading
import subprocess
import webbrowser
from typing import Optional
from PIL import Image, ImageDraw
import pystray
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_BASE    = "http://127.0.0.1:8000"
POLL_SEC    = 10        # How often to check status (seconds)
APP_NAME    = "Persistence Hunter"

# Dark navy + cyan theme colors (match the UI)
COLORS = {
    "clean":    "#22c55e",   # green
    "warning":  "#f59e0b",   # amber
    "danger":   "#ef4444",   # red
    "error":    "#64748b",   # slate/grey
    "scanning": "#06b6d4",   # cyan
    "bg":       "#0f1117",   # dark navy (icon background)
}

# ---------------------------------------------------------------------------
# Icon generation — draw a shield in PIL, no external image files needed
# ---------------------------------------------------------------------------

def _draw_shield(color: str, size: int = 64) -> Image.Image:
    """
    Draw a filled shield icon in the given hex color.
    Returns a PIL Image with transparent background.
    """
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield outline points (normalised 0-1, scaled to size)
    def pt(x: float, y: float):
        return (int(x * size), int(y * size))

    shield = [
        pt(0.5,  0.05),   # top center
        pt(0.95, 0.20),   # top right
        pt(0.95, 0.55),   # right middle
        pt(0.5,  0.97),   # bottom point
        pt(0.05, 0.55),   # left middle
        pt(0.05, 0.20),   # top left
    ]

    # Parse hex color
    c = color.lstrip("#")
    r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)

    draw.polygon(shield, fill=(r, g, b, 255))
    return img


def _draw_pulse(color: str, frame: int, size: int = 64) -> Image.Image:
    """Animate the shield with a pulsing opacity for the scanning state."""
    alpha = int(180 + 75 * abs((frame % 20) - 10) / 10)
    img   = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw  = ImageDraw.Draw(img)

    def pt(x: float, y: float):
        return (int(x * size), int(y * size))

    shield = [
        pt(0.5,  0.05),
        pt(0.95, 0.20),
        pt(0.95, 0.55),
        pt(0.5,  0.97),
        pt(0.05, 0.55),
        pt(0.05, 0.20),
    ]
    c = color.lstrip("#")
    r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
    draw.polygon(shield, fill=(r, g, b, alpha))
    return img


# ---------------------------------------------------------------------------
# Status polling — calls the local API
# ---------------------------------------------------------------------------

class StatusPoller:
    """Polls the API every POLL_SEC and caches the current status."""

    def __init__(self):
        self.status     = "error"
        self.summary    = "Connecting..."
        self.counts     = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        self.scanning   = False
        self._lock      = threading.Lock()

    def poll(self):
        try:
            resp = requests.get(f"{API_BASE}/api/status", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                with self._lock:
                    self.status   = data.get("status", "clean")
                    self.summary  = data.get("status_message", "")
                    self.counts   = data.get("counts", self.counts)
                    self.scanning = data.get("scanning", False)
        except Exception:
            with self._lock:
                self.status  = "error"
                self.summary = "Service unavailable"

    def start(self):
        def _loop():
            while True:
                self.poll()
                time.sleep(POLL_SEC)
        t = threading.Thread(target=_loop, daemon=True)
        t.start()

    @property
    def icon_color(self) -> str:
        if self.scanning:
            return COLORS["scanning"]
        return {
            "clean":   COLORS["clean"],
            "notice":  COLORS["warning"],
            "warning": COLORS["warning"],
            "danger":  COLORS["danger"],
        }.get(self.status, COLORS["error"])

    @property
    def tooltip(self) -> str:
        if self.status == "error":
            return f"{APP_NAME} — Service unavailable"
        c = self.counts
        parts = []
        if c["critical"]: parts.append(f"{c['critical']} critical")
        if c["high"]:     parts.append(f"{c['high']} high")
        if c["medium"]:   parts.append(f"{c['medium']} medium")
        if parts:
            return f"{APP_NAME} — {', '.join(parts)}"
        return f"{APP_NAME} — Protected"


# ---------------------------------------------------------------------------
# Tray app
# ---------------------------------------------------------------------------

class TrayApp:
    def __init__(self):
        self.poller       = StatusPoller()
        self._icon: Optional[pystray.Icon] = None
        self._frame       = 0
        self._prev_status = None

    # ------------------------------------------------------------------
    # Menu
    # ------------------------------------------------------------------

    def _build_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem("Open Dashboard",     self._on_open,   default=True),
            pystray.MenuItem("Scan Now",           self._on_scan),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Pause Protection",   self._on_pause),
            pystray.MenuItem("Settings",           self._on_settings),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("About",              self._on_about),
            pystray.MenuItem("Quit",               self._on_quit),
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_open(self, icon=None, item=None):
        """Open the main Tauri app window (or fallback to browser)."""
        tauri_exe = os.path.join(BASE_DIR, "Persistence Hunter.exe")
        if os.path.exists(tauri_exe):
            subprocess.Popen([tauri_exe])
        else:
            webbrowser.open("http://127.0.0.1:8000")

    def _on_scan(self, icon=None, item=None):
        """Trigger a full scan via the API."""
        try:
            requests.post(f"{API_BASE}/api/scan", timeout=3)
        except Exception:
            pass

    def _on_pause(self, icon=None, item=None):
        """Pause real-time protection for 5 minutes."""
        try:
            requests.post(f"{API_BASE}/api/protection/pause",
                          json={"minutes": 5}, timeout=3)
        except Exception:
            pass

    def _on_settings(self, icon=None, item=None):
        self._on_open()   # open app, it will land on settings if flagged

    def _on_about(self, icon=None, item=None):
        webbrowser.open("https://github.com/JimmyDevvvvv/Persistence-Hunter")

    def _on_quit(self, icon=None, item=None):
        if self._icon:
            self._icon.stop()

    # ------------------------------------------------------------------
    # Icon update loop
    # ------------------------------------------------------------------

    def _update_icon(self):
        """Called periodically to refresh the tray icon color."""
        while True:
            self._frame += 1
            color = self.poller.icon_color

            if self.poller.scanning:
                img = _draw_pulse(color, self._frame)
            else:
                img = _draw_shield(color)

            if self._icon:
                self._icon.icon   = img
                self._icon.title  = self.poller.tooltip

            time.sleep(0.1 if self.poller.scanning else 1.0)

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self):
        # Initial icon
        img = _draw_shield(COLORS["error"])

        self._icon = pystray.Icon(
            name    = APP_NAME,
            icon    = img,
            title   = f"{APP_NAME} — Starting...",
            menu    = self._build_menu(),
        )

        # Start polling and icon update in background
        self.poller.start()
        t = threading.Thread(target=self._update_icon, daemon=True)
        t.start()

        # Block here — pystray.run() owns this thread
        self._icon.run()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = TrayApp()
    app.run()
