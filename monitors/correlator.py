"""
monitors/correlator.py
======================
EventCorrelator — stateful, time-window-based correlation of ETW events
against behavioral rules defined in rules/behavior_rules.json.

PID attribution model
---------------------
Windows registry watchers (RegNotifyChangeKeyValue) cannot report which
process wrote a key — registry_write events always arrive with pid=0.
Rather than passing all pid=0 events through same_process_tree checks
(which would fire BEH-002 every time Discord or Steam refreshes its Run key),
the correlator uses *temporal proximity attribution*:

  1. When a registry_write or file_create has pid=0, scan the buffer for a
     process_create event whose path is in a *genuinely suspicious* location
     (AppData/Temp/Public) AND is NOT from a known-legitimate app directory.

  2. If such a process is found  → attribute, same_process_tree passes,
                                   confidence = "probable"

  3. If no such process is found → same_process_tree fails.
     This blocks false positives from Discord/Steam/Notion updating their
     own Run keys — their updaters run from known app directories (LEGIT_DIRS).

Confidence levels
-----------------
  "definitive" — both events carry non-zero PIDs in the same process tree
  "probable"   — temporal attribution (pid=0, suspicious process in window)
  "low"        — unused in current rules (future fallback)

Usage:
    correlator = EventCorrelator()
    fired = correlator.ingest(event_dict)
    for rule in fired:
        print(rule["id"], rule["confidence"], rule["matched_events"])
"""
from __future__ import annotations

import os
import re
import json
import time
from collections import deque
from pathlib import Path

# ---------------------------------------------------------------------------
# Legitimate app directories — keep in sync with core/threat_scorer.py
# LEGIT_APPDATA_DIRS.  Binaries from these directories are NOT treated as
# suspicious processes for attribution purposes (they're Squirrel updaters,
# cloud-sync clients, etc. managing their own Run keys).
# ---------------------------------------------------------------------------
_LEGIT_DIRS: set = {
    "discord", "slack", "teams", "notion", "spotify",
    "telegram desktop", "signal", "whatsapp", "skype", "zoom",
    "github desktop", "gitkraken", "sourcetree", "cursor",
    "figma", "linear", "loom", "obsidian", "logseq",
    "programs",
    "microsoft", "onedrive", "dropbox", "box", "mega",
    "google", "brave-browser", "vivaldi", "opera",
    "1password", "bitwarden",
    "parsec", "anydesk",
    # Steam and common gaming clients manage their own Run keys
    "steam", "epic games launcher", "origin", "ea desktop",
    "battle.net", "gog galaxy", "ubisoft connect",
}

_APPDATA_RE  = re.compile(
    r'\\appdata\\(?:local|roaming)\\([^\\]+)\\', re.IGNORECASE
)
_SUSP_PATHS = [r"\appdata", r"\temp", r"\users\public"]


def _appdata_dir(path: str) -> str:
    """First-level dir under AppData, lower-cased, or ''."""
    m = _APPDATA_RE.search(path)
    return m.group(1).lower() if m else ""


def _is_legit_process_path(path: str) -> bool:
    """True if path belongs to a known-legitimate app directory."""
    lo       = path.lower()
    par_dir  = os.path.basename(os.path.dirname(lo))
    app_dir  = _appdata_dir(lo)
    return par_dir in _LEGIT_DIRS or app_dir in _LEGIT_DIRS


# ===========================================================================
# EventCorrelator
# ===========================================================================

class EventCorrelator:

    def __init__(
        self,
        window_seconds: float = 30.0,
        rules_path: str | Path | None = None,
    ):
        self.window             = window_seconds
        self._buf: deque        = deque()        # (timestamp, event)
        self._ptree: dict       = {}             # pid -> parent_pid
        self._last_fired: dict  = {}             # rule_id -> float
        self.rules              = self._load_rules(rules_path)

    # ── Rule loading ────────────────────────────────────────────────────────

    def _load_rules(self, path) -> list:
        if path is None:
            path = Path(__file__).parent.parent / "rules" / "behavior_rules.json"
        try:
            with open(path, encoding="utf-8") as f:
                rules = json.load(f)
            print(f"[Correlator] Loaded {len(rules)} rule(s) from {path}")
            return rules
        except Exception as exc:
            print(f"[Correlator] Cannot load rules: {exc}")
            return []

    # ── Buffer management ────────────────────────────────────────────────────

    def _trim(self):
        cutoff = time.time() - self.window
        while self._buf and self._buf[0][0] < cutoff:
            self._buf.popleft()

    # ── Process tree ────────────────────────────────────────────────────────

    def _in_same_tree(self, anchor_pid: int, other_pid: int) -> bool:
        """True when both PIDs are known and related via parent_pid chain."""
        if anchor_pid == other_pid:
            return True
        visited: set = set()
        cur = other_pid
        while cur and cur not in visited:
            visited.add(cur)
            parent = self._ptree.get(cur)
            if parent == anchor_pid:
                return True
            cur = parent
        visited = set()
        cur = anchor_pid
        while cur and cur not in visited:
            visited.add(cur)
            parent = self._ptree.get(cur)
            if parent == other_pid:
                return True
            cur = parent
        return False

    # ── Temporal attribution ─────────────────────────────────────────────────

    def _find_suspicious_process(self, before_ts: float | None) -> dict | None:
        """
        Return the most-recent suspicious process_create in the buffer that
        occurred before *before_ts*, or None.

        A process is suspicious if:
          - its path is in a suspicious location (AppData, Temp, Public) AND
          - its path is NOT from a known-legitimate app directory (_LEGIT_DIRS).

        This correctly rejects Discord's Update.exe (in \\AppData\\Local\\Discord\\)
        while accepting unknown binaries dropped in %TEMP%.
        """
        for _, ev in reversed(list(self._buf)):
            if ev["type"] != "process_create":
                continue
            ts = ev.get("timestamp") or 0
            if before_ts is not None and ts > before_ts:
                continue
            path = (ev.get("path") or "").lower()
            if not any(p in path for p in _SUSP_PATHS):
                continue
            if _is_legit_process_path(path):
                continue      # known-legit app — skip
            return ev
        return None

    # ── Filter matching ──────────────────────────────────────────────────────

    def _matches(
        self,
        event:       dict,
        filters:     dict,
        anchor_pid:  int | None = None,
        confidence:  list | None = None,   # mutable list — caller appends levels
    ) -> bool:
        """
        Return True if *event* passes all *filters*.

        *confidence* is a mutable list; if temporal attribution is used
        (pid=0), "probable" is appended so callers can downgrade certainty.
        """
        path_l   = (event.get("path")   or "").lower()
        detail_l = (event.get("detail") or "").lower()

        if "path_contains" in filters:
            if not any(p.lower() in path_l for p in filters["path_contains"]):
                return False

        if "detail_contains" in filters:
            if not any(p.lower() in detail_l for p in filters["detail_contains"]):
                return False

        if filters.get("same_process_tree") and anchor_pid is not None:
            other_pid = event.get("pid") or 0

            if other_pid != 0 and anchor_pid != 0:
                # Both PIDs known — use definitive tree check
                if not self._in_same_tree(anchor_pid, other_pid):
                    return False
                # confidence stays "definitive"

            elif other_pid == 0:
                # PID unknown (registry_write / file_create) — temporal attribution
                before_ts = event.get("timestamp")
                suspect   = self._find_suspicious_process(before_ts)
                if suspect is None:
                    return False    # no suspicious process → block
                if confidence is not None:
                    confidence.append("probable")
            # anchor_pid == 0 and other_pid != 0 should not occur in practice
            # (anchor is always a process_create which carries a real PID).

        return True

    # ── Rule matching ────────────────────────────────────────────────────────

    def _try_match(
        self, rule: dict, events: list
    ) -> tuple[list, str] | tuple[None, None]:
        """
        Greedy search for events satisfying every condition in *rule*.

        Returns (matched_events, confidence) or (None, None).
        confidence: "definitive" | "probable"
        """
        conditions = rule.get("events", [])
        if not conditions:
            return None, None

        first = conditions[0]
        for anchor in events:
            if anchor["type"] != first["event"]:
                continue
            if not self._matches(anchor, first.get("filters", {})):
                continue

            anchor_pid   = anchor.get("pid") or 0
            matched      = [anchor]
            conf_levels: list = []

            for cond in conditions[1:]:
                hit = None
                for ev in events:
                    if ev is anchor or ev in matched:
                        continue
                    if ev["type"] != cond["event"]:
                        continue
                    c: list = []
                    if not self._matches(
                        ev, cond.get("filters", {}), anchor_pid, c
                    ):
                        continue
                    hit = ev
                    conf_levels.extend(c)
                    break

                if hit is None:
                    break
                matched.append(hit)

            if len(matched) == len(conditions):
                overall = "probable" if "probable" in conf_levels else "definitive"
                return matched, overall

        return None, None

    # ── Public API ───────────────────────────────────────────────────────────

    def ingest(self, event: dict) -> list:
        """
        Add *event* to the rolling buffer and evaluate all rules.

        Returns a list of fired rule dicts.  Each dict is a copy of the rule
        from behavior_rules.json with two extra keys:
          "matched_events" : list of the events that triggered the rule
          "confidence"     : "definitive" | "probable"

        Each rule fires at most once per its window_seconds cooldown.
        """
        now = event.get("timestamp") or time.time()

        if event["type"] == "process_create":
            pid  = event.get("pid")  or 0
            ppid = event.get("parent_pid") or 0
            if pid:
                self._ptree[pid] = ppid

        self._buf.append((now, event))
        self._trim()

        window_events = [e for _, e in self._buf]
        fired: list   = []

        for rule in self.rules:
            rule_id  = rule.get("id", "")
            cooldown = float(rule.get("window_seconds", self.window))

            if time.time() - self._last_fired.get(rule_id, 0.0) < cooldown:
                continue

            matched, confidence = self._try_match(rule, window_events)
            if matched is not None:
                self._last_fired[rule_id] = time.time()
                fired.append(
                    {**rule, "matched_events": matched, "confidence": confidence}
                )

        return fired
