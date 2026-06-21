"""
monitors/correlator.py
======================
EventCorrelator — stateful, time-window-based correlation of ETW events
against behavioral rules defined in rules/behavior_rules.json.

Design:
  - Rolling buffer holds events for the last window_seconds
  - Each ingest() call tries to match every rule against the current buffer
  - A rule fires at most once per window_seconds (per-rule cooldown)
  - same_process_tree filter: events with pid=0 always pass (PID unknown)

Usage:
    correlator = EventCorrelator()
    fired = correlator.ingest(event_dict)
    for rule in fired:
        print(rule["id"], rule["matched_events"])
"""
from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path


class EventCorrelator:

    def __init__(
        self,
        window_seconds: float = 30.0,
        rules_path: str | Path | None = None,
    ):
        self.window           = window_seconds
        self._buf: deque      = deque()            # (timestamp, event)
        self._ptree: dict     = {}                 # pid -> parent_pid
        self._last_fired: dict = {}                # rule_id -> float (last fire time)
        self.rules            = self._load_rules(rules_path)

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
        """True if other_pid is in the same process tree as anchor_pid."""
        if anchor_pid == 0 or other_pid == 0:
            return True     # unknown PID — can't deny, so pass
        if anchor_pid == other_pid:
            return True

        # Walk other_pid's ancestry looking for anchor_pid
        visited: set = set()
        cur = other_pid
        while cur and cur not in visited:
            visited.add(cur)
            parent = self._ptree.get(cur)
            if parent == anchor_pid:
                return True
            cur = parent

        # Walk anchor_pid's ancestry looking for other_pid
        visited = set()
        cur = anchor_pid
        while cur and cur not in visited:
            visited.add(cur)
            parent = self._ptree.get(cur)
            if parent == other_pid:
                return True
            cur = parent

        return False

    # ── Filter matching ──────────────────────────────────────────────────────

    def _matches(
        self,
        event: dict,
        filters: dict,
        anchor_pid: int | None = None,
    ) -> bool:
        path_l   = (event.get("path")   or "").lower()
        detail_l = (event.get("detail") or "").lower()

        if "path_contains" in filters:
            if not any(p.lower() in path_l for p in filters["path_contains"]):
                return False

        if "detail_contains" in filters:
            if not any(p.lower() in detail_l for p in filters["detail_contains"]):
                return False

        if filters.get("same_process_tree") and anchor_pid is not None:
            if not self._in_same_tree(anchor_pid, event.get("pid") or 0):
                return False

        return True

    # ── Rule matching ────────────────────────────────────────────────────────

    def _try_match(self, rule: dict, events: list) -> list | None:
        """
        Greedily find a set of events satisfying every condition in order.
        Returns the matched list, or None if any condition cannot be satisfied.
        The first condition's matching event becomes the anchor for
        same_process_tree checks on subsequent conditions.
        """
        conditions = rule.get("events", [])
        if not conditions:
            return None

        first = conditions[0]
        for anchor in events:
            if anchor["type"] != first["event"]:
                continue
            if not self._matches(anchor, first.get("filters", {})):
                continue

            anchor_pid = anchor.get("pid") or 0
            matched    = [anchor]

            for cond in conditions[1:]:
                hit = None
                for ev in events:
                    if ev is anchor or ev in matched:
                        continue
                    if ev["type"] != cond["event"]:
                        continue
                    if not self._matches(ev, cond.get("filters", {}), anchor_pid):
                        continue
                    hit = ev
                    break

                if hit is None:
                    break
                matched.append(hit)

            if len(matched) == len(conditions):
                return matched

        return None

    # ── Public API ───────────────────────────────────────────────────────────

    def ingest(self, event: dict) -> list:
        """
        Add event to the rolling buffer and evaluate all rules.

        Returns a list of fired rule dicts.  Each dict is a copy of the
        rule from behavior_rules.json with "matched_events" appended.

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
        fired:  list  = []

        for rule in self.rules:
            rule_id  = rule.get("id", "")
            cooldown = float(rule.get("window_seconds", self.window))

            if time.time() - self._last_fired.get(rule_id, 0.0) < cooldown:
                continue

            matched = self._try_match(rule, window_events)
            if matched is not None:
                self._last_fired[rule_id] = time.time()
                fired.append({**rule, "matched_events": matched})

        return fired
