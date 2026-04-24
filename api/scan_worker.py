"""
api/scan_worker.py
Full scan pipeline: collect → sysmon/4688 events → build chains → threat score.
No enrichment module. Everything runs from the collectors and threat_scorer directly.
"""

import os
import sys
import asyncio
import uuid
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from api.models import ScanRequest
from api.dependencies import DB_PATH

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── Job state ──────────────────────────────────────────────────────────────

class ScanJob:
    __slots__ = (
        "job_id", "status", "progress", "stage",
        "started", "finished", "error", "summary",
    )

    def __init__(self, job_id: str):
        self.job_id   = job_id
        self.status   = "pending"
        self.progress = 0
        self.stage    = "Queued"
        self.started  = datetime.now(tz=timezone.utc).isoformat()
        self.finished: Optional[str] = None
        self.error:    Optional[str] = None
        self.summary:  dict          = {}

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


_scan_jobs:      dict[str, ScanJob] = {}
_current_job_id: Optional[str]      = None


def get_job(job_id: str) -> Optional[ScanJob]:
    return _scan_jobs.get(job_id)

def get_latest_job() -> Optional[ScanJob]:
    if not _scan_jobs:
        return None
    return list(_scan_jobs.values())[-1]

def get_all_jobs() -> list[ScanJob]:
    return list(_scan_jobs.values())

def is_scan_running() -> bool:
    return (
        _current_job_id is not None and
        _scan_jobs.get(_current_job_id) is not None and
        _scan_jobs[_current_job_id].status == "running"
    )

def create_job() -> ScanJob:
    job_id = str(uuid.uuid4())
    job = ScanJob(job_id)
    _scan_jobs[job_id] = job
    return job


# ── Helpers ────────────────────────────────────────────────────────────────

def _run_threat_scorer(db_path: str) -> int:
    try:
        from threat_scorer import score_all
        return score_all(verbose=False)
    except Exception as e:
        print(f"[scan_worker] threat_scorer failed: {e}")
        return 0


def _get_new_entry_count(db_path: str) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        bl = conn.execute(
            "SELECT id FROM baselines ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not bl:
            return {"registry": 0, "task": 0, "service": 0, "total": 0}

        bl_id = bl["id"]
        counts = {}
        for et, table in [
            ("registry", "registry_entries"),
            ("task",     "task_entries"),
            ("service",  "service_entries"),
        ]:
            row = conn.execute(f"""
                SELECT COUNT(*) as c FROM {table} t
                WHERE t.severity IN ('critical','high')
                AND NOT EXISTS (
                    SELECT 1 FROM baseline_entries be
                    WHERE be.baseline_id=? AND be.entry_type=? AND be.hash_id=t.hash_id
                )
            """, (bl_id, et)).fetchone()
            counts[et] = row["c"] if row else 0
        counts["total"] = sum(counts.values())
        return counts
    finally:
        conn.close()


# ── Main worker ────────────────────────────────────────────────────────────

async def run_scan(job: ScanJob, request: ScanRequest):
    global _current_job_id
    job.status      = "running"
    _current_job_id = job.job_id

    def _update(stage: str, progress: int):
        job.stage    = stage
        job.progress = progress

    def _collect() -> dict:
        summary = {
            "registry":       0,
            "tasks":          0,
            "services":       0,
            "sysmon_events":  0,
            "process_events": 0,
            "chains_built":   0,
            "scored":         0,
            "new_entries":    {},
            "new_total":      0,
        }

        hours = getattr(request, "hours", 24)
        types = getattr(request, "entry_types", ["registry", "task", "service"])

        # ── 1. Registry ──────────────────────────────────────────────────
        if "registry" in types:
            _update("Scanning registry run keys...", 5)
            from collector.registry_collector import RegistryCollector
            rc = RegistryCollector(db_path=DB_PATH, collection_hours=hours)
            entries = rc.collect_registry()
            summary["registry"] = len(entries)

            _update("Collecting Sysmon events...", 12)
            summary["sysmon_events"] += rc.collect_sysmon_events()

            _update("Collecting 4688 process events...", 18)
            summary["process_events"] += rc.collect_process_events()

            _update("Building registry attack chains...", 24)
            for e in entries:
                if e.get("severity") in ("high", "critical"):
                    try:
                        rc.build_attack_chain(e["id"])
                        summary["chains_built"] += 1
                    except Exception:
                        pass
            rc.close()

        # ── 2. Scheduled tasks ───────────────────────────────────────────
        if "task" in types:
            _update("Scanning scheduled tasks...", 32)
            from collector.task_collector import TaskCollector
            tc = TaskCollector(db_path=DB_PATH, collection_hours=hours)
            task_entries = tc.collect_tasks()
            summary["tasks"] = len(task_entries)

            _update("Collecting task creation events (4698)...", 40)
            tc.collect_task_events()

            _update("Building task attack chains...", 46)
            for e in task_entries:
                if e.get("severity") in ("high", "critical"):
                    try:
                        tc.build_attack_chain(e["id"])
                        summary["chains_built"] += 1
                    except Exception:
                        pass
            tc.close()

        # ── 3. Services ──────────────────────────────────────────────────
        if "service" in types:
            _update("Scanning Windows services...", 54)
            from collector.service_collector import ServiceCollector
            sc = ServiceCollector(db_path=DB_PATH, collection_hours=hours)
            svc_entries = sc.collect_services()
            summary["services"] = len(svc_entries)

            _update("Collecting service install events (7045)...", 62)
            sc.collect_service_events()

            _update("Building service attack chains...", 68)
            for e in svc_entries:
                if e.get("severity") in ("high", "critical"):
                    try:
                        sc.build_attack_chain(e["id"])
                        summary["chains_built"] += 1
                    except Exception:
                        pass
            sc.close()

        # ── 4. Threat scoring ────────────────────────────────────────────
        _update("Running threat scorer...", 80)
        summary["scored"] = _run_threat_scorer(DB_PATH)

        # ── 5. Diff vs baseline ──────────────────────────────────────────
        _update("Calculating new entries since baseline...", 92)
        summary["new_entries"] = _get_new_entry_count(DB_PATH)
        summary["new_total"]   = summary["new_entries"].pop("total", 0)

        return summary

    try:
        loop    = asyncio.get_event_loop()
        summary = await loop.run_in_executor(None, _collect)
        job.summary  = summary
        job.status   = "done"
        job.progress = 100
        job.stage    = "Complete"
    except Exception as exc:
        job.status = "error"
        job.error  = str(exc)
    finally:
        job.finished    = datetime.now(tz=timezone.utc).isoformat()
        _current_job_id = None