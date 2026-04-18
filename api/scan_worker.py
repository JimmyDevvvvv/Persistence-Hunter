"""
api/scan_worker.py
------------------
Scan job state management and the background worker that runs
collectors + enrichment without blocking the event loop.
"""

import os
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

from api.models import ScanRequest
from api.dependencies import DB_PATH


# ---------------------------------------------------------------------------
# Job state
# ---------------------------------------------------------------------------

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


# In-memory job registry — keyed by job_id
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


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

async def run_scan(job: ScanJob, request: ScanRequest):
    global _current_job_id
    job.status     = "running"
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
        }

        if "registry" in request.entry_types:
            _update("Scanning registry...", 5)
            from collector.registry_collector import RegistryCollector
            rc = RegistryCollector(db_path=DB_PATH,
                                   collection_hours=request.hours)
            entries = rc.collect_registry()
            summary["registry"] = len(entries)

            _update("Collecting Sysmon events...", 20)
            summary["sysmon_events"] += rc.collect_sysmon_events()

            _update("Collecting 4688 events...", 35)
            summary["process_events"] += rc.collect_process_events()
            rc.close()

        if "task" in request.entry_types:
            _update("Scanning scheduled tasks...", 45)
            from collector.task_collector import TaskCollector
            tc = TaskCollector(db_path=DB_PATH,
                               collection_hours=request.hours)
            summary["tasks"] = len(tc.collect_tasks())
            tc.collect_task_events()
            tc.close()

        if "service" in request.entry_types:
            _update("Scanning services...", 60)
            from collector.service_collector import ServiceCollector
            sc = ServiceCollector(db_path=DB_PATH,
                                  collection_hours=request.hours)
            summary["services"] = len(sc.collect_services())
            sc.collect_service_events()
            sc.close()

        if request.enrich:
            _update("Enriching high/critical entries...", 75)
            from enrichment.enrichment_manager import EnrichmentManager
            mgr = EnrichmentManager(
                db_path=DB_PATH,
                vt_api_key=request.vt_api_key or os.environ.get("VT_API_KEY"),
                mb_api_key=request.mb_api_key or os.environ.get("MB_API_KEY"),
            )
            mgr.enrich_all(
                only_high_critical=True,
                run_intel=bool(
                    request.vt_api_key or os.environ.get("VT_API_KEY")
                ),
            )

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
