"""api/routes/scan.py — /api/scan"""

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from api.models import ScanRequest
from api.scan_worker import (
    create_job, run_scan,
    get_job, get_latest_job, get_all_jobs,
    is_scan_running,
)

router = APIRouter()


@router.post("")
async def trigger_scan(request: ScanRequest,
                       background_tasks: BackgroundTasks):
    """
    Start a background scan.
    Pipeline: collect → sysmon/4688/4698/7045 events → build chains → threat score → diff.
    Returns job_id to poll with GET /api/scan/status.
    Only one scan can run at a time.
    """
    if is_scan_running():
        latest = get_latest_job()
        return JSONResponse(status_code=409, content={
            "error":  "A scan is already running",
            "job_id": latest.job_id if latest else None,
        })

    job = create_job()
    background_tasks.add_task(run_scan, job, request)
    return {
        "job_id":  job.job_id,
        "status":  "pending",
        "message": "Scan started — pipeline: collect → events → chains → threat score",
    }


@router.get("/status")
def get_scan_status(job_id: str = None):
    """
    Poll a scan job. Returns stage, progress %, and summary when done.
    If no job_id, returns the most recent job.
    """
    job = get_job(job_id) if job_id else get_latest_job()
    if not job:
        return {"status": "no_jobs"}
    if job_id and not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.to_dict()


@router.get("/history")
def get_scan_history():
    """List all scan jobs from this server session."""
    return {"jobs": [j.to_dict() for j in get_all_jobs()]}