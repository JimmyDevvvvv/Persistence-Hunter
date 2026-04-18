"""api/routes/baseline.py — /api/baseline and /api/diff"""

from typing import Optional, Literal
from fastapi import APIRouter, HTTPException
from api.models import BaselineRequest
from api.dependencies import DB_PATH

router = APIRouter()


def _bm():
    from enrichment.baseline import BaselineManager
    return BaselineManager(DB_PATH)


@router.get("")
def list_baselines():
    """List all stored baselines, most recent first."""
    bm        = _bm()
    baselines = bm.list_baselines()
    return {
        "baselines": baselines,
        "latest":    baselines[0] if baselines else None,
        "count":     len(baselines),
    }


@router.post("")
def create_baseline(request: BaselineRequest):
    """Snapshot all current persistence entries as a new baseline."""
    bm  = _bm()
    bid = bm.create_baseline(
        entry_type=request.entry_type,
        name=request.name,
    )
    baselines = bm.list_baselines()
    created   = next((b for b in baselines if b["id"] == bid), None)
    return {
        "message":     "Baseline created",
        "baseline_id": bid,
        "baseline":    created,
    }


@router.delete("/{baseline_id}")
def delete_baseline(baseline_id: int):
    """Delete a baseline by ID."""
    bm = _bm()
    bm.delete_baseline(baseline_id)
    return {"message": f"Baseline {baseline_id} deleted"}


@router.get("/diff")
def get_diff(
    entry_type:  Literal["all", "registry", "task", "service"] = "all",
    baseline_id: Optional[int] = None,
):
    """
    Show new and removed entries since the last (or specified) baseline.
    This is the core alert feed — run after every scan.
    """
    bm   = _bm()
    diff = bm.diff(entry_type=entry_type, baseline_id=baseline_id)
    if "error" in diff:
        raise HTTPException(status_code=404, detail=diff["error"])
    return diff
