"""api/routes/exclusions.py — /api/exclusions"""

import sys
import os

# Ensure repo root is importable (needed when FastAPI loads this module)
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.dependencies import DB_PATH
from core.exclusion_engine import (
    add_exclusion, list_exclusions, remove_exclusion, clean_expired,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class ExclusionIn(BaseModel):
    type:            str
    value:           str
    label:           Optional[str] = None
    expires_minutes: Optional[int] = None


class PauseIn(BaseModel):
    expires_minutes: int = 5


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
def get_exclusions():
    """List all exclusions (active and expired)."""
    clean_expired(DB_PATH)
    excls = list_exclusions(DB_PATH)
    return {"exclusions": excls, "count": len(excls)}


@router.post("")
def create_exclusion(body: ExclusionIn):
    """Add a new exclusion rule."""
    if body.type not in ("hash", "path", "process", "rule"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid exclusion type '{body.type}'. "
                   f"Must be one of: hash, path, process, rule",
        )
    if not body.value or not body.value.strip():
        raise HTTPException(status_code=400, detail="value must not be empty")

    new_id = add_exclusion(
        excl_type=body.type,
        value=body.value.strip(),
        label=body.label,
        expires_minutes=body.expires_minutes,
        db_path=DB_PATH,
    )
    return {"id": new_id, "status": "added"}


@router.delete("/{excl_id}")
def delete_exclusion(excl_id: int):
    """Remove an exclusion by id."""
    removed = remove_exclusion(excl_id, DB_PATH)
    if not removed:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    return {"status": "removed", "id": excl_id}


@router.post("/pause")
def pause_protection(body: PauseIn):
    """
    Temporarily pause all rule-based detection for expires_minutes (default 5).
    Hash/path/process exclusions remain active.
    """
    if body.expires_minutes < 1 or body.expires_minutes > 1440:
        raise HTTPException(
            status_code=400, detail="expires_minutes must be between 1 and 1440"
        )
    new_id = add_exclusion(
        excl_type="rule",
        value="*",
        label=f"Protection paused for {body.expires_minutes} min",
        expires_minutes=body.expires_minutes,
        db_path=DB_PATH,
    )
    return {
        "id":              new_id,
        "expires_minutes": body.expires_minutes,
        "status":          "paused",
    }
