"""
api/models.py
-------------
All Pydantic request / response models for the API.
Keeping them in one place makes it easy to version or extend.
"""

from typing import Optional, Literal, List, Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    hours:       int = Field(default=24, ge=1, le=720,
                             description="How many hours of event logs to collect")
    entry_types: List[Literal["registry", "task", "service"]] = Field(
        default=["registry", "task", "service"],
        description="Which persistence types to scan",
    )
    enrich:      bool = Field(default=True,
                              description="Run file enrichment after scanning")
    vt_api_key:  Optional[str] = Field(default=None,
                                       description="VirusTotal API key (overrides env var)")
    mb_api_key:  Optional[str] = Field(default=None,
                                       description="MalwareBazaar API key (overrides env var)")


class ScanStatusResponse(BaseModel):
    job_id:   str
    status:   Literal["pending", "running", "done", "error"]
    progress: int
    stage:    str
    started:  str
    finished: Optional[str]
    error:    Optional[str]
    summary:  dict


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

class BaselineRequest(BaseModel):
    name:       Optional[str] = Field(default=None,
                                      description="Human-readable baseline name")
    entry_type: Literal["all", "registry", "task", "service"] = Field(
        default="all",
        description="Which entry types to snapshot",
    )


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

class EnrichRequest(BaseModel):
    vt_api_key: Optional[str] = None
    mb_api_key: Optional[str] = None
