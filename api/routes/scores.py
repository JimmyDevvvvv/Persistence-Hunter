# api/routes/scores.py
from fastapi import APIRouter, Depends
from ..dependencies import get_db, row_to_dict
import json

router = APIRouter()

@router.get("/scores")
def get_all_scores(db=Depends(get_db)):
    """Get threat scores for all entries, joined with entry data."""
    rows = db.execute("""
        SELECT ts.entry_type, ts.entry_id, ts.score,
               ts.breakdown_json, ts.apt_json, ts.risk_json, ts.scored_at,
               COALESCE(r.name, t.task_name, s.service_name, '?')   AS name,
               COALESCE(r.severity, t.severity, s.severity, 'unknown') AS severity,
               COALESCE(r.value_data, t.command, s.binary_path, '') AS value
        FROM threat_scores ts
        LEFT JOIN registry_entries r ON ts.entry_type='registry' AND ts.entry_id=r.id
        LEFT JOIN task_entries     t ON ts.entry_type='task'     AND ts.entry_id=t.id
        LEFT JOIN service_entries  s ON ts.entry_type='service'  AND ts.entry_id=s.id
        ORDER BY ts.score DESC
    """).fetchall()

    results = []
    for row in rows:
        d = row_to_dict(row)
        for key in ("breakdown_json", "apt_json", "risk_json"):
            try:
                d[key.replace("_json", "")] = json.loads(d.pop(key) or "[]")
            except Exception:
                d[key.replace("_json", "")] = []
        results.append(d)
    return {"scores": results}


@router.get("/scores/{entry_type}/{entry_id}")
def get_score(entry_type: str, entry_id: int, db=Depends(get_db)):
    """Get threat score for a specific entry."""
    row = db.execute("""
        SELECT * FROM threat_scores
        WHERE entry_type = ? AND entry_id = ?
    """, (entry_type, entry_id)).fetchone()

    if not row:
        return {"score": None, "breakdown": [], "apt_matches": [], "risk_indicators": []}

    d = row_to_dict(row)
    for key in ("breakdown_json", "apt_json", "risk_json"):
        field = key.replace("_json", "").replace("apt", "apt_matches").replace("risk", "risk_indicators")
        if key == "breakdown_json":
            field = "breakdown"
        try:
            d[field] = json.loads(d.pop(key) or "[]")
        except Exception:
            d[field] = []
    return d


@router.post("/scores/run")
def run_scorer(db=Depends(get_db)):
    """Trigger threat scoring for all entries."""
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    try:
        from threat_scorer import score_all
        count = score_all(verbose=False)
        return {"status": "done", "scored": count}
    except Exception as e:
        return {"status": "error", "detail": str(e)}