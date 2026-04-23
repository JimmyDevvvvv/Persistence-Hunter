# api/routes/scores.py
import json
from fastapi import APIRouter, HTTPException
from ..dependencies import get_db, row_to_dict

router = APIRouter()


def _parse_score_row(d: dict) -> dict:
    """Unpack the three JSON blobs into named fields."""
    mapping = {
        "breakdown_json": "breakdown",
        "apt_json":       "apt_matches",
        "risk_json":      "risk_indicators",
    }
    for raw_key, nice_key in mapping.items():
        try:
            d[nice_key] = json.loads(d.pop(raw_key) or "[]")
        except Exception:
            d[nice_key] = []
    return d


@router.get("")
def get_all_scores():
    """Get threat scores for all entries, joined with entry data."""
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT ts.entry_type, ts.entry_id, ts.score,
                   ts.breakdown_json, ts.apt_json, ts.risk_json, ts.scored_at,
                   COALESCE(r.name, t.task_name, s.service_name, '?')        AS name,
                   COALESCE(r.severity, t.severity, s.severity, 'unknown')   AS severity,
                   COALESCE(r.value_data, t.command, s.binary_path, '')      AS value
            FROM threat_scores ts
            LEFT JOIN registry_entries r ON ts.entry_type='registry' AND ts.entry_id=r.id
            LEFT JOIN task_entries     t ON ts.entry_type='task'     AND ts.entry_id=t.id
            LEFT JOIN service_entries  s ON ts.entry_type='service'  AND ts.entry_id=s.id
            ORDER BY ts.score DESC
        """).fetchall()
        return {"scores": [_parse_score_row(row_to_dict(r)) for r in rows]}
    finally:
        conn.close()


@router.get("/{entry_type}/{entry_id}")
def get_score(entry_type: str, entry_id: int):
    """Get threat score for a specific entry."""
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT * FROM threat_scores
            WHERE entry_type = ? AND entry_id = ?
        """, (entry_type, entry_id)).fetchone()

        if not row:
            return {"score": None, "breakdown": [], "apt_matches": [], "risk_indicators": []}

        return _parse_score_row(row_to_dict(row))
    finally:
        conn.close()


@router.post("/run")
def run_scorer():
    """Trigger threat scoring for all entries."""
    try:
        from threat_scorer import score_all
        count = score_all(verbose=False)
        return {"status": "done", "scored": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))