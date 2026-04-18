"""
enrichment/threat_intel.py
--------------------------
Threat intelligence lookups for file hashes.
Supports: VirusTotal (v3 API), MalwareBazaar (no key needed).

Usage:
    Set environment variable: VT_API_KEY=your_key_here
    Or pass api_key= directly to VirusTotalClient.

Rate limits:
    VT free tier: 4 requests/minute, 500/day
    MalwareBazaar: no limit for hash lookups
"""

import os
import json
import time
import hashlib
import sqlite3
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode


# ---------------------------------------------------------------------------
# Simple in-DB cache to avoid burning API quota on repeated lookups
# ---------------------------------------------------------------------------

class LookupCache:
    """
    SQLite-backed cache for threat intel results.
    Stores results keyed by sha256 hash, with a configurable TTL.
    """

    def __init__(self, db_path: str = "reghunt.db", ttl_hours: int = 24):
        self.db_path  = db_path
        self.ttl_hours = ttl_hours
        self._init_table()

    def _init_table(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                sha256      TEXT PRIMARY KEY,
                source      TEXT NOT NULL,
                result_json TEXT,
                cached_at   TEXT
            )
        """)
        conn.commit()
        conn.close()

    def get(self, sha256: str, source: str) -> dict | None:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT result_json, cached_at FROM threat_intel_cache "
                "WHERE sha256=? AND source=?",
                (sha256, source),
            ).fetchone()
            if not row:
                return None
            cached_at = datetime.fromisoformat(row["cached_at"])
            if datetime.now(tz=timezone.utc) - cached_at > timedelta(hours=self.ttl_hours):
                return None  # expired
            return json.loads(row["result_json"])
        finally:
            conn.close()

    def set(self, sha256: str, source: str, result: dict):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT OR REPLACE INTO threat_intel_cache
                    (sha256, source, result_json, cached_at)
                VALUES (?, ?, ?, ?)
            """, (sha256, source, json.dumps(result),
                  datetime.now(tz=timezone.utc).isoformat()))
            conn.commit()
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# VirusTotal v3 client
# ---------------------------------------------------------------------------

class VirusTotalClient:
    BASE_URL    = "https://www.virustotal.com/api/v3"
    MIN_DELAY   = 16  # seconds between requests (free tier: 4/min)

    def __init__(self, api_key: str = None, db_path: str = "reghunt.db"):
        self.api_key    = api_key or os.environ.get("VT_API_KEY", "")
        self.cache      = LookupCache(db_path)
        self._last_call = 0.0

    def _rate_limit(self):
        elapsed = time.time() - self._last_call
        if elapsed < self.MIN_DELAY:
            time.sleep(self.MIN_DELAY - elapsed)
        self._last_call = time.time()

    def _get(self, endpoint: str) -> dict:
        if not self.api_key:
            return {"error": "No VT API key configured"}
        self._rate_limit()
        url = self.BASE_URL + endpoint
        req = Request(url, headers={"x-apikey": self.api_key})
        try:
            with urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            if e.code == 404:
                return {"not_found": True}
            if e.code == 429:
                return {"error": "VT rate limit hit — slow down"}
            return {"error": f"HTTP {e.code}"}
        except URLError as e:
            return {"error": str(e)}

    def lookup_hash(self, sha256: str) -> dict:
        """
        Look up a file hash on VirusTotal.
        Returns a normalised result dict.
        """
        if not sha256:
            return {"error": "No hash provided"}

        # Check cache first
        cached = self.cache.get(sha256, "virustotal")
        if cached:
            cached["_from_cache"] = True
            return cached

        raw = self._get(f"/files/{sha256}")

        if raw.get("not_found"):
            result = {
                "found":          False,
                "sha256":         sha256,
                "detection_ratio": "0/0",
                "malicious":      0,
                "suspicious":     0,
                "undetected":     0,
                "total":          0,
                "names":          [],
                "tags":           [],
                "first_seen":     None,
                "last_seen":      None,
                "vt_link":        f"https://www.virustotal.com/gui/file/{sha256}",
            }
            self.cache.set(sha256, "virustotal", result)
            return result

        if "error" in raw:
            return raw

        try:
            attrs = raw["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            mal   = stats.get("malicious", 0)
            sus   = stats.get("suspicious", 0)
            und   = stats.get("undetected", 0)
            total = mal + sus + und + stats.get("harmless", 0) + stats.get("failure", 0)

            result = {
                "found":           True,
                "sha256":          sha256,
                "detection_ratio": f"{mal}/{total}",
                "malicious":       mal,
                "suspicious":      sus,
                "undetected":      und,
                "total":           total,
                "names":           attrs.get("names", [])[:5],
                "tags":            attrs.get("tags", []),
                "first_seen":      attrs.get("first_submission_date"),
                "last_seen":       attrs.get("last_analysis_date"),
                "vt_link":         f"https://www.virustotal.com/gui/file/{sha256}",
                "threat_label":    attrs.get("popular_threat_classification", {})
                                       .get("suggested_threat_label", None),
            }
        except (KeyError, TypeError) as e:
            return {"error": f"Unexpected VT response: {e}"}

        self.cache.set(sha256, "virustotal", result)
        return result


# ---------------------------------------------------------------------------
# MalwareBazaar client (no API key required)
# ---------------------------------------------------------------------------

class MalwareBazaarClient:
    API_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, db_path: str = "reghunt.db", api_key: str = None):
        self.cache   = LookupCache(db_path, ttl_hours=48)
        self.api_key = api_key or os.environ.get("MB_API_KEY", "")

    def lookup_hash(self, sha256: str) -> dict:
        """
        Query MalwareBazaar for a SHA256 hash.
        Returns normalised result dict.
        """
        if not sha256:
            return {"error": "No hash provided"}

        cached = self.cache.get(sha256, "malwarebazaar")
        if cached:
            cached["_from_cache"] = True
            return cached

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        payload = urlencode({"query": "get_info", "hash": sha256}).encode()
        req = Request(self.API_URL, data=payload, headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                raw = json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

        if raw.get("query_status") == "hash_not_found":
            result = {
                "found":      False,
                "sha256":     sha256,
                "malware":    False,
                "tags":       [],
                "mb_link":    f"https://bazaar.abuse.ch/sample/{sha256}/",
            }
            self.cache.set(sha256, "malwarebazaar", result)
            return result

        if raw.get("query_status") != "ok":
            return {"error": raw.get("query_status", "Unknown error")}

        try:
            data   = raw["data"][0]
            result = {
                "found":        True,
                "sha256":       sha256,
                "malware":      True,
                "file_name":    data.get("file_name"),
                "file_type":    data.get("file_type"),
                "mime_type":    data.get("mime_type"),
                "tags":         data.get("tags") or [],
                "first_seen":   data.get("first_seen"),
                "last_seen":    data.get("last_seen"),
                "reporter":     data.get("reporter"),
                "signature":    data.get("signature"),
                "mb_link":      f"https://bazaar.abuse.ch/sample/{sha256}/",
            }
        except (KeyError, IndexError, TypeError) as e:
            return {"error": f"Unexpected MB response: {e}"}

        self.cache.set(sha256, "malwarebazaar", result)
        return result


# ---------------------------------------------------------------------------
# Combined threat intel runner
# ---------------------------------------------------------------------------

class ThreatIntelEnricher:
    """
    Runs all threat intel lookups for a given set of hashes.
    Combines VT + MalwareBazaar results into a single intel dict.
    """

    def __init__(self, vt_api_key: str = None, mb_api_key: str = None,
                 db_path: str = "reghunt.db"):
        self.vt = VirusTotalClient(api_key=vt_api_key, db_path=db_path)
        self.mb = MalwareBazaarClient(
            db_path=db_path,
            api_key=mb_api_key or os.environ.get("MB_API_KEY", ""),
        )

    def enrich(self, hashes: dict) -> dict:
        """
        hashes: dict with keys md5, sha1, sha256
        Returns combined intel dict.
        """
        sha256 = hashes.get("sha256")
        result = {
            "sha256":          sha256,
            "virustotal":      None,
            "malwarebazaar":   None,
            "verdict":         "unknown",
            "risk_indicators": [],
        }

        if not sha256:
            result["verdict"] = "no_hash"
            return result

        # MalwareBazaar (no rate limit — always run)
        mb_result = self.mb.lookup_hash(sha256)
        result["malwarebazaar"] = mb_result

        if mb_result.get("malware"):
            result["risk_indicators"].append({
                "type":        "malwarebazaar_hit",
                "description": f"Hash found in MalwareBazaar — signature: {mb_result.get('signature', 'unknown')}",
                "severity":    "critical",
                "link":        mb_result.get("mb_link"),
            })

        # VirusTotal (rate-limited — only if key configured)
        if self.vt.api_key:
            vt_result = self.vt.lookup_hash(sha256)
            result["virustotal"] = vt_result

            if vt_result.get("found"):
                mal   = vt_result.get("malicious", 0)
                sus   = vt_result.get("suspicious", 0)
                total = vt_result.get("total", 0)

                if mal >= 5:
                    result["risk_indicators"].append({
                        "type":        "vt_malicious",
                        "description": f"VirusTotal: {mal}/{total} engines flagged as malicious",
                        "severity":    "critical",
                        "link":        vt_result.get("vt_link"),
                    })
                elif mal >= 1 or sus >= 3:
                    result["risk_indicators"].append({
                        "type":        "vt_suspicious",
                        "description": f"VirusTotal: {mal} malicious, {sus} suspicious out of {total}",
                        "severity":    "high",
                        "link":        vt_result.get("vt_link"),
                    })
        else:
            result["virustotal"] = {"error": "No VT API key — set VT_API_KEY env var"}

        # Overall verdict
        indicators = result["risk_indicators"]
        if any(i["severity"] == "critical" for i in indicators):
            result["verdict"] = "malicious"
        elif any(i["severity"] == "high" for i in indicators):
            result["verdict"] = "suspicious"
        elif result["malwarebazaar"] and result["malwarebazaar"].get("found") is False:
            if result["virustotal"] and result["virustotal"].get("malicious", 0) == 0:
                result["verdict"] = "clean"
        else:
            result["verdict"] = "unknown"

        return result