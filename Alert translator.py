"""
alert_translator.py
===================
Translates technical Persistence-Hunter findings into plain English
for the consumer-facing interface.

Analysts see raw scores, MITRE tags, and chain details.
Regular users see: what happened, why it's bad, what to do.

Usage:
    from alert_translator import translate_alert, severity_from_score

    result   = score_entry(entry, chain, enrichment, sigs)
    alert    = translate_alert(entry, result)
    # alert["title"]          → "A suspicious startup program was detected"
    # alert["plain_reasons"]  → ["It's hiding what it does using scrambled code"]
    # alert["recommendation"] → "We recommend blocking this."
    # alert["severity"]       → "critical"
    # alert["action_options"] → ["Block", "Trust", "Learn more"]
"""

from __future__ import annotations

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Plain English translations for each scoring factor
# ---------------------------------------------------------------------------

FACTOR_PLAIN_ENGLISH: Dict[str, str] = {
    # Execution / obfuscation
    "encoded_command": (
        "It's hiding what it's doing using scrambled code. "
        "Legitimate programs almost never do this."
    ),
    "download_cradle": (
        "It's downloading additional files from the internet "
        "without your knowledge."
    ),
    "hidden_window": (
        "It's set to run completely invisibly in the background, "
        "with no window or taskbar icon."
    ),
    "bypass_execution_policy": (
        "It's bypassing a Windows security restriction that's meant "
        "to prevent unauthorised scripts from running."
    ),
    "no_profile_flag": (
        "It's running in a way specifically designed to avoid "
        "certain security monitoring tools."
    ),

    # Paths
    "temp_path": (
        "The program file is stored in a temporary folder. "
        "Legitimate installed software is never stored there."
    ),
    "appdata_path": (
        "The program is stored in your personal data folder instead of "
        "a proper install location — a common trick used by malware."
    ),
    "suspicious_path": (
        "The program is running from an unusual location that "
        "legitimate software doesn't use."
    ),

    # Credential / session theft
    "browser_db_access": (
        "It's accessing your browser's stored passwords and session data. "
        "This is the primary sign of an info stealer — software designed "
        "to steal your accounts."
    ),
    "dpapi_abuse": (
        "It's using a Windows feature to decrypt your stored credentials. "
        "This is how info stealers like Lumma and Redline steal "
        "your saved passwords."
    ),
    "credential_path_reference": (
        "It references the location where your browser stores passwords "
        "and login cookies."
    ),
    "wallet_access": (
        "It's accessing your cryptocurrency wallet files. "
        "This is a sign of a crypto stealer."
    ),
    "post_access_exfil": (
        "After accessing your credentials, it appears to be "
        "sending data to an external server."
    ),

    # Chain / origin
    "written_by_powershell": (
        "A scripting tool (PowerShell) added this startup entry, "
        "not a normal installer. Legitimate software installs itself."
    ),
    "written_by_lolbin": (
        "A built-in Windows tool was used to create this startup entry "
        "— a technique used by attackers to avoid detection."
    ),
    "written_by_script_engine": (
        "A script (Python, JavaScript, etc.) created this startup entry "
        "rather than a normal installer."
    ),
    "chain_contains_malicious": (
        "The program that created this startup entry was itself flagged "
        "as suspicious — suggesting a multi-stage attack."
    ),
    "chain_contains_lolbin": (
        "Built-in Windows tools were involved in creating this entry, "
        "which is a common attacker technique."
    ),
    "deep_chain": (
        "This went through many programs before reaching your startup — "
        "suggesting a sophisticated, multi-step attack."
    ),

    # Name / identity
    "masquerade_name": (
        "This program is pretending to be a Windows system file "
        "to avoid detection."
    ),
    "stealer_name_pattern": (
        "The program has a generic name (like 'update' or 'helper') "
        "combined with a suspicious location — a pattern used by "
        "info stealers."
    ),
    "ifeo_key": (
        "This modifies how Windows launches accessibility tools, "
        "which can give an attacker administrator-level access "
        "from the login screen."
    ),
    "winlogon_key": (
        "This runs every time any user logs into Windows — "
        "a persistence method used by serious malware."
    ),

    # Threat intel
    "vt_detections_high": (
        "Multiple antivirus engines have confirmed this file is malicious."
    ),
    "vt_detections_low": (
        "At least one antivirus engine has flagged this file as malicious."
    ),
    "malwarebazaar_hit": (
        "This exact file has been identified as malware in a global "
        "threat database."
    ),
    "unsigned_binary": (
        "This program is not digitally signed. All legitimate software "
        "from reputable companies is signed."
    ),

    # APT
    "apt_signature_match": (
        "This matches techniques used by known hacker groups or "
        "criminal malware operations."
    ),
}

# ---------------------------------------------------------------------------
# Severity thresholds and user-facing messages
# ---------------------------------------------------------------------------

SEVERITY_THRESHOLDS = [
    (80, "critical"),
    (60, "high"),
    (35, "medium"),
    (0,  "low"),
]

SEVERITY_DISPLAY: Dict[str, Dict] = {
    "critical": {
        "label":          "Critical Threat",
        "emoji":          "🚨",
        "color":          "#dc2626",
        "recommendation": (
            "Block this immediately. This is very likely malicious and "
            "could compromise your accounts, passwords, and files."
        ),
        "action_primary":   "Block",
        "action_secondary": "Learn More",
    },
    "high": {
        "label":          "Suspicious",
        "emoji":          "⚠️",
        "color":          "#f97316",
        "recommendation": (
            "This looks suspicious. We recommend blocking it unless you "
            "specifically installed it and recognise the name."
        ),
        "action_primary":   "Block",
        "action_secondary": "Trust It",
    },
    "medium": {
        "label":          "Worth Reviewing",
        "emoji":          "🔍",
        "color":          "#eab308",
        "recommendation": (
            "This is unusual but might be legitimate. Check if you "
            "recognise the program name before deciding."
        ),
        "action_primary":   "Review",
        "action_secondary": "Trust It",
    },
    "low": {
        "label":          "Low Risk",
        "emoji":          "ℹ️",
        "color":          "#3b82f6",
        "recommendation": (
            "This is worth noting but is probably fine. "
            "No action needed unless you're concerned."
        ),
        "action_primary":   "Dismiss",
        "action_secondary": "Learn More",
    },
}

# ---------------------------------------------------------------------------
# Entry type plain English labels
# ---------------------------------------------------------------------------

ENTRY_TYPE_LABELS: Dict[str, str] = {
    "registry": "startup program",
    "task":     "scheduled task",
    "service":  "background service",
}

# ---------------------------------------------------------------------------
# APT group plain English descriptions
# ---------------------------------------------------------------------------

APT_PLAIN_DESCRIPTIONS: Dict[str, str] = {
    "Lumma Stealer":    "a criminal tool sold to steal passwords and browser sessions",
    "Redline Stealer":  "a criminal tool sold to steal passwords and crypto wallets",
    "Stealc":           "a criminal info-stealing tool",
    "Vidar":            "a criminal tool used to steal browser data and crypto wallets",
    "Raccoon":          "a criminal info-stealing service",
    "Laplas Clipper":   "a tool that hijacks crypto transactions",
    "APT29":            "a Russian government hacking group (Cozy Bear)",
    "APT41":            "a Chinese state-sponsored hacking group",
    "Lazarus":          "a North Korean state-sponsored hacking group",
    "FIN7":             "a sophisticated criminal group known for financial attacks",
    "Kimsuky":          "a North Korean espionage group",
    "Cobalt Group":     "a criminal group known for deploying ransomware",
    "TA505":            "a criminal group that distributes ransomware and banking trojans",
    "Evil Corp":        "a Russian criminal group responsible for major financial attacks",
}


# ---------------------------------------------------------------------------
# Core translation function
# ---------------------------------------------------------------------------

def severity_from_score(score: int) -> str:
    """Return severity string from numeric score."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def _build_title(entry: Dict, entry_type: str, severity: str) -> str:
    """Build a clear, human-readable alert title."""
    name = (
        entry.get("name") or
        entry.get("task_name") or
        entry.get("service_name") or
        "Unknown Program"
    )
    type_label = ENTRY_TYPE_LABELS.get(entry_type, "program")

    if severity == "critical":
        return f"Dangerous {type_label} detected: \"{name}\""
    elif severity == "high":
        return f"Suspicious {type_label} detected: \"{name}\""
    elif severity == "medium":
        return f"Unusual {type_label} found: \"{name}\""
    else:
        return f"New {type_label} added: \"{name}\""


def _extract_plain_reasons(
    breakdown: List[Dict],
    apt_matches: List[Dict],
    max_reasons: int = 3,
) -> List[str]:
    """
    Extract the top plain-English reasons from the scoring breakdown.
    Prioritises the highest-delta factors.
    """
    reasons: List[str] = []

    # Sort breakdown by delta descending, take top factors
    sorted_factors = sorted(
        breakdown, key=lambda b: b["delta"], reverse=True
    )

    for item in sorted_factors:
        factor = item["factor"]

        # Direct lookup
        if factor in FACTOR_PLAIN_ENGLISH:
            text = FACTOR_PLAIN_ENGLISH[factor]
            if text not in reasons:
                reasons.append(text)

        # APT match factors (dynamic keys like apt_match_APT-SIG-001)
        elif factor.startswith("apt_match_"):
            if "apt_signature_match" not in [r[:20] for r in reasons]:
                reasons.append(FACTOR_PLAIN_ENGLISH["apt_signature_match"])

        if len(reasons) >= max_reasons:
            break

    # Add APT group context if matched
    if apt_matches and len(reasons) < max_reasons:
        for match in apt_matches[:1]:
            groups = match.get("apt_groups", [])
            described = [
                APT_PLAIN_DESCRIPTIONS.get(g, g)
                for g in groups[:2]
            ]
            if described:
                reasons.append(
                    f"This matches techniques used by: "
                    f"{', '.join(described)}."
                )

    return reasons[:max_reasons]


def _build_what_it_is(entry: Dict, entry_type: str) -> str:
    """One-sentence plain English explanation of what type of entry this is."""
    value = (
        entry.get("value_data") or
        entry.get("command") or
        entry.get("binary_path") or
        ""
    ).strip()

    type_explanations = {
        "registry": (
            "This program has added itself to your Windows startup, "
            "meaning it will run automatically every time you turn on your computer."
        ),
        "task": (
            "A scheduled task has been created that will run this program "
            "automatically on a set schedule."
        ),
        "service": (
            "A background service has been installed that runs silently "
            "in the background at all times."
        ),
    }
    return type_explanations.get(entry_type, "A new program has been added to your system.")


def translate_alert(
    entry: Dict,
    score_result: Dict,
    entry_type: Optional[str] = None,
) -> Dict:
    """
    Translate a technical score result into a user-facing alert.

    Parameters
    ----------
    entry        : the persistence entry dict (from registry/task/service table)
    score_result : output of score_entry()
    entry_type   : "registry", "task", or "service"

    Returns
    -------
    {
        title           : str    — short, clear alert title
        what_it_is      : str    — one sentence explaining the entry type
        plain_reasons   : list   — up to 3 plain English reasons it's suspicious
        recommendation  : str    — what the user should do
        severity        : str    — "critical" / "high" / "medium" / "low"
        severity_label  : str    — "Critical Threat" / "Suspicious" / etc.
        severity_color  : str    — hex color for UI
        severity_emoji  : str    — emoji for quick visual
        action_primary  : str    — primary button label ("Block")
        action_secondary: str    — secondary button label ("Trust It")
        analyst_data    : dict   — full technical result for analyst mode
        entry_name      : str    — raw entry name
        entry_type      : str    — registry / task / service
    }
    """
    etype    = entry_type or entry.get("entry_type", "registry")
    score    = score_result.get("score", 0)
    severity = severity_from_score(score)
    display  = SEVERITY_DISPLAY[severity]

    plain_reasons = _extract_plain_reasons(
        score_result.get("breakdown", []),
        score_result.get("apt_matches", []),
    )

    entry_name = (
        entry.get("name") or
        entry.get("task_name") or
        entry.get("service_name") or
        "Unknown"
    )

    return {
        "title":            _build_title(entry, etype, severity),
        "what_it_is":       _build_what_it_is(entry, etype),
        "plain_reasons":    plain_reasons,
        "recommendation":   display["recommendation"],
        "severity":         severity,
        "severity_label":   display["label"],
        "severity_color":   display["color"],
        "severity_emoji":   display["emoji"],
        "action_primary":   display["action_primary"],
        "action_secondary": display["action_secondary"],
        "score":            score,
        "analyst_data":     score_result,
        "entry_name":       entry_name,
        "entry_type":       etype,
    }


def batch_translate(
    entries_with_results: List[Dict],
) -> List[Dict]:
    """
    Translate a list of (entry, score_result, entry_type) dicts.
    Sorts output by severity (critical first).
    """
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    translated = []

    for item in entries_with_results:
        alert = translate_alert(
            item["entry"],
            item["score_result"],
            item.get("entry_type"),
        )
        translated.append(alert)

    translated.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 99))
    return translated


# ---------------------------------------------------------------------------
# System status summary (for consumer dashboard header)
# ---------------------------------------------------------------------------

def system_status_summary(alerts: List[Dict]) -> Dict:
    """
    Generate the top-level system status shown in the consumer dashboard.

    Returns
    -------
    {
        status        : "clean" / "warning" / "danger"
        status_emoji  : str
        status_message: str
        counts        : {critical, high, medium, low}
    }
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        sev = alert.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1

    if counts["critical"] > 0:
        return {
            "status":         "danger",
            "status_emoji":   "🚨",
            "status_message": (
                f"{counts['critical']} critical threat"
                f"{'s' if counts['critical'] > 1 else ''} detected. "
                "Immediate action required."
            ),
            "counts": counts,
        }
    elif counts["high"] > 0:
        return {
            "status":         "warning",
            "status_emoji":   "⚠️",
            "status_message": (
                f"{counts['high']} suspicious "
                f"item{'s' if counts['high'] > 1 else ''} found. "
                "Review recommended."
            ),
            "counts": counts,
        }
    elif counts["medium"] > 0:
        return {
            "status":         "notice",
            "status_emoji":   "🔍",
            "status_message": (
                f"{counts['medium']} unusual "
                f"item{'s' if counts['medium'] > 1 else ''} worth reviewing."
            ),
            "counts": counts,
        }
    else:
        return {
            "status":         "clean",
            "status_emoji":   "✅",
            "status_message": "Your system looks clean. No threats detected.",
            "counts": counts,
        }