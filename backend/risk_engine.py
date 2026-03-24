"""
Risk Engine — Scoring and classification of detected findings.
Aggregates findings into an overall risk score and level.
"""


# ─── Risk Weights ───────────────────────────────────────────────────

RISK_WEIGHTS = {
    "critical": 5,
    "high": 3,
    "medium": 2,
    "low": 1,
}

RISK_LEVELS = [
    (10, "critical"),
    (6, "high"),
    (3, "medium"),
    (0, "low"),
]


# ─── Scoring ────────────────────────────────────────────────────────

def calculate_risk_score(findings: list[dict]) -> int:
    """Calculate total risk score from a list of finding dicts."""
    score = 0
    for finding in findings:
        risk = finding.get("risk", "low").lower()
        score += RISK_WEIGHTS.get(risk, 1)
    return score


def classify_risk_level(score: int) -> str:
    """Map a numeric score to a risk level string."""
    for threshold, level in RISK_LEVELS:
        if score >= threshold:
            return level
    return "low"


def compute_risk_breakdown(findings: list[dict]) -> dict:
    """Return a count of findings per risk level."""
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        risk = finding.get("risk", "low").lower()
        if risk in breakdown:
            breakdown[risk] += 1
    return breakdown


def compute_type_breakdown(findings: list[dict]) -> dict:
    """Return a count of findings per detection type."""
    breakdown: dict[str, int] = {}
    for finding in findings:
        ftype = finding.get("type", "unknown")
        breakdown[ftype] = breakdown.get(ftype, 0) + 1
    return breakdown


# ─── High-Level API ─────────────────────────────────────────────────

def evaluate_risk(findings: list[dict], anomalies: list[dict] | None = None) -> dict:
    """
    Full risk evaluation combining findings and anomalies.
    Returns risk_score, risk_level, risk_breakdown, and type_breakdown.
    """
    all_items = list(findings)
    if anomalies:
        all_items.extend(anomalies)

    score = calculate_risk_score(all_items)
    level = classify_risk_level(score)
    risk_breakdown = compute_risk_breakdown(all_items)
    type_breakdown = compute_type_breakdown(findings)

    return {
        "risk_score": score,
        "risk_level": level,
        "risk_breakdown": risk_breakdown,
        "type_breakdown": type_breakdown,
        "total_findings": len(findings),
        "total_anomalies": len(anomalies) if anomalies else 0,
    }
