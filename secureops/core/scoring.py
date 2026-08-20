from typing import Any

from secureops.core.models import Finding

# Severity -> risk point weight. Deterministic and explicit; not configurable
# in this task (see Task 6 scope restrictions).
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

# Findings whose title starts with any of these prefixes represent an
# assessment/coverage gap (AWS SecureOps could not fully check something due
# to a permission or execution failure) rather than an observed security
# posture condition. They are excluded from the risk score entirely so that
# missing permissions cannot inflate (or deflate) the reported risk.
COVERAGE_TITLE_PREFIXES = (
    "Scanner Permission Error:",
    "Scanner Execution Error:",
    "Could Not Initialize",
    "Could Not Describe",
    "Could Not Retrieve",
    "Could Not List",
    "Error Scanning",
)

RISK_LEVEL_BOUNDARIES = (
    (0, 0, "LOW"),
    (1, 20, "LOW"),
    (21, 40, "MODERATE"),
    (41, 70, "HIGH"),
    (71, 100, "CRITICAL"),
)


def is_coverage_finding(finding: Finding) -> bool:
    """
    True if this finding represents an assessment/coverage gap (permission
    denied, scanner init/execution failure) rather than an observed security
    posture condition.
    """
    return finding.title.startswith(COVERAGE_TITLE_PREFIXES)


def risk_level_for_score(score: int) -> str:
    """
    Maps a 0-100 risk score to a simple, explicit label. Boundaries:
    0 = LOW, 1-20 = LOW, 21-40 = MODERATE, 41-70 = HIGH, 71-100 = CRITICAL.
    """
    for low, high, label in RISK_LEVEL_BOUNDARIES:
        if low <= score <= high:
            return label
    return "CRITICAL"  # score > 100 should not occur (score is capped), but stay safe.


def calculate_assessment(findings: list[Finding]) -> dict[str, Any]:
    """
    Computes a simple, transparent posture risk score plus assessment
    coverage status from a list of Finding objects.

    This is NOT a compliance score, a certification, or a prediction of
    breach/exploitability likelihood. It is a deterministic sum of severity
    weights for observed posture findings, capped at 100. Coverage gaps
    (permission errors, scanner execution failures) are excluded from the
    score and reported separately via coverage_status/coverage_issue_count,
    so that missing access never inflates or deflates the risk score.
    """
    posture_findings = [f for f in findings if not is_coverage_finding(f)]
    coverage_findings = [f for f in findings if is_coverage_finding(f)]

    raw_risk_points = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in posture_findings)
    risk_score = min(100, raw_risk_points)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level_for_score(risk_score),
        "raw_risk_points": raw_risk_points,
        "posture_finding_count": len(posture_findings),
        "coverage_status": "DEGRADED" if coverage_findings else "COMPLETE",
        "coverage_issue_count": len(coverage_findings),
    }
