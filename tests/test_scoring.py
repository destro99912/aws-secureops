from secureops.core.models import Finding
from secureops.core.scoring import calculate_assessment, is_coverage_finding, risk_level_for_score


def _posture(severity, title="Example Posture Finding"):
    return Finding(
        service="EC2", severity=severity, title=title,
        resource="r", evidence="e", recommendation="rec",
    )


def _coverage(title, severity="MEDIUM"):
    return Finding(
        service="EC2", severity=severity, title=title,
        resource="r", evidence="e", recommendation="rec",
    )


def test_no_findings():
    """A. No findings -> score 0, level LOW, coverage COMPLETE."""
    result = calculate_assessment([])
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["raw_risk_points"] == 0
    assert result["posture_finding_count"] == 0
    assert result["coverage_status"] == "COMPLETE"
    assert result["coverage_issue_count"] == 0


def test_single_low_posture_finding():
    """B. Single LOW posture finding -> score 1."""
    result = calculate_assessment([_posture("LOW")])
    assert result["risk_score"] == 1
    assert result["raw_risk_points"] == 1


def test_single_medium_posture_finding():
    """C. Single MEDIUM -> score 4."""
    result = calculate_assessment([_posture("MEDIUM")])
    assert result["risk_score"] == 4


def test_single_high_posture_finding():
    """D. Single HIGH -> score 7."""
    result = calculate_assessment([_posture("HIGH")])
    assert result["risk_score"] == 7


def test_single_critical_posture_finding():
    """E. Single CRITICAL -> score 10."""
    result = calculate_assessment([_posture("CRITICAL")])
    assert result["risk_score"] == 10


def test_multiple_severities_correct_sum():
    """F. Multiple severities -> correct sum."""
    findings = [
        _posture("CRITICAL"),  # 10
        _posture("HIGH"),      # 7
        _posture("HIGH"),      # 7
        _posture("MEDIUM"),    # 4
        _posture("LOW"),       # 1
    ]
    result = calculate_assessment(findings)
    assert result["raw_risk_points"] == 29
    assert result["risk_score"] == 29
    assert result["posture_finding_count"] == 5


def test_score_cap_at_100():
    """G. Enough findings to exceed 100 raw points -> capped exactly at 100."""
    findings = [_posture("CRITICAL") for _ in range(15)]  # 150 raw points
    result = calculate_assessment(findings)
    assert result["raw_risk_points"] == 150
    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"


def test_permission_finding_contributes_zero_and_degrades_coverage():
    """H. Permission finding contributes 0 risk, coverage DEGRADED."""
    findings = [_coverage("Scanner Permission Error: Access Denied for Describe Volumes", severity="HIGH")]
    result = calculate_assessment(findings)
    assert result["raw_risk_points"] == 0
    assert result["risk_score"] == 0
    assert result["posture_finding_count"] == 0
    assert result["coverage_status"] == "DEGRADED"
    assert result["coverage_issue_count"] == 1


def test_scanner_execution_finding_contributes_zero_and_degrades_coverage():
    """I. Scanner execution/init error contributes 0 risk, coverage DEGRADED."""
    for title in (
        "Scanner Execution Error: Unable to perform Describe Instances",
        "Could Not Initialize EC2 Client",
        "Could Not Describe Security Groups",
        "Could Not Retrieve Account Summary",
        "Could Not List IAM Users",
        "Error Scanning Security Group",
    ):
        findings = [_coverage(title, severity="CRITICAL")]
        result = calculate_assessment(findings)
        assert result["raw_risk_points"] == 0, title
        assert result["coverage_status"] == "DEGRADED", title
        assert result["coverage_issue_count"] == 1, title


def test_mixture_posture_and_coverage():
    """J. Mixture of posture + coverage findings -> only posture contributes risk."""
    findings = [
        _posture("HIGH", title="SSH Open To Internet"),
        _coverage("Scanner Permission Error: Access Denied for Describe Volumes", severity="HIGH"),
    ]
    result = calculate_assessment(findings)
    assert result["raw_risk_points"] == 7
    assert result["risk_score"] == 7
    assert result["posture_finding_count"] == 1
    assert result["coverage_status"] == "DEGRADED"
    assert result["coverage_issue_count"] == 1


def test_info_posture_zero_points_but_counted_as_posture():
    """K. INFO posture finding -> zero risk points but still counted as a posture finding."""
    result = calculate_assessment([_posture("INFO")])
    assert result["raw_risk_points"] == 0
    assert result["risk_score"] == 0
    assert result["posture_finding_count"] == 1
    assert result["coverage_status"] == "COMPLETE"
    assert result["coverage_issue_count"] == 0


def test_risk_level_boundaries():
    """L. Risk-level boundary values."""
    assert risk_level_for_score(0) == "LOW"
    assert risk_level_for_score(1) == "LOW"
    assert risk_level_for_score(20) == "LOW"
    assert risk_level_for_score(21) == "MODERATE"
    assert risk_level_for_score(40) == "MODERATE"
    assert risk_level_for_score(41) == "HIGH"
    assert risk_level_for_score(70) == "HIGH"
    assert risk_level_for_score(71) == "CRITICAL"
    assert risk_level_for_score(100) == "CRITICAL"


def test_is_coverage_finding_classification():
    assert is_coverage_finding(_coverage("Scanner Permission Error: Access Denied for X"))
    assert is_coverage_finding(_coverage("Scanner Execution Error: Unable to perform X"))
    assert is_coverage_finding(_coverage("Could Not Initialize EC2 Client"))
    assert not is_coverage_finding(_posture("HIGH", title="SSH Open To Internet"))
    assert not is_coverage_finding(_posture("CRITICAL", title="Root Account MFA Missing"))
