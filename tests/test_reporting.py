import json
from datetime import datetime

import pytest
from secureops.core.models import Finding
from secureops.core.reporting import build_json_report, write_json_report
from secureops.core.version import AWS_SECUREOPS_VERSION


def _finding(service="EC2", severity="HIGH", title="Example Finding",
             resource="i-example", evidence="Example evidence.",
             recommendation="Example recommendation.", region="us-east-1"):
    return Finding(
        service=service,
        severity=severity,
        title=title,
        resource=resource,
        evidence=evidence,
        recommendation=recommendation,
        region=region,
    )


def test_report_schema_top_level_keys_and_tool_metadata():
    """
    A. Report has the expected top-level keys and correct tool name/version.
    """
    report = build_json_report([], region="us-east-1")

    assert set(report.keys()) == {"tool", "scan", "summary", "assessment", "findings"}
    assert report["tool"] == {"name": "AWS SecureOps", "version": AWS_SECUREOPS_VERSION}
    assert AWS_SECUREOPS_VERSION == "0.2.0"


def test_summary_counts_correct():
    """
    B. Summary counts CRITICAL/HIGH/MEDIUM/LOW/INFO correctly.
    """
    findings = [
        _finding(severity="CRITICAL"),
        _finding(severity="HIGH"),
        _finding(severity="HIGH"),
        _finding(severity="MEDIUM"),
        _finding(severity="LOW"),
        _finding(severity="LOW"),
        _finding(severity="LOW"),
        _finding(severity="INFO"),
    ]

    report = build_json_report(findings, region="us-east-1")

    assert report["summary"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 3,
        "INFO": 1,
    }
    assert report["scan"]["finding_count"] == 8


def test_finding_serialization_preserves_fields():
    """
    C. Finding.to_dict() fields are preserved correctly in the report.
    """
    f = _finding(
        service="EC2",
        severity="HIGH",
        title="IMDSv2 Not Enforced",
        resource="i-0123456789abcdef0",
        evidence="Instance metadata options allow requests without mandatory session tokens.",
        recommendation="Require IMDSv2 by configuring instance metadata HttpTokens to 'required'.",
        region="us-east-1",
    )

    report = build_json_report([f], region="us-east-1")

    assert len(report["findings"]) == 1
    serialized = report["findings"][0]
    assert serialized == {
        "service": "EC2",
        "severity": "HIGH",
        "title": "IMDSv2 Not Enforced",
        "resource": "i-0123456789abcdef0",
        "evidence": "Instance metadata options allow requests without mandatory session tokens.",
        "recommendation": "Require IMDSv2 by configuring instance metadata HttpTokens to 'required'.",
        "region": "us-east-1",
    }


def test_empty_findings_produces_valid_zeroed_report():
    """
    D. Empty findings -> valid report, all summary values zero, findings = [].
    """
    report = build_json_report([], region="us-east-1")

    assert report["scan"]["finding_count"] == 0
    assert report["summary"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    assert report["findings"] == []


def test_generated_at_is_iso8601_timezone_aware_utc():
    """
    E. generated_at is a valid ISO-8601 timezone-aware UTC timestamp.
    """
    report = build_json_report([], region="us-east-1")
    timestamp = report["scan"]["generated_at"]

    parsed = datetime.fromisoformat(timestamp)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_region_present_when_available():
    """
    F. Expected region appears in the report when available.
    """
    report = build_json_report([], region="eu-west-1")
    assert report["scan"]["region"] == "eu-west-1"


def test_region_none_when_unavailable():
    """
    F. None/null allowed when region cannot be determined.
    """
    report = build_json_report([], region=None)
    assert report["scan"]["region"] is None


def test_report_contains_no_sensitive_metadata():
    """
    G. Report must not contain account IDs, ARNs, UserId, profile names, or
    credential-looking strings.
    """
    findings = [
        _finding(
            evidence="Lacks 'ec2:DescribeInstances' permission. AWS error code: AccessDenied.",
            recommendation="Ensure the scanner identity has 'ec2:DescribeInstances' permissions.",
        )
    ]
    report = build_json_report(findings, region="us-east-1")
    serialized = json.dumps(report)

    assert "Account" not in serialized
    assert "arn:aws" not in serialized
    assert "UserId" not in serialized
    assert "profile" not in serialized.lower()
    assert "AKIA" not in serialized
    assert "aws_secret_access_key" not in serialized.lower()


def test_report_assessment_object_present():
    """
    M. The report contains a top-level 'assessment' object.
    """
    report = build_json_report([_finding(severity="HIGH")], region="us-east-1")

    assert "assessment" in report
    assert set(report["assessment"].keys()) == {
        "risk_score", "risk_level", "raw_risk_points",
        "posture_finding_count", "coverage_status", "coverage_issue_count",
    }


def test_report_existing_keys_still_present_alongside_assessment():
    """
    N. Adding 'assessment' does not remove/rename existing top-level keys.
    """
    report = build_json_report([_finding()], region="us-east-1")

    assert "tool" in report
    assert "scan" in report
    assert "summary" in report
    assert "findings" in report
    assert "assessment" in report


def test_report_assessment_score_and_coverage_values_correct():
    """
    O. Assessment score/coverage values in the report are correct.
    """
    findings = [
        _finding(severity="HIGH", title="SSH Open To Internet"),
        _finding(severity="HIGH", title="Scanner Permission Error: Access Denied for Describe Volumes"),
    ]
    report = build_json_report(findings, region="us-east-1")

    assessment = report["assessment"]
    assert assessment["raw_risk_points"] == 7
    assert assessment["risk_score"] == 7
    assert assessment["risk_level"] == "LOW"
    assert assessment["posture_finding_count"] == 1
    assert assessment["coverage_status"] == "DEGRADED"
    assert assessment["coverage_issue_count"] == 1


def test_write_json_report_produces_valid_indented_json(tmp_path):
    """
    H. Writing the report to a temp file produces valid, human-readable JSON.
    """
    report = build_json_report([_finding()], region="us-east-1")
    out_path = tmp_path / "report.json"

    write_json_report(report, str(out_path))

    raw = out_path.read_text(encoding="utf-8")
    assert "\n  " in raw  # indent=2 produces multi-line, indented output

    loaded = json.loads(raw)
    assert loaded == report


def test_write_json_report_raises_oserror_on_failure(tmp_path):
    """
    I. Writing to an unwritable/nonexistent-parent path fails safely with an
    OSError (no traceback / raw exception leakage is the caller's job to
    handle - this asserts the low-level failure mode is a plain OSError).
    """
    report = build_json_report([], region="us-east-1")
    bad_path = tmp_path / "no-such-directory" / "report.json"

    with pytest.raises(OSError):
        write_json_report(report, str(bad_path))
