import importlib.util
import json
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "generate_demo_report.py"


def _load_demo_module():
    spec = importlib.util.spec_from_file_location("generate_demo_report", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_generator_source_makes_no_aws_calls():
    """
    The demo generator must never create a boto3 session or an AWS client -
    it only constructs Finding objects in memory.
    """
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    assert "boto3.Session" not in source
    assert "get_aws_session" not in source
    assert ".client(" not in source


def test_demo_report_schema_valid_and_json_serializable():
    """
    The demo findings, run through the real build_json_report(), produce a
    schema-valid report identical in shape to a real scan's output.
    """
    module = _load_demo_module()
    findings = module.build_demo_findings()
    report = module.build_json_report(findings, region=module.DEMO_REGION)

    assert set(report.keys()) == {"tool", "scan", "summary", "assessment", "findings"}
    assert report["scan"]["finding_count"] == len(findings)
    assert len(report["findings"]) == len(findings)

    # Must be plain JSON-serializable, matching what write_json_report() would produce.
    json.dumps(report)


def test_demo_coverage_finding_excluded_from_risk_score():
    """
    The synthetic 'Scanner Permission Error: Access Denied for Describe Hub'
    finding must be excluded from the posture risk score and must degrade
    coverage status, exactly like the real scoring behavior.
    """
    module = _load_demo_module()
    findings = module.build_demo_findings()
    report = module.build_json_report(findings, region=module.DEMO_REGION)
    assessment = report["assessment"]

    coverage_titles = [f for f in findings if f.title.startswith("Scanner Permission Error:")]
    assert len(coverage_titles) == 1

    assert assessment["coverage_status"] == "DEGRADED"
    assert assessment["coverage_issue_count"] == 1
    assert assessment["posture_finding_count"] == len(findings) - 1

    # The permission-denied finding is HIGH (would add 7 points if wrongly
    # counted). Verify it did NOT inflate the score.
    posture_weight_sum = sum(
        {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}[f.severity]
        for f in findings
        if not f.title.startswith("Scanner Permission Error:")
    )
    assert assessment["raw_risk_points"] == posture_weight_sum
    assert assessment["risk_score"] == posture_weight_sum
