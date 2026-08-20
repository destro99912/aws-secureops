import json
import os
import sys
import botocore.exceptions
import pytest
from secureops import main as main_module
from secureops.core.models import Finding


class FakeSTSClient:
    def get_caller_identity(self):
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
            "UserId": "AIDAEXAMPLE",
        }


class FakeSession:
    region_name = "us-east-1"

    def client(self, service_name, *args, **kwargs):
        if service_name == "sts":
            return FakeSTSClient()
        raise AssertionError(f"unexpected client requested: {service_name}")


def _mock_scanners(monkeypatch, findings_by_scanner=None):
    findings_by_scanner = findings_by_scanner or {}
    for scanner_name in (
        "scan_iam", "scan_s3", "scan_cloudtrail", "scan_config",
        "scan_guardduty", "scan_securityhub", "scan_inspector",
        "scan_kms", "scan_security_groups", "scan_ec2",
    ):
        result = findings_by_scanner.get(scanner_name, [])
        monkeypatch.setattr(main_module, scanner_name, lambda session, result=result: result)


class RaisingSTSClient:
    def get_caller_identity(self):
        raise botocore.exceptions.ClientError(
            error_response={
                "Error": {
                    "Code": "SomeUnrecognizedErrorCode",
                    "Message": "User: arn:aws:iam::987654321098:user/leaked-user is not authorized "
                                "to perform sts:GetCallerIdentity (super-secret-detail-xyz)",
                },
                "ResponseMetadata": {
                    "RequestId": "req-fake-1234-5678-abcd",
                    "HTTPHeaders": {"x-amzn-requestid": "req-fake-1234-5678-abcd"},
                },
            },
            operation_name="GetCallerIdentity",
        )


class RaisingSession:
    def client(self, service_name, *args, **kwargs):
        if service_name == "sts":
            return RaisingSTSClient()
        raise AssertionError(f"unexpected client requested: {service_name}")


def test_cli_identity_output_hides_sensitive_fields(monkeypatch, capsys):
    """
    On successful authentication, the CLI must print only a safe success
    message and must not print Account, Arn, or UserId.
    """
    monkeypatch.setattr(
        main_module, "get_aws_session",
        lambda profile_name=None, region_name=None: FakeSession()
    )
    _mock_scanners(monkeypatch)

    monkeypatch.setattr(sys, "argv", ["main.py"])

    main_module.main()

    output = capsys.readouterr().out

    assert "[+] Successfully authenticated to AWS." in output
    assert "123456789012" not in output
    assert "arn:aws:iam::123456789012:user/test" not in output
    assert "AIDAEXAMPLE" not in output
    assert "Account" not in output
    assert "Arn:" not in output
    assert "UserId" not in output


def test_cli_unrecognized_client_error_hides_raw_message(monkeypatch, capsys):
    """
    An unrecognized STS ClientError must not leak the raw AWS error message,
    account IDs, ARNs, or request metadata to stdout - only the error code
    and a generic safe explanation.
    """
    monkeypatch.setattr(
        main_module, "get_aws_session",
        lambda profile_name=None, region_name=None: RaisingSession()
    )
    monkeypatch.setattr(sys, "argv", ["main.py"])

    with pytest.raises(SystemExit):
        main_module.main()

    output = capsys.readouterr().out

    assert "SomeUnrecognizedErrorCode" in output
    assert "987654321098" not in output
    assert "arn:aws:iam::987654321098:user/leaked-user" not in output
    assert "req-fake-1234-5678-abcd" not in output
    assert "super-secret-detail-xyz" not in output
    assert "not authorized to perform" not in output


def test_cli_output_json_option_writes_report_with_findings(monkeypatch, capsys, tmp_path):
    """
    J & K. --output-json writes a valid JSON report when findings exist.
    """
    monkeypatch.setattr(
        main_module, "get_aws_session",
        lambda profile_name=None, region_name=None: FakeSession()
    )
    finding = Finding(
        service="EC2", severity="HIGH", title="IMDSv2 Not Enforced",
        resource="i-example", evidence="evidence text", recommendation="fix it",
        region="us-east-1"
    )
    _mock_scanners(monkeypatch, {"scan_ec2": [finding]})

    out_path = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["main.py", "--output-json", str(out_path)])

    main_module.main()

    output = capsys.readouterr().out
    assert f"JSON report written to: {out_path}" in output
    assert out_path.exists()

    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["scan"]["finding_count"] == 1
    assert report["summary"]["HIGH"] == 1
    assert len(report["findings"]) == 1
    assert report["findings"][0]["resource"] == "i-example"


def test_cli_output_json_option_writes_report_with_zero_findings(monkeypatch, capsys, tmp_path):
    """
    L. --output-json writes a valid report even when there are zero findings.
    """
    monkeypatch.setattr(
        main_module, "get_aws_session",
        lambda profile_name=None, region_name=None: FakeSession()
    )
    _mock_scanners(monkeypatch)

    out_path = tmp_path / "empty-report.json"
    monkeypatch.setattr(sys, "argv", ["main.py", "--output-json", str(out_path)])

    main_module.main()

    output = capsys.readouterr().out
    assert "No security findings discovered" in output
    assert f"JSON report written to: {out_path}" in output
    assert out_path.exists()

    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["scan"]["finding_count"] == 0
    assert report["summary"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    assert report["findings"] == []


def test_cli_console_only_behavior_when_output_json_omitted(monkeypatch, capsys, tmp_path):
    """
    M. Existing console-only behavior still works when --output-json is omitted;
    no JSON file is written.
    """
    monkeypatch.setattr(
        main_module, "get_aws_session",
        lambda profile_name=None, region_name=None: FakeSession()
    )
    _mock_scanners(monkeypatch)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["main.py"])

    main_module.main()

    output = capsys.readouterr().out
    assert "No security findings discovered" in output
    assert "JSON report written" not in output
    assert list(tmp_path.iterdir()) == []


def test_cli_output_json_write_failure_is_safe(monkeypatch, capsys, tmp_path):
    """
    Writing to a path whose parent directory doesn't exist fails safely:
    no traceback, a clear local error message, non-zero exit.
    """
    monkeypatch.setattr(
        main_module, "get_aws_session",
        lambda profile_name=None, region_name=None: FakeSession()
    )
    _mock_scanners(monkeypatch)

    bad_path = tmp_path / "no-such-dir" / "report.json"
    monkeypatch.setattr(sys, "argv", ["main.py", "--output-json", str(bad_path)])

    with pytest.raises(SystemExit) as exc_info:
        main_module.main()

    assert exc_info.value.code == 1

    output = capsys.readouterr().out
    assert "Could not write JSON report" in output
    assert "Traceback" not in output
    assert not bad_path.exists()
