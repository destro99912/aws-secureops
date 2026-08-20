import sys
import botocore.exceptions
import pytest
from secureops import main as main_module


class FakeSTSClient:
    def get_caller_identity(self):
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
            "UserId": "AIDAEXAMPLE",
        }


class FakeSession:
    def client(self, service_name, *args, **kwargs):
        if service_name == "sts":
            return FakeSTSClient()
        raise AssertionError(f"unexpected client requested: {service_name}")


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
    for scanner_name in (
        "scan_iam", "scan_s3", "scan_cloudtrail", "scan_config",
        "scan_guardduty", "scan_securityhub", "scan_inspector",
        "scan_kms", "scan_security_groups", "scan_ec2",
    ):
        monkeypatch.setattr(main_module, scanner_name, lambda session: [])

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
