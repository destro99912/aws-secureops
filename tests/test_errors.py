import botocore.exceptions
from secureops.core.errors import create_permission_finding, sanitize_error


def _client_error(code: str, message: str, request_id: str = "abc-123-request-id"):
    return botocore.exceptions.ClientError(
        error_response={
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {
                "RequestId": request_id,
                "HTTPHeaders": {"x-amzn-requestid": request_id},
            },
        },
        operation_name="DescribeSecurityGroups",
    )


def test_create_permission_finding_sanitizes_access_denied():
    error = _client_error(
        "AccessDenied",
        "User: arn:aws:iam::123456789012:user/scanner is not authorized to perform: ec2:DescribeSecurityGroups",
    )

    finding = create_permission_finding(
        service="EC2",
        operation="Describe Security Groups",
        resource="Security Groups",
        required_permission="ec2:DescribeSecurityGroups",
        error=error,
        severity="MEDIUM",
    )

    assert "ec2:DescribeSecurityGroups" in finding.evidence
    assert "AccessDenied" in finding.evidence
    assert "123456789012" not in finding.evidence
    assert "arn:aws:iam" not in finding.evidence
    assert "abc-123-request-id" not in finding.evidence
    assert "not authorized to perform" not in finding.evidence


def test_create_permission_finding_sanitizes_non_permission_error():
    error = _client_error("Throttling", "Rate exceeded for account 123456789012")

    finding = create_permission_finding(
        service="EC2",
        operation="Describe Security Groups",
        resource="Security Groups",
        required_permission="ec2:DescribeSecurityGroups",
        error=error,
        severity="LOW",
    )

    assert "Describe Security Groups" in finding.evidence
    assert "Throttling" in finding.evidence
    assert "123456789012" not in finding.evidence
    assert "Rate exceeded" not in finding.evidence
    assert "abc-123-request-id" not in finding.evidence


def test_sanitize_error_hides_raw_boto_details():
    error = _client_error(
        "InternalError",
        "Something failed for arn:aws:iam::123456789012:role/scanner",
    )

    message = sanitize_error(error)

    assert "InternalError" in message
    assert "123456789012" not in message
    assert "arn:aws:iam" not in message
    assert "abc-123-request-id" not in message


def test_sanitize_error_handles_generic_exception():
    message = sanitize_error(Exception("some raw internal detail: secret-token-xyz"))

    assert "secret-token-xyz" not in message
