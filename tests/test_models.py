import pytest
from dataclasses import FrozenInstanceError
from secureops.core.models import Finding


def test_valid_finding_creation():
    """
    Test that a valid Finding can be created.
    """
    finding = Finding(
        service="IAM",
        severity="HIGH",
        title="Directly Attached AdministratorAccess Policy",
        resource="User: admin",
        evidence="AdministratorAccess policy is directly attached to the user.",
        recommendation="Remove policies directly attached to users.",
        region="us-east-1"
    )
    assert finding.service == "IAM"
    assert finding.severity == "HIGH"
    assert finding.title == "Directly Attached AdministratorAccess Policy"
    assert finding.resource == "User: admin"
    assert finding.evidence == "AdministratorAccess policy is directly attached to the user."
    assert finding.recommendation == "Remove policies directly attached to users."
    assert finding.region == "us-east-1"


def test_finding_to_dict():
    """
    Test that to_dict() returns the expected dictionary.
    """
    finding = Finding(
        service="S3",
        severity="LOW",
        title="Public Bucket Access Check",
        resource="arn:aws:s3:::my-bucket",
        evidence="Bucket is public.",
        recommendation="Enable public access block.",
        region=None
    )
    expected = {
        "service": "S3",
        "severity": "LOW",
        "title": "Public Bucket Access Check",
        "resource": "arn:aws:s3:::my-bucket",
        "evidence": "Bucket is public.",
        "recommendation": "Enable public access block.",
        "region": None
    }
    assert finding.to_dict() == expected


def test_frozen_finding_cannot_be_modified():
    """
    Test that a frozen Finding cannot be modified (raises FrozenInstanceError).
    """
    finding = Finding(
        service="KMS",
        severity="MEDIUM",
        title="KMS Key Rotation Disabled",
        resource="arn:aws:kms:us-east-1:123456789012:key/123",
        evidence="Rotation is disabled.",
        recommendation="Enable rotation."
    )
    with pytest.raises(FrozenInstanceError):
        finding.severity = "HIGH"  # type: ignore[misc]


def test_invalid_severity_raises_value_error():
    """
    Test that invalid severity values raise ValueError.
    """
    with pytest.raises(ValueError) as excinfo:
        Finding(
            service="Config",
            severity="invalid-severity",
            title="Config status check",
            resource="Config Recorder",
            evidence="Not enabled",
            recommendation="Enable config"
        )
    assert "Invalid severity 'invalid-severity'" in str(excinfo.value)


def test_optional_region_works():
    """
    Test that the optional region field works correctly.
    """
    finding = Finding(
        service="GuardDuty",
        severity="CRITICAL",
        title="GuardDuty Not Enabled",
        resource="GuardDuty Config",
        evidence="Disabled",
        recommendation="Enable it",
        region="us-west-2"
    )
    assert finding.region == "us-west-2"


def test_finding_without_region_remains_valid():
    """
    Test that a Finding without a region remains valid (defaults to None).
    """
    finding = Finding(
        service="Inspector",
        severity="INFO",
        title="Inspector Subscription Check",
        resource="Inspector Service",
        evidence="Subscribed",
        recommendation="N/A"
    )
    assert finding.region is None
