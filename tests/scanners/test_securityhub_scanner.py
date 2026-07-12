import pytest
import boto3
from botocore.stub import Stubber
from secureops.scanners.securityhub_scanner import scan_securityhub


def test_securityhub_scanner_client_init_error():
    """
    Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("SecurityHub init error")

    session = FailSession()
    findings = scan_securityhub(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "SecurityHub"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize Security Hub Client"


def test_securityhub_scanner_permission_denied():
    """
    Test describe_hub permission denied maps to high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("securityhub")
    stubber = Stubber(client)
    
    stubber.add_client_error(
        "describe_hub",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_securityhub(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "SecurityHub"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "Describe Hub" in findings[0].title


def test_securityhub_scanner_not_enabled():
    """
    Test Security Hub is not enabled (e.g. InvalidAccessException).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("securityhub")
    stubber = Stubber(client)
    
    stubber.add_client_error(
        "describe_hub",
        service_error_code="SubscriptionRequiredException",
        service_message="Not subscribed"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_securityhub(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "SecurityHub"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Security Hub Not Enabled"


def test_securityhub_scanner_no_findings():
    """
    Test clean Security Hub state (Enabled, no active findings).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("securityhub")
    stubber = Stubber(client)
    
    # 1. describe_hub
    stubber.add_response("describe_hub", {"HubArn": "arn:aws:securityhub:us-east-1:123:hub/default"})
    
    # 2. get_findings (empty)
    stubber.add_response("get_findings", {"Findings": []})
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_securityhub(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 0


def test_securityhub_scanner_active_findings():
    """
    Test that active findings are correctly counted and reported.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("securityhub")
    stubber = Stubber(client)
    
    # 1. describe_hub
    stubber.add_response("describe_hub", {"HubArn": "arn:aws:securityhub:us-east-1:123:hub/default"})
    
    # 2. get_findings (returns CRITICAL, HIGH, MEDIUM, LOW)
    stubber.add_response(
        "get_findings",
        {
            "Findings": [
                {
                    "Id": "f1",
                    "Severity": {"Label": "CRITICAL"},
                    "SchemaVersion": "2018-12-18",
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                    "GeneratorId": "aws-securityhub",
                    "AwsAccountId": "123456789012",
                    "CreatedAt": "2026-07-12T10:00:00Z",
                    "UpdatedAt": "2026-07-12T10:00:00Z",
                    "Title": "Dummy 1",
                    "Description": "Dummy Desc 1",
                    "Resources": [{"Type": "AwsEc2Instance", "Id": "i-1"}]
                },
                {
                    "Id": "f2",
                    "Severity": {"Label": "HIGH"},
                    "SchemaVersion": "2018-12-18",
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                    "GeneratorId": "aws-securityhub",
                    "AwsAccountId": "123456789012",
                    "CreatedAt": "2026-07-12T10:00:00Z",
                    "UpdatedAt": "2026-07-12T10:00:00Z",
                    "Title": "Dummy 2",
                    "Description": "Dummy Desc 2",
                    "Resources": [{"Type": "AwsEc2Instance", "Id": "i-2"}]
                },
                {
                    "Id": "f3",
                    "Severity": {"Label": "MEDIUM"},
                    "SchemaVersion": "2018-12-18",
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                    "GeneratorId": "aws-securityhub",
                    "AwsAccountId": "123456789012",
                    "CreatedAt": "2026-07-12T10:00:00Z",
                    "UpdatedAt": "2026-07-12T10:00:00Z",
                    "Title": "Dummy 3",
                    "Description": "Dummy Desc 3",
                    "Resources": [{"Type": "AwsEc2Instance", "Id": "i-3"}]
                },
                {
                    "Id": "f4",
                    "Severity": {"Label": "LOW"},
                    "SchemaVersion": "2018-12-18",
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                    "GeneratorId": "aws-securityhub",
                    "AwsAccountId": "123456789012",
                    "CreatedAt": "2026-07-12T10:00:00Z",
                    "UpdatedAt": "2026-07-12T10:00:00Z",
                    "Title": "Dummy 4",
                    "Description": "Dummy Desc 4",
                    "Resources": [{"Type": "AwsEc2Instance", "Id": "i-4"}]
                }
            ]
        }
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_securityhub(session)
    stubber.assert_no_pending_responses()
    
    # Expected: 4 findings
    assert len(findings) == 4
    
    crit_f = next(f for f in findings if f.severity == "CRITICAL")
    assert "Active CRITICAL Security Hub Findings Exist" in crit_f.title
    
    high_f = next(f for f in findings if f.severity == "HIGH")
    assert "Active HIGH Security Hub Findings Exist" in high_f.title
    
    med_f = next(f for f in findings if f.severity == "MEDIUM")
    assert "Active MEDIUM Security Hub Findings Exist" in med_f.title
    
    low_f = next(f for f in findings if f.severity == "LOW")
    assert "Active LOW Security Hub Findings Exist" in low_f.title
