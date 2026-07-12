import pytest
import boto3
from botocore.stub import Stubber
from botocore.exceptions import ClientError
from secureops.scanners.guardduty_scanner import scan_guardduty


def test_guardduty_scanner_client_init_error():
    """
    Test that scanner handles client initialization failures gracefully.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("Connection failed")

    session = FailSession()
    findings = scan_guardduty(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "GuardDuty"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize GuardDuty Client"


def test_guardduty_scanner_access_denied():
    """
    Test that AccessDenied when listing detectors generates a high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("guardduty")
    stubber = Stubber(client)
    
    stubber.add_client_error(
        "list_detectors",
        service_error_code="AccessDenied",
        service_message="Access denied to list detectors"
    )
    stubber.activate()
    
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_guardduty(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "GuardDuty"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "List Detectors" in findings[0].title


def test_guardduty_scanner_subscription_required():
    """
    Test that SubscriptionRequiredException is mapped to a critical finding that GuardDuty is not enabled.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("guardduty")
    stubber = Stubber(client)
    
    stubber.add_client_error(
        "list_detectors",
        service_error_code="SubscriptionRequiredException",
        service_message="GuardDuty subscription required"
    )
    stubber.activate()
    
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_guardduty(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "GuardDuty"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "GuardDuty Not Enabled"
    assert "SubscriptionRequiredException" in findings[0].evidence


def test_guardduty_scanner_no_detectors():
    """
    Test that an empty detector list returns a critical GuardDuty Not Enabled finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("guardduty")
    stubber = Stubber(client)
    
    stubber.add_response("list_detectors", {"DetectorIds": []})
    stubber.activate()
    
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_guardduty(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "GuardDuty"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "GuardDuty Not Enabled"
    assert "No GuardDuty detectors found" in findings[0].evidence


def test_guardduty_scanner_active_findings():
    """
    Test that active high/medium/low findings are correctly fetched, grouped, and mapped to findings.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("guardduty")
    stubber = Stubber(client)
    
    # 1. list_detectors
    stubber.add_response("list_detectors", {"DetectorIds": ["det-1"]})
    
    # 2. list_findings (returns finding IDs)
    stubber.add_response(
        "list_findings",
        {"FindingIds": ["find-high", "find-med", "find-low"]}
    )
    
    # 3. get_findings (returns finding details)
    stubber.add_response(
        "get_findings",
        {
            "Findings": [
                {
                    "Id": "find-high",
                    "Severity": 8.5,
                    "AccountId": "123456789012",
                    "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/det-1/finding/find-high",
                    "CreatedAt": "2026-07-12T10:00:00.000Z",
                    "Region": "us-east-1",
                    "Resource": {},
                    "SchemaVersion": "2.0",
                    "Type": "UnauthorizedAccess:EC2/TorIPCaller",
                    "UpdatedAt": "2026-07-12T10:00:00.000Z"
                },
                {
                    "Id": "find-med",
                    "Severity": 5.0,
                    "AccountId": "123456789012",
                    "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/det-1/finding/find-med",
                    "CreatedAt": "2026-07-12T10:00:00.000Z",
                    "Region": "us-east-1",
                    "Resource": {},
                    "SchemaVersion": "2.0",
                    "Type": "UnauthorizedAccess:EC2/TorIPCaller",
                    "UpdatedAt": "2026-07-12T10:00:00.000Z"
                },
                {
                    "Id": "find-low",
                    "Severity": 2.5,
                    "AccountId": "123456789012",
                    "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/det-1/finding/find-low",
                    "CreatedAt": "2026-07-12T10:00:00.000Z",
                    "Region": "us-east-1",
                    "Resource": {},
                    "SchemaVersion": "2.0",
                    "Type": "UnauthorizedAccess:EC2/TorIPCaller",
                    "UpdatedAt": "2026-07-12T10:00:00.000Z"
                }
            ]
        }
    )
    
    stubber.activate()
    
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_guardduty(session)
    stubber.assert_no_pending_responses()
    
    # Expected: 3 findings (one for High, one for Medium, one for Low)
    assert len(findings) == 3
    
    # Verify High
    high_f = next(f for f in findings if f.severity == "HIGH")
    assert high_f.service == "GuardDuty"
    assert high_f.title == "Active High Severity GuardDuty Findings"
    assert "Found 1 active high severity" in high_f.evidence
    
    # Verify Medium
    med_f = next(f for f in findings if f.severity == "MEDIUM")
    assert med_f.service == "GuardDuty"
    assert med_f.title == "Active Medium Severity GuardDuty Findings"
    assert "Found 1 active medium severity" in med_f.evidence
    
    # Verify Low
    low_f = next(f for f in findings if f.severity == "LOW")
    assert low_f.service == "GuardDuty"
    assert low_f.title == "Active Low Severity GuardDuty Findings"
    assert "Found 1 active low severity" in low_f.evidence
