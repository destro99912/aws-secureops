import pytest
import boto3
from botocore.stub import Stubber
from secureops.scanners.inspector_scanner import scan_inspector


def test_inspector_scanner_client_init_error():
    """
    Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("Inspector init error")

    session = FailSession()
    findings = scan_inspector(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "Inspector"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize Inspector Client"


def test_inspector_scanner_permission_denied():
    """
    Test batch_get_account_status permission denied maps to high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("inspector2")
    sts_client = session.client("sts")
    
    stubber = Stubber(client)
    sts_stubber = Stubber(sts_client)
    
    sts_stubber.add_response("get_caller_identity", {"Account": "123456789012"})
    
    stubber.add_client_error(
        "batch_get_account_status",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    
    sts_stubber.activate()
    stubber.activate()
    
    def mock_client(name, *args, **kwargs):
        if name == "inspector2":
            return client
        if name == "sts":
            return sts_client
        raise ValueError(f"Unknown service {name}")
        
    session.client = mock_client  # type: ignore[assignment]
    
    findings = scan_inspector(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "Inspector"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "Batch Get Account Status" in findings[0].title


def test_inspector_scanner_not_enabled():
    """
    Test Amazon Inspector not enabled (e.g. state status is not ENABLED).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("inspector2")
    sts_client = session.client("sts")
    
    stubber = Stubber(client)
    sts_stubber = Stubber(sts_client)
    
    sts_stubber.add_response("get_caller_identity", {"Account": "123456789012"})
    
    stubber.add_response(
        "batch_get_account_status",
        {
            "accounts": [
                {
                    "accountId": "123456789012",
                    "state": {
                        "status": "DISABLED",
                        "errorCode": "NONE",
                        "errorMessage": "none"
                    },
                    "resourceState": {
                        "ec2": {"status": "DISABLED", "errorCode": "NONE", "errorMessage": "none"},
                        "ecr": {"status": "DISABLED", "errorCode": "NONE", "errorMessage": "none"}
                    }
                }
            ]
        }
    )
    
    sts_stubber.activate()
    stubber.activate()
    
    def mock_client(name, *args, **kwargs):
        if name == "inspector2":
            return client
        if name == "sts":
            return sts_client
        raise ValueError(f"Unknown service {name}")
        
    session.client = mock_client  # type: ignore[assignment]
    
    findings = scan_inspector(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "Inspector"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Amazon Inspector Not Enabled"


def test_inspector_scanner_no_findings():
    """
    Test clean Inspector state (Enabled, no active findings).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("inspector2")
    sts_client = session.client("sts")
    
    stubber = Stubber(client)
    sts_stubber = Stubber(sts_client)
    
    sts_stubber.add_response("get_caller_identity", {"Account": "123456789012"})
    
    stubber.add_response(
        "batch_get_account_status",
        {
            "accounts": [
                {
                    "accountId": "123456789012",
                    "state": {
                        "status": "ENABLED",
                        "errorCode": "NONE",
                        "errorMessage": "none"
                    },
                    "resourceState": {
                        "ec2": {"status": "ENABLED", "errorCode": "NONE", "errorMessage": "none"},
                        "ecr": {"status": "ENABLED", "errorCode": "NONE", "errorMessage": "none"}
                    }
                }
            ]
        }
    )
    
    stubber.add_response("list_findings", {"findings": []})
    
    sts_stubber.activate()
    stubber.activate()
    
    def mock_client(name, *args, **kwargs):
        if name == "inspector2":
            return client
        if name == "sts":
            return sts_client
        raise ValueError(f"Unknown service {name}")
        
    session.client = mock_client  # type: ignore[assignment]
    
    findings = scan_inspector(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 0


def test_inspector_scanner_active_findings():
    """
    Test that active findings are correctly counted and reported.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("inspector2")
    sts_client = session.client("sts")
    
    stubber = Stubber(client)
    sts_stubber = Stubber(sts_client)
    
    sts_stubber.add_response("get_caller_identity", {"Account": "123456789012"})
    
    stubber.add_response(
        "batch_get_account_status",
        {
            "accounts": [
                {
                    "accountId": "123456789012",
                    "state": {
                        "status": "ENABLED",
                        "errorCode": "NONE",
                        "errorMessage": "none"
                    },
                    "resourceState": {
                        "ec2": {"status": "ENABLED", "errorCode": "NONE", "errorMessage": "none"},
                        "ecr": {"status": "ENABLED", "errorCode": "NONE", "errorMessage": "none"}
                    }
                }
            ]
        }
    )
    
    # We add active findings details. Let's make sure we include all required fields for Inspector Finding.
    # Required parameters in botocore Inspector Finding: findingArn, status, severity, type, firstObservedAt, lastObservedAt, awsAccountId, description, remediation
    stubber.add_response(
        "list_findings",
        {
            "findings": [
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:123:finding/f1",
                    "status": "ACTIVE",
                    "severity": "CRITICAL",
                    "type": "PACKAGE_VULNERABILITY",
                    "firstObservedAt": 1234567890.0,
                    "lastObservedAt": 1234567890.0,
                    "awsAccountId": "123456789012",
                    "description": "Vulnerability 1",
                    "remediation": {"recommendation": {"text": "Fix it"}},
                    "resources": [{"id": "i-1", "type": "AWS_EC2_INSTANCE"}]
                },
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:123:finding/f2",
                    "status": "ACTIVE",
                    "severity": "HIGH",
                    "type": "PACKAGE_VULNERABILITY",
                    "firstObservedAt": 1234567890.0,
                    "lastObservedAt": 1234567890.0,
                    "awsAccountId": "123456789012",
                    "description": "Vulnerability 2",
                    "remediation": {"recommendation": {"text": "Fix it"}},
                    "resources": [{"id": "i-2", "type": "AWS_EC2_INSTANCE"}]
                },
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:123:finding/f3",
                    "status": "ACTIVE",
                    "severity": "MEDIUM",
                    "type": "PACKAGE_VULNERABILITY",
                    "firstObservedAt": 1234567890.0,
                    "lastObservedAt": 1234567890.0,
                    "awsAccountId": "123456789012",
                    "description": "Vulnerability 3",
                    "remediation": {"recommendation": {"text": "Fix it"}},
                    "resources": [{"id": "i-3", "type": "AWS_EC2_INSTANCE"}]
                },
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:123:finding/f4",
                    "status": "ACTIVE",
                    "severity": "LOW",
                    "type": "PACKAGE_VULNERABILITY",
                    "firstObservedAt": 1234567890.0,
                    "lastObservedAt": 1234567890.0,
                    "awsAccountId": "123456789012",
                    "description": "Vulnerability 4",
                    "remediation": {"recommendation": {"text": "Fix it"}},
                    "resources": [{"id": "i-4", "type": "AWS_EC2_INSTANCE"}]
                }
            ]
        }
    )
    
    sts_stubber.activate()
    stubber.activate()
    
    def mock_client(name, *args, **kwargs):
        if name == "inspector2":
            return client
        if name == "sts":
            return sts_client
        raise ValueError(f"Unknown service {name}")
        
    session.client = mock_client  # type: ignore[assignment]
    
    findings = scan_inspector(session)
    stubber.assert_no_pending_responses()
    
    # Expected: 4 findings
    assert len(findings) == 4
    
    crit_f = next(f for f in findings if f.severity == "CRITICAL")
    assert "Active CRITICAL Inspector Findings Exist" in crit_f.title
    
    high_f = next(f for f in findings if f.severity == "HIGH")
    assert "Active HIGH Inspector Findings Exist" in high_f.title
    
    med_f = next(f for f in findings if f.severity == "MEDIUM")
    assert "Active MEDIUM Inspector Findings Exist" in med_f.title
    
    low_f = next(f for f in findings if f.severity == "LOW")
    assert "Active LOW Inspector Findings Exist" in low_f.title
