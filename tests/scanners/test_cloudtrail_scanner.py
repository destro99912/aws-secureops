import pytest
import boto3
from botocore.stub import Stubber
from secureops.scanners.cloudtrail_scanner import scan_cloudtrail


def test_cloudtrail_scanner_client_init_error():
    """
    Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("CloudTrail client error")

    session = FailSession()
    findings = scan_cloudtrail(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "CloudTrail"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize CloudTrail Client"


def test_cloudtrail_scanner_permission_denied():
    """
    Test describe trails permission denied maps to high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("cloudtrail")
    stubber = Stubber(client)
    
    stubber.add_client_error(
        "describe_trails",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_cloudtrail(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "CloudTrail"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "Describe Trails" in findings[0].title


def test_cloudtrail_scanner_no_findings():
    """
    Test clean CloudTrail state (At least 1 active, logging, multi-region trail with S3 bucket and validation enabled).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("cloudtrail")
    stubber = Stubber(client)
    
    # 1. describe_trails
    stubber.add_response(
        "describe_trails",
        {
            "trailList": [
                {
                    "Name": "clean-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/clean-trail",
                    "IsMultiRegionTrail": True,
                    "S3BucketName": "logs-bucket",
                    "LogFileValidationEnabled": True
                }
            ]
        }
    )
    
    # 2. get_trail_status
    stubber.add_response(
        "get_trail_status",
        {"IsLogging": True}
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_cloudtrail(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 0


def test_cloudtrail_scanner_no_trails():
    """
    Test that finding is returned when no trails are configured.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("cloudtrail")
    stubber = Stubber(client)
    
    stubber.add_response("describe_trails", {"trailList": []})
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_cloudtrail(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "CloudTrail"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "No CloudTrail Trails Found"


def test_cloudtrail_scanner_positive_findings():
    """
    Test that stopped logging, single region trail, missing S3 bucket, and validation disabled are flagged.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("cloudtrail")
    stubber = Stubber(client)
    
    # 1. describe_trails
    stubber.add_response(
        "describe_trails",
        {
            "trailList": [
                {
                    "Name": "risk-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/risk-trail",
                    "IsMultiRegionTrail": False,
                    "LogFileValidationEnabled": False
                    # S3BucketName is missing
                }
            ]
        }
    )
    
    # 2. get_trail_status (IsLogging=False)
    stubber.add_response(
        "get_trail_status",
        {"IsLogging": False}
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_cloudtrail(session)
    stubber.assert_no_pending_responses()
    
    # Expected findings:
    # 1. CloudTrail Logging is Stopped (CRITICAL)
    # 2. CloudTrail is Not Multi-Region (HIGH)
    # 3. CloudTrail Trail Has No S3 Bucket Configured (HIGH)
    # 4. CloudTrail Log File Validation is Disabled (MEDIUM)
    assert len(findings) == 4
    
    # Verify stopped
    stop_f = next(f for f in findings if f.title == "CloudTrail Logging is Stopped")
    assert stop_f.severity == "CRITICAL"
    
    # Verify multi-region
    mr_f = next(f for f in findings if f.title == "CloudTrail is Not Multi-Region")
    assert mr_f.severity == "HIGH"
    
    # Verify S3 config
    s3_f = next(f for f in findings if f.title == "CloudTrail Trail Has No S3 Bucket Configured")
    assert s3_f.severity == "HIGH"
    
    # Verify log validation
    val_f = next(f for f in findings if f.title == "CloudTrail Log File Validation is Disabled")
    assert val_f.severity == "MEDIUM"
