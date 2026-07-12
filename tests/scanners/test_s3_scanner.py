import pytest
import boto3
from botocore.stub import Stubber
from secureops.scanners.s3_scanner import scan_s3


def test_s3_scanner_client_init_error():
    """
    Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("S3 client init error")

    session = FailSession()
    findings = scan_s3(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "S3"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize S3 Client"


def test_s3_scanner_permission_denied():
    """
    Test list buckets permission denied maps to high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("s3")
    stubber = Stubber(client)
    
    stubber.add_client_error(
        "list_buckets",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_s3(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "S3"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "List S3 Buckets" in findings[0].title


def test_s3_scanner_no_findings():
    """
    Test a clean S3 bucket state (Fully blocked public access, Encryption enabled, Versioning enabled, Policy not public).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("s3")
    stubber = Stubber(client)
    
    # 1. list_buckets
    stubber.add_response(
        "list_buckets",
        {"Buckets": [{"Name": "secure-bucket"}]}
    )
    
    # 2. get_public_access_block (all True)
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
    )
    
    # 3. get_bucket_encryption (SSE enabled)
    stubber.add_response(
        "get_bucket_encryption",
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
    )
    
    # 4. get_bucket_versioning (Enabled)
    stubber.add_response(
        "get_bucket_versioning",
        {"Status": "Enabled"}
    )
    
    # 5. get_bucket_policy_status (IsPublic=False)
    stubber.add_response(
        "get_bucket_policy_status",
        {"PolicyStatus": {"IsPublic": False}}
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_s3(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 0


def test_s3_scanner_positive_findings():
    """
    Test that missing Public Access Block, missing encryption, disabled versioning, and public bucket policy are flagged.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("s3")
    stubber = Stubber(client)
    
    # 1. list_buckets
    stubber.add_response(
        "list_buckets",
        {"Buckets": [{"Name": "risk-bucket"}]}
    )
    
    # 2. get_public_access_block throws NoSuchPublicAccessBlockConfiguration (Missing configuration)
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        service_message="No PAB configuration"
    )
    
    # 3. get_bucket_encryption throws ServerSideEncryptionConfigurationNotFoundError
    stubber.add_client_error(
        "get_bucket_encryption",
        service_error_code="ServerSideEncryptionConfigurationNotFoundError",
        service_message="Encryption not found"
    )
    
    # 4. get_bucket_versioning (returns empty status/Suspended)
    stubber.add_response(
        "get_bucket_versioning",
        {"Status": "Suspended"}
    )
    
    # 5. get_bucket_policy_status (IsPublic=True)
    stubber.add_response(
        "get_bucket_policy_status",
        {"PolicyStatus": {"IsPublic": True}}
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_s3(session)
    stubber.assert_no_pending_responses()
    
    # Expected findings:
    # 1. Public Access Block is Missing (HIGH)
    # 2. Default Encryption is Missing (MEDIUM)
    # 3. Versioning is Disabled (LOW)
    # 4. Bucket Policy Allows Public Access (CRITICAL)
    assert len(findings) == 4
    
    # Verify PAB
    pab_f = next(f for f in findings if f.title == "Public Access Block is Missing")
    assert pab_f.severity == "HIGH"
    
    # Verify Encryption
    enc_f = next(f for f in findings if f.title == "Default Encryption is Missing")
    assert enc_f.severity == "MEDIUM"
    
    # Verify Versioning
    ver_f = next(f for f in findings if f.title == "Versioning is Disabled")
    assert ver_f.severity == "LOW"
    
    # Verify Public policy
    policy_f = next(f for f in findings if f.title == "Bucket Policy Allows Public Access")
    assert policy_f.severity == "CRITICAL"
