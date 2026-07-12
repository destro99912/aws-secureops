import pytest
import boto3
from datetime import datetime
from botocore.stub import Stubber
from secureops.scanners.kms_scanner import scan_kms


def test_kms_scanner_client_init_error():
    """
    Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("KMS init error")

    session = FailSession()
    findings = scan_kms(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "KMS"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize KMS Client"


def test_kms_scanner_permission_denied():
    """
    Test list_keys permission denied maps to high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("kms")
    stubber = Stubber(client)
    
    stubber.add_client_error(
        "list_keys",
        service_error_code="AccessDeniedException",
        service_message="Access Denied"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_kms(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "KMS"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "List Keys" in findings[0].title


def test_kms_scanner_no_findings():
    """
    Test clean KMS state (Customer key exists, Enabled, and rotation is enabled).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("kms")
    stubber = Stubber(client)
    
    # 1. list_keys
    stubber.add_response("list_keys", {"Keys": [{"KeyId": "key-1", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-1"}]})
    
    # 2. describe_key
    stubber.add_response(
        "describe_key",
        {
            "KeyMetadata": {
                "KeyId": "key-1",
                "Arn": "arn:aws:kms:us-east-1:123:key/key-1",
                "CreationDate": datetime.now(),
                "Enabled": True,
                "Description": "Test Key",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "KeyManager": "CUSTOMER",
                "Origin": "AWS_KMS",
                "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT"
            }
        }
    )
    
    # 3. get_key_rotation_status (Enabled)
    stubber.add_response("get_key_rotation_status", {"KeyRotationEnabled": True})
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_kms(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 0


def test_kms_scanner_positive_findings():
    """
    Test finding triggers for key disabled, scheduled for deletion, and key rotation disabled.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("kms")
    stubber = Stubber(client)
    
    # 1. list_keys (has 3 keys)
    stubber.add_response(
        "list_keys",
        {
            "Keys": [
                {"KeyId": "key-disabled", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-disabled"},
                {"KeyId": "key-deletion", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-deletion"},
                {"KeyId": "key-norotation", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-norotation"}
            ]
        }
    )
    
    # Key 1: Disabled
    stubber.add_response(
        "describe_key",
        {
            "KeyMetadata": {
                "KeyId": "key-disabled",
                "Arn": "arn:aws:kms:us-east-1:123:key/key-disabled",
                "CreationDate": datetime.now(),
                "Enabled": False,
                "Description": "Disabled Key",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Disabled",
                "KeyManager": "CUSTOMER",
                "Origin": "AWS_KMS",
                "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT"
            }
        }
    )
    
    # Key 2: PendingDeletion
    stubber.add_response(
        "describe_key",
        {
            "KeyMetadata": {
                "KeyId": "key-deletion",
                "Arn": "arn:aws:kms:us-east-1:123:key/key-deletion",
                "CreationDate": datetime.now(),
                "Enabled": False,
                "Description": "Deleted Key",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "PendingDeletion",
                "KeyManager": "CUSTOMER",
                "Origin": "AWS_KMS",
                "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT"
            }
        }
    )
    
    # Key 3: Enabled but No Rotation
    stubber.add_response(
        "describe_key",
        {
            "KeyMetadata": {
                "KeyId": "key-norotation",
                "Arn": "arn:aws:kms:us-east-1:123:key/key-norotation",
                "CreationDate": datetime.now(),
                "Enabled": True,
                "Description": "No Rotation Key",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "KeyManager": "CUSTOMER",
                "Origin": "AWS_KMS",
                "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT"
            }
        }
    )
    stubber.add_response("get_key_rotation_status", {"KeyRotationEnabled": False})
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_kms(session)
    stubber.assert_no_pending_responses()
    
    # Expected: 3 findings
    assert len(findings) == 3
    
    disabled_f = next(f for f in findings if f.title == "KMS Key Disabled")
    assert disabled_f.severity == "HIGH"
    
    deletion_f = next(f for f in findings if f.title == "KMS Key Scheduled For Deletion")
    assert deletion_f.severity == "HIGH"
    
    rotation_f = next(f for f in findings if f.title == "KMS Key Rotation Disabled")
    assert rotation_f.severity == "MEDIUM"
