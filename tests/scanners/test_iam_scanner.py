import pytest
import boto3
from datetime import datetime, timezone, timedelta
from botocore.stub import Stubber
from secureops.scanners.iam_scanner import scan_iam


def test_iam_scanner_client_init_error():
    """
    Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("IAM failure")

    session = FailSession()
    findings = scan_iam(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "IAM"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize IAM Client"


def test_iam_scanner_permission_denied():
    """
    Test permission denied when listing users is mapped to high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("iam")
    stubber = Stubber(client)
    
    # get_account_summary succeeds (MFA enabled)
    stubber.add_response(
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1}}
    )
    
    # list_users raises AccessDenied
    stubber.add_client_error(
        "list_users",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_iam(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "IAM"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "List IAM Users" in findings[0].title


def test_iam_scanner_no_findings():
    """
    Test a clean IAM state (Root MFA active, users exist with console login MFA, no keys, no direct admin policy).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("iam")
    stubber = Stubber(client)
    
    # Root MFA enabled
    stubber.add_response(
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1}}
    )
    
    # Users list (1 user)
    stubber.add_response(
        "list_users",
        {"Users": [{"UserName": "clean-user", "UserId": "AIDAQRSTUVWXYZEXAMPLE", "Path": "/", "Arn": "arn:aws:iam::123:user/clean-user", "CreateDate": datetime.now()}]}
    )
    
    # get_login_profile fails with NoSuchEntity (no console access, meaning programmatic only, so MFA isn't flagged as missing console-mfa)
    stubber.add_client_error(
        "get_login_profile",
        service_error_code="NoSuchEntity",
        service_message="No Login Profile"
    )
    
    # list_access_keys (empty)
    stubber.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": []}
    )
    
    # list_attached_user_policies (empty)
    stubber.add_response(
        "list_attached_user_policies",
        {"AttachedPolicies": []}
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_iam(session)
    stubber.assert_no_pending_responses()
    
    # Should have no findings
    assert len(findings) == 0


def test_iam_scanner_positive_findings():
    """
    Test that Root MFA missing, directly attached Admin policy, old access key, and active key warnings are triggered.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("iam")
    stubber = Stubber(client)
    
    # 1. Root MFA missing (AccountMFAEnabled=0)
    stubber.add_response(
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 0}}
    )
    
    # 2. List Users (1 user: 'risk-user')
    stubber.add_response(
        "list_users",
        {"Users": [{"UserName": "risk-user", "UserId": "AIDAQRSTUVWXYZEXAMPLE", "Path": "/", "Arn": "arn:aws:iam::123:user/risk-user", "CreateDate": datetime.now()}]}
    )
    
    # 3. get_login_profile succeeds (user has console access)
    stubber.add_response(
        "get_login_profile",
        {"LoginProfile": {"UserName": "risk-user", "CreateDate": datetime.now()}}
    )
    
    # 4. list_mfa_devices is empty (missing MFA finding)
    stubber.add_response(
        "list_mfa_devices",
        {"MFADevices": []}
    )
    
    # 5. list_access_keys (has a key older than 90 days)
    old_date = datetime.now(timezone.utc) - timedelta(days=95)
    stubber.add_response(
        "list_access_keys",
        {
            "AccessKeyMetadata": [
                {
                    "UserName": "risk-user",
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "Status": "Active",
                    "CreateDate": old_date
                }
            ]
        }
    )
    
    # 6. list_attached_user_policies (has directly attached AdministratorAccess policy)
    stubber.add_response(
        "list_attached_user_policies",
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
                }
            ]
        }
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_iam(session)
    stubber.assert_no_pending_responses()
    
    # Expected findings:
    # 1. Root Account MFA Missing (CRITICAL)
    # 2. MFA Not Enabled for User (MEDIUM)
    # 3. Active Access Keys Found (LOW)
    # 4. Access Key Older Than 90 Days (HIGH)
    # 5. Directly Attached AdministratorAccess Policy (HIGH)
    assert len(findings) == 5
    
    # Verify Root MFA
    root_f = next(f for f in findings if f.title == "Root Account MFA Missing")
    assert root_f.severity == "CRITICAL"
    
    # Verify Console MFA
    mfa_f = next(f for f in findings if f.title == "MFA Not Enabled for User")
    assert mfa_f.severity == "MEDIUM"
    
    # Verify Active Keys
    active_key_f = next(f for f in findings if f.title == "Active Access Keys Found")
    assert active_key_f.severity == "LOW"
    
    # Verify Old Key
    old_key_f = next(f for f in findings if f.title == "Access Key Older Than 90 Days")
    assert old_key_f.severity == "HIGH"
    
    # Verify Direct Admin policy
    admin_policy_f = next(f for f in findings if f.title == "Directly Attached AdministratorAccess Policy")
    assert admin_policy_f.severity == "HIGH"
