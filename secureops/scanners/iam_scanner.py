from datetime import datetime, timezone
import botocore.exceptions
from secureops.core.models import Finding
from secureops.core.errors import create_permission_finding, sanitize_error

def scan_iam(session) -> list[Finding]:
    """
    Scans IAM posture on AWS. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list[Finding]: A list of Finding objects representing security issues.
    """
    findings: list[Finding] = []
    
    try:
        client = session.client("iam")
    except Exception as e:
        findings.append(Finding(
            service="IAM",
            severity="CRITICAL",
            title="Could Not Initialize IAM Client",
            resource="IAM Service",
            evidence=sanitize_error(e),
            recommendation="Verify your AWS session, credentials, and region config."
        ))
        return findings

    # F. Check account summary (Root MFA status)
    try:
        summary = client.get_account_summary()
        summary_map = summary.get("SummaryMap", {})
        mfa_enabled = summary_map.get("AccountMFAEnabled", 0)
        if mfa_enabled == 0:
            findings.append(Finding(
                service="IAM",
                severity="CRITICAL",
                title="Root Account MFA Missing",
                resource="Root Account",
                evidence="AccountMFAEnabled is 0",
                recommendation="Enable Multi-Factor Authentication (MFA) on the root account immediately."
            ))
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append(create_permission_finding(
                service="IAM",
                operation="Get Account Summary",
                resource="Account Summary",
                required_permission="iam:GetAccountSummary",
                error=e,
                severity="MEDIUM"
            ))
        else:
            findings.append(Finding(
                service="IAM",
                severity="MEDIUM",
                title="Could Not Retrieve Account Summary",
                resource="Account Summary",
                evidence=sanitize_error(e),
                recommendation="Ensure the scanner identity has 'iam:GetAccountSummary' permissions."
            ))
    except Exception as e:
        findings.append(Finding(
            service="IAM",
            severity="MEDIUM",
            title="Could Not Retrieve Account Summary",
            resource="Account Summary",
            evidence=sanitize_error(e),
            recommendation="Ensure the scanner identity has 'iam:GetAccountSummary' permissions."
        ))

    # A. List all IAM users
    users = []
    try:
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            users.extend(page.get('Users', []))
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append(create_permission_finding(
                service="IAM",
                operation="List IAM Users",
                resource="IAM Users List",
                required_permission="iam:ListUsers",
                error=e,
                severity="HIGH"
            ))
        else:
            findings.append(Finding(
                service="IAM",
                severity="HIGH",
                title="Could Not List IAM Users",
                resource="IAM Users List",
                evidence=sanitize_error(e),
                recommendation="Ensure the scanner identity has 'iam:ListUsers' permissions."
            ))
        return findings
    except Exception as e:
        findings.append(Finding(
            service="IAM",
            severity="HIGH",
            title="Could Not List IAM Users",
            resource="IAM Users List",
            evidence=sanitize_error(e),
            recommendation="Ensure the scanner identity has 'iam:ListUsers' permissions."
        ))
        return findings

    # Scan each user
    for user in users:
        username = user['UserName']
        
        # B. Check if MFA devices exist
        try:
            # Check if user has console access
            has_console_access = False
            try:
                client.get_login_profile(UserName=username)
                has_console_access = True
            except client.exceptions.NoSuchEntityException:
                has_console_access = False
            except botocore.exceptions.ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'NoSuchEntity':
                    has_console_access = False
                else:
                    raise e
            
            if has_console_access:
                mfa = client.list_mfa_devices(UserName=username)
                if not mfa.get('MFADevices', []):
                    findings.append(Finding(
                        service="IAM",
                        severity="MEDIUM",
                        title="MFA Not Enabled for User",
                        resource=f"User: {username}",
                        evidence="User has AWS Console access but no MFA devices configured.",
                        recommendation="Require this user to configure Multi-Factor Authentication (MFA) for AWS Console login."
                    ))
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                findings.append(create_permission_finding(
                    service="IAM",
                    operation=f"List MFA Devices for User {username}",
                    resource=f"User: {username}",
                    required_permission="iam:ListMFADevices",
                    error=e,
                    severity="LOW"
                ))
            else:
                findings.append(Finding(
                    service="IAM",
                    severity="LOW",
                    title="Could Not List MFA Devices for User",
                    resource=f"User: {username}",
                    evidence=sanitize_error(e),
                    recommendation="Ensure the scanner identity has 'iam:ListMFADevices' and 'iam:GetLoginProfile' permissions."
                ))
        except Exception as e:
            findings.append(Finding(
                service="IAM",
                severity="LOW",
                title="Could Not List MFA Devices for User",
                resource=f"User: {username}",
                evidence=sanitize_error(e),
                recommendation="Ensure the scanner identity has 'iam:ListMFADevices' and 'iam:GetLoginProfile' permissions."
            ))

        # C & D. Check Access Keys and Key Age
        try:
            keys = client.list_access_keys(UserName=username)
            metadata = keys.get('AccessKeyMetadata', [])
            active_keys = [k for k in metadata if k.get('Status') == 'Active']
            if active_keys:
                findings.append(Finding(
                    service="IAM",
                    severity="LOW",
                    title="Active Access Keys Found",
                    resource=f"User: {username}",
                    evidence=f"User has {len(active_keys)} active access key(s).",
                    recommendation="Verify if programmatic access is necessary for this user. Deactivate/delete if unused."
                ))

                # Check age for each active key
                for key in active_keys:
                    create_date = key['CreateDate']
                    age_days = (datetime.now(timezone.utc) - create_date).days
                    if age_days > 90:
                        findings.append(Finding(
                            service="IAM",
                            severity="HIGH",
                            title="Access Key Older Than 90 Days",
                            resource=f"User: {username}",
                            evidence=f"Access key age is {age_days} days (Created: {create_date.strftime('%Y-%m-%d')}).",
                            recommendation="Rotate programmatic access keys every 90 days."
                        ))
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                findings.append(create_permission_finding(
                    service="IAM",
                    operation=f"List Access Keys for User {username}",
                    resource=f"User: {username}",
                    required_permission="iam:ListAccessKeys",
                    error=e,
                    severity="LOW"
                ))
            else:
                findings.append(Finding(
                    service="IAM",
                    severity="LOW",
                    title="Could Not List Access Keys for User",
                    resource=f"User: {username}",
                    evidence=sanitize_error(e),
                    recommendation="Ensure the scanner identity has 'iam:ListAccessKeys' permissions."
                ))
        except Exception as e:
            findings.append(Finding(
                service="IAM",
                severity="LOW",
                title="Could Not List Access Keys for User",
                resource=f"User: {username}",
                evidence=sanitize_error(e),
                recommendation="Ensure the scanner identity has 'iam:ListAccessKeys' permissions."
            ))

        # E. Check for AdministratorAccess directly attached
        try:
            policies = client.list_attached_user_policies(UserName=username)
            attached = policies.get('AttachedPolicies', [])
            for policy in attached:
                if policy['PolicyArn'] == 'arn:aws:iam::aws:policy/AdministratorAccess':
                    findings.append(Finding(
                        service="IAM",
                        severity="HIGH",
                        title="Directly Attached AdministratorAccess Policy",
                        resource=f"User: {username}",
                        evidence="AdministratorAccess policy is directly attached to the user.",
                        recommendation="Remove policies directly attached to users. Assign policies to IAM groups/roles instead."
                    ))
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                findings.append(create_permission_finding(
                    service="IAM",
                    operation=f"List Attached User Policies for User {username}",
                    resource=f"User: {username}",
                    required_permission="iam:ListAttachedUserPolicies",
                    error=e,
                    severity="LOW"
                ))
            else:
                findings.append(Finding(
                    service="IAM",
                    severity="LOW",
                    title="Could Not List Attached Policies for User",
                    resource=f"User: {username}",
                    evidence=sanitize_error(e),
                    recommendation="Ensure the scanner identity has 'iam:ListAttachedUserPolicies' permissions."
                ))
        except Exception as e:
            findings.append(Finding(
                service="IAM",
                severity="LOW",
                title="Could Not List Attached Policies for User",
                resource=f"User: {username}",
                evidence=sanitize_error(e),
                recommendation="Ensure the scanner identity has 'iam:ListAttachedUserPolicies' permissions."
            ))

    return findings
