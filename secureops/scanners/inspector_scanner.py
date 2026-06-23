import botocore.exceptions

def scan_inspector(session):
    """
    Scans Amazon Inspector status and active findings. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list: A list of dict findings representing security issues.
    """
    findings = []
    
    try:
        client = session.client("inspector2")
    except Exception as e:
        findings.append({
            "service": "Inspector",
            "severity": "CRITICAL",
            "title": "Could Not Initialize Inspector Client",
            "resource": "Amazon Inspector Service",
            "evidence": str(e),
            "recommendation": "Verify your AWS session, credentials, and region config."
        })
        return findings

    # Retrieve current Account ID using STS
    account_id = None
    try:
        sts_client = session.client("sts")
        identity = sts_client.get_caller_identity()
        account_id = identity.get("Account")
    except Exception as e:
        # Fallback if STS calls fail, but we'll try to proceed
        pass

    # Check if Inspector is enabled
    is_enabled = False
    try:
        if account_id:
            status_response = client.batch_get_account_status(accountIds=[account_id])
            accounts = status_response.get("accounts", [])
            for account in accounts:
                if account.get("accountId") == account_id:
                    status = account.get("state", {}).get("status")
                    if status == "ENABLED":
                        is_enabled = True
        else:
            # Fallback check if account_id couldn't be retrieved
            status_response = client.batch_get_account_status(accountIds=[])
            is_enabled = True
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "service": "Inspector",
                "severity": "HIGH",
                "title": "Access Denied: Batch Get Account Status",
                "resource": "Amazon Inspector Config",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'inspector2:BatchGetAccountStatus' permissions."
            })
            return findings
        elif error_code in ("ResourceNotFoundException", "ValidationException", "SubscriptionRequiredException"):
            findings.append({
                "service": "Inspector",
                "severity": "CRITICAL",
                "title": "Amazon Inspector Not Enabled",
                "resource": "Amazon Inspector Config",
                "evidence": f"Inspector is not enabled/subscribed in this region ({error_code}).",
                "recommendation": "Enable Amazon Inspector to start automated vulnerability management."
            })
            return findings
        else:
            findings.append({
                "service": "Inspector",
                "severity": "MEDIUM",
                "title": "Could Not Retrieve Inspector Status",
                "resource": "Amazon Inspector Config",
                "evidence": str(e),
                "recommendation": "Investigate Amazon Inspector configuration and permissions."
            })
            return findings
    except Exception as e:
        findings.append({
            "service": "Inspector",
            "severity": "MEDIUM",
            "title": "Could Not Retrieve Inspector Status",
            "resource": "Amazon Inspector Config",
            "evidence": str(e),
            "recommendation": "Investigate errors accessing Amazon Inspector."
        })
        return findings

    # If status check succeeded but state is not ENABLED
    if not is_enabled:
        findings.append({
            "service": "Inspector",
            "severity": "CRITICAL",
            "title": "Amazon Inspector Not Enabled",
            "resource": "Amazon Inspector Config",
            "evidence": "Amazon Inspector status is not ENABLED for this account.",
            "recommendation": "Enable Amazon Inspector in the AWS console to monitor resources."
        })
        return findings

    # Retrieve active findings
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    try:
        paginator = client.get_paginator('list_findings')
        filter_criteria = {
            'findingStatus': [
                {'comparison': 'EQUALS', 'value': 'ACTIVE'}
            ]
        }
        for page in paginator.paginate(filterCriteria=filter_criteria):
            for finding in page.get('findings', []):
                sev = finding.get('severity')
                if sev in counts:
                    counts[sev] += 1
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "service": "Inspector",
                "severity": "HIGH",
                "title": "Access Denied: List Findings",
                "resource": "Amazon Inspector Findings",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'inspector2:ListFindings' permissions."
            })
        else:
            findings.append({
                "service": "Inspector",
                "severity": "MEDIUM",
                "title": "Could Not Retrieve Inspector Findings",
                "resource": "Amazon Inspector Findings",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has correct Amazon Inspector permissions."
            })
        return findings
    except Exception as e:
        findings.append({
            "service": "Inspector",
            "severity": "MEDIUM",
            "title": "Could Not Retrieve Inspector Findings",
            "resource": "Amazon Inspector Findings",
            "evidence": str(e),
            "recommendation": "Investigate errors retrieving Amazon Inspector findings."
        })
        return findings

    # Add findings for active issues by severity if count > 0
    if counts["CRITICAL"] > 0:
        findings.append({
            "service": "Inspector",
            "severity": "CRITICAL",
            "title": "Active CRITICAL Inspector Findings Exist",
            "resource": "Amazon Inspector Findings",
            "evidence": f"CRITICAL: {counts['CRITICAL']} active Inspector finding(s)",
            "recommendation": "Remediate critical vulnerabilities identified by Amazon Inspector immediately."
        })
        
    if counts["HIGH"] > 0:
        findings.append({
            "service": "Inspector",
            "severity": "HIGH",
            "title": "Active HIGH Inspector Findings Exist",
            "resource": "Amazon Inspector Findings",
            "evidence": f"HIGH: {counts['HIGH']} active Inspector finding(s)",
            "recommendation": "Address high severity vulnerabilities identified by Amazon Inspector."
        })
        
    if counts["MEDIUM"] > 0:
        findings.append({
            "service": "Inspector",
            "severity": "MEDIUM",
            "title": "Active MEDIUM Inspector Findings Exist",
            "resource": "Amazon Inspector Findings",
            "evidence": f"MEDIUM: {counts['MEDIUM']} active Inspector finding(s)",
            "recommendation": "Review and patch medium severity vulnerabilities identified by Amazon Inspector."
        })
        
    if counts["LOW"] > 0:
        findings.append({
            "service": "Inspector",
            "severity": "LOW",
            "title": "Active LOW Inspector Findings Exist",
            "resource": "Amazon Inspector Findings",
            "evidence": f"LOW: {counts['LOW']} active Inspector finding(s)",
            "recommendation": "Review low severity vulnerabilities identified by Amazon Inspector during routine cycles."
        })

    return findings
