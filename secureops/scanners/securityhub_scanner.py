import botocore.exceptions

def scan_securityhub(session):
    """
    Scans Security Hub status and active findings. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list: A list of dict findings representing security issues.
    """
    findings = []
    
    try:
        client = session.client("securityhub")
    except Exception as e:
        findings.append({
            "service": "SecurityHub",
            "severity": "CRITICAL",
            "title": "Could Not Initialize Security Hub Client",
            "resource": "Security Hub Service",
            "evidence": str(e),
            "recommendation": "Verify your AWS session, credentials, and region config."
        })
        return findings

    # Check if Security Hub is enabled
    is_enabled = False
    try:
        client.describe_hub()
        is_enabled = True
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("InvalidAccessException", "ResourceNotFoundException", "SubscriptionRequiredException"):
            findings.append({
                "service": "SecurityHub",
                "severity": "CRITICAL",
                "title": "Security Hub Not Enabled",
                "resource": "Security Hub Config",
                "evidence": f"Security Hub is not enabled or subscribed in this region ({error_code}).",
                "recommendation": "Enable AWS Security Hub to centralize security alerts and compliance checks."
            })
            return findings
        elif error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "service": "SecurityHub",
                "severity": "HIGH",
                "title": "Access Denied: Describe Hub",
                "resource": "Security Hub Config",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'securityhub:DescribeHub' permissions."
            })
            return findings
        else:
            findings.append({
                "service": "SecurityHub",
                "severity": "MEDIUM",
                "title": "Could Not Describe Security Hub Status",
                "resource": "Security Hub Config",
                "evidence": str(e),
                "recommendation": "Investigate Security Hub service configuration and permissions."
            })
            return findings
    except Exception as e:
        findings.append({
            "service": "SecurityHub",
            "severity": "MEDIUM",
            "title": "Could Not Describe Security Hub Status",
            "resource": "Security Hub Config",
            "evidence": str(e),
            "recommendation": "Investigate errors accessing Security Hub."
        })
        return findings

    # Retrieve active findings
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    try:
        paginator = client.get_paginator('get_findings')
        filters = {
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }
        for page in paginator.paginate(Filters=filters):
            for finding in page.get('Findings', []):
                severity_info = finding.get('Severity', {})
                label = severity_info.get('Label')
                if label in counts:
                    counts[label] += 1
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "service": "SecurityHub",
                "severity": "HIGH",
                "title": "Access Denied: Get Findings",
                "resource": "Security Hub Findings",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'securityhub:GetFindings' permissions."
            })
        else:
            findings.append({
                "service": "SecurityHub",
                "severity": "MEDIUM",
                "title": "Could Not Retrieve Security Hub Findings",
                "resource": "Security Hub Findings",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has correct Security Hub permissions."
            })
        return findings
    except Exception as e:
        findings.append({
            "service": "SecurityHub",
            "severity": "MEDIUM",
            "title": "Could Not Retrieve Security Hub Findings",
            "resource": "Security Hub Findings",
            "evidence": str(e),
            "recommendation": "Investigate errors retrieving Security Hub findings."
        })
        return findings

    # Add findings for active issues by severity if count > 0
    if counts["CRITICAL"] > 0:
        findings.append({
            "service": "SecurityHub",
            "severity": "CRITICAL",
            "title": "Active CRITICAL Security Hub Findings Exist",
            "resource": "Security Hub Findings",
            "evidence": f"CRITICAL: {counts['CRITICAL']} active Security Hub finding(s)",
            "recommendation": "Investigate and remediate CRITICAL Security Hub findings immediately."
        })
        
    if counts["HIGH"] > 0:
        findings.append({
            "service": "SecurityHub",
            "severity": "HIGH",
            "title": "Active HIGH Security Hub Findings Exist",
            "resource": "Security Hub Findings",
            "evidence": f"HIGH: {counts['HIGH']} active Security Hub finding(s)",
            "recommendation": "Address HIGH severity Security Hub findings as soon as possible."
        })
        
    if counts["MEDIUM"] > 0:
        findings.append({
            "service": "SecurityHub",
            "severity": "MEDIUM",
            "title": "Active MEDIUM Security Hub Findings Exist",
            "resource": "Security Hub Findings",
            "evidence": f"MEDIUM: {counts['MEDIUM']} active Security Hub finding(s)",
            "recommendation": "Review and schedule remediation for MEDIUM severity Security Hub findings."
        })
        
    if counts["LOW"] > 0:
        findings.append({
            "service": "SecurityHub",
            "severity": "LOW",
            "title": "Active LOW Security Hub Findings Exist",
            "resource": "Security Hub Findings",
            "evidence": f"LOW: {counts['LOW']} active Security Hub finding(s)",
            "recommendation": "Monitor and address LOW severity Security Hub findings during standard maintenance windows."
        })

    return findings
