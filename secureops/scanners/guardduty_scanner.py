import botocore.exceptions

def scan_guardduty(session):
    """
    Scans GuardDuty findings and detector status. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list: A list of dict findings representing security issues.
    """
    findings = []
    
    try:
        client = session.client("guardduty")
    except Exception as e:
        findings.append({
            "service": "GuardDuty",
            "severity": "CRITICAL",
            "title": "Could Not Initialize GuardDuty Client",
            "resource": "GuardDuty Service",
            "evidence": str(e),
            "recommendation": "Verify your AWS session, credentials, and region config."
        })
        return findings

    detector_ids = []
    try:
        response = client.list_detectors()
        detector_ids = response.get("DetectorIds", [])
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "service": "GuardDuty",
                "severity": "HIGH",
                "title": "Access Denied: List Detectors",
                "resource": "GuardDuty Detectors",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'guardduty:ListDetectors' permissions."
            })
            return findings
        elif error_code == "SubscriptionRequiredException":
            findings.append({
                "service": "GuardDuty",
                "severity": "CRITICAL",
                "title": "GuardDuty Not Enabled",
                "resource": "GuardDuty Config",
                "evidence": "GuardDuty is not subscribed or enabled (SubscriptionRequiredException).",
                "recommendation": "Enable Amazon GuardDuty to start monitoring for threats in your account."
            })
            return findings
        else:
            findings.append({
                "service": "GuardDuty",
                "severity": "MEDIUM",
                "title": "Could Not List GuardDuty Detectors",
                "resource": "GuardDuty Detectors",
                "evidence": str(e),
                "recommendation": "Investigate permissions or configurations for GuardDuty."
            })
            return findings
    except Exception as e:
        findings.append({
            "service": "GuardDuty",
            "severity": "MEDIUM",
            "title": "Could Not List GuardDuty Detectors",
            "resource": "GuardDuty Detectors",
            "evidence": str(e),
            "recommendation": "Investigate errors listing GuardDuty detectors."
        })
        return findings

    # 1. GuardDuty not enabled
    if not detector_ids:
        findings.append({
            "service": "GuardDuty",
            "severity": "CRITICAL",
            "title": "GuardDuty Not Enabled",
            "resource": "GuardDuty Config",
            "evidence": "No GuardDuty detectors found in this region.",
            "recommendation": "Enable Amazon GuardDuty to start monitoring for threats in your account."
        })
        return findings

    # For active detectors, retrieve findings
    total_high = 0
    total_medium = 0
    total_low = 0
    
    for detector_id in detector_ids:
        finding_ids = []
        try:
            paginator = client.get_paginator('list_findings')
            for page in paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={'Criterion': {'service.archived': {'Eq': ['false']}}}
            ):
                finding_ids.extend(page.get('FindingIds', []))
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                findings.append({
                    "service": "GuardDuty",
                    "severity": "HIGH",
                    "title": "Access Denied: List Findings",
                    "resource": f"Detector: {detector_id}",
                    "evidence": str(e),
                    "recommendation": "Ensure the scanner identity has 'guardduty:ListFindings' permissions."
                })
                continue
            else:
                findings.append({
                    "service": "GuardDuty",
                    "severity": "MEDIUM",
                    "title": "Could Not List GuardDuty Findings",
                    "resource": f"Detector: {detector_id}",
                    "evidence": str(e),
                    "recommendation": "Investigate errors listing findings for this detector."
                })
                continue
        except Exception as e:
            findings.append({
                "service": "GuardDuty",
                "severity": "MEDIUM",
                "title": "Could Not List GuardDuty Findings",
                "resource": f"Detector: {detector_id}",
                "evidence": str(e),
                "recommendation": "Investigate errors listing findings for this detector."
            })
            continue

        if not finding_ids:
            continue

        # Fetch findings details in batches of 50
        findings_details = []
        try:
            for i in range(0, len(finding_ids), 50):
                batch_ids = finding_ids[i:i+50]
                res = client.get_findings(DetectorId=detector_id, FindingIds=batch_ids)
                findings_details.extend(res.get('Findings', []))
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                findings.append({
                    "service": "GuardDuty",
                    "severity": "HIGH",
                    "title": "Access Denied: Get Findings",
                    "resource": f"Detector: {detector_id}",
                    "evidence": str(e),
                    "recommendation": "Ensure the scanner identity has 'guardduty:GetFindings' permissions."
                })
                continue
            else:
                findings.append({
                    "service": "GuardDuty",
                    "severity": "MEDIUM",
                    "title": "Could Not Retrieve GuardDuty Findings Details",
                    "resource": f"Detector: {detector_id}",
                    "evidence": str(e),
                    "recommendation": "Investigate errors retrieving details for GuardDuty findings."
                })
                continue
        except Exception as e:
            findings.append({
                "service": "GuardDuty",
                "severity": "MEDIUM",
                "title": "Could Not Retrieve GuardDuty Findings Details",
                "resource": f"Detector: {detector_id}",
                "evidence": str(e),
                "recommendation": "Investigate errors retrieving details for GuardDuty findings."
            })
            continue

        for finding in findings_details:
            severity = finding.get('Severity', 0.0)
            if severity >= 7.0:
                total_high += 1
            elif severity >= 4.0:
                total_medium += 1
            else:
                total_low += 1

    # 2. Active HIGH severity GuardDuty findings
    if total_high > 0:
        findings.append({
            "service": "GuardDuty",
            "severity": "HIGH",
            "title": "Active High Severity GuardDuty Findings",
            "resource": "GuardDuty Detector",
            "evidence": f"Found {total_high} active high severity finding(s).",
            "recommendation": "Investigate and resolve high severity GuardDuty findings immediately in the AWS Console."
        })

    # 3. Active MEDIUM severity GuardDuty findings
    if total_medium > 0:
        findings.append({
            "service": "GuardDuty",
            "severity": "MEDIUM",
            "title": "Active Medium Severity GuardDuty Findings",
            "resource": "GuardDuty Detector",
            "evidence": f"Found {total_medium} active medium severity finding(s).",
            "recommendation": "Review and address active medium severity GuardDuty findings."
        })

    # 4. Active LOW severity GuardDuty findings
    if total_low > 0:
        findings.append({
            "service": "GuardDuty",
            "severity": "LOW",
            "title": "Active Low Severity GuardDuty Findings",
            "resource": "GuardDuty Detector",
            "evidence": f"Found {total_low} active low severity finding(s).",
            "recommendation": "Review low severity GuardDuty findings during routine security maintenance."
        })

    return findings
