import botocore.exceptions

def scan_cloudtrail(session):
    """
    Scans CloudTrail posture on AWS. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list: A list of dict findings representing security issues.
    """
    findings = []
    
    try:
        client = session.client("cloudtrail")
    except Exception as e:
        findings.append({
            "service": "CloudTrail",
            "severity": "CRITICAL",
            "title": "Could Not Initialize CloudTrail Client",
            "resource": "CloudTrail Service",
            "evidence": str(e),
            "recommendation": "Verify your AWS session, credentials, and region config."
        })
        return findings

    # Describe trails
    try:
        response = client.describe_trails()
        trails = response.get("trailList", [])
    except Exception as e:
        findings.append({
            "service": "CloudTrail",
            "severity": "HIGH",
            "title": "Could Not Describe CloudTrails",
            "resource": "CloudTrail Service",
            "evidence": str(e),
            "recommendation": "Ensure the scanner identity has 'cloudtrail:DescribeTrails' permissions."
        })
        return findings

    # 1. No CloudTrail trail exists -> CRITICAL
    if not trails:
        findings.append({
            "service": "CloudTrail",
            "severity": "CRITICAL",
            "title": "No CloudTrail Trails Found",
            "resource": "CloudTrail Config",
            "evidence": "No trails are configured in this region.",
            "recommendation": "Create at least one multi-region CloudTrail to record all account activities."
        })
        return findings

    for trail in trails:
        trail_name = trail.get("Name")
        trail_arn = trail.get("TrailARN", trail_name)
        
        # 2. Trail exists but logging is stopped -> CRITICAL
        try:
            status = client.get_trail_status(Name=trail_arn)
            is_logging = status.get("IsLogging", False)
            if not is_logging:
                findings.append({
                    "service": "CloudTrail",
                    "severity": "CRITICAL",
                    "title": "CloudTrail Logging is Stopped",
                    "resource": trail_name,
                    "evidence": "IsLogging status is False.",
                    "recommendation": "Start logging on the trail immediately to resume auditing and capturing events."
                })
        except Exception as e:
            findings.append({
                "service": "CloudTrail",
                "severity": "LOW",
                "title": "Could Not Retrieve CloudTrail Status",
                "resource": trail_name,
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'cloudtrail:GetTrailStatus' permissions."
            })

        # 3. Trail is not multi-region -> HIGH
        is_multi_region = trail.get("IsMultiRegionTrail", False)
        if not is_multi_region:
            findings.append({
                "service": "CloudTrail",
                "severity": "HIGH",
                "title": "CloudTrail is Not Multi-Region",
                "resource": trail_name,
                "evidence": "IsMultiRegionTrail is False.",
                "recommendation": "Enable multi-region logging for the trail to capture activity across all AWS regions."
            })

        # 4. Trail has no S3 bucket configured -> HIGH
        s3_bucket = trail.get("S3BucketName")
        if not s3_bucket:
            findings.append({
                "service": "CloudTrail",
                "severity": "HIGH",
                "title": "CloudTrail Trail Has No S3 Bucket Configured",
                "resource": trail_name,
                "evidence": "S3BucketName is empty or missing.",
                "recommendation": "Configure a target S3 bucket to deliver CloudTrail logs securely."
            })

        # 5. Log file validation disabled -> MEDIUM
        log_validation = trail.get("LogFileValidationEnabled", False)
        if not log_validation:
            findings.append({
                "service": "CloudTrail",
                "severity": "MEDIUM",
                "title": "CloudTrail Log File Validation is Disabled",
                "resource": trail_name,
                "evidence": "LogFileValidationEnabled is False.",
                "recommendation": "Enable log file validation to ensure the integrity of the delivered logs."
            })

    return findings
