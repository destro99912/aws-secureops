import botocore.exceptions

def scan_s3(session):
    """
    Scans S3 posture on AWS. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list: A list of dict findings representing security issues.
    """
    findings = []
    
    try:
        client = session.client("s3")
    except Exception as e:
        findings.append({
            "service": "S3",
            "severity": "CRITICAL",
            "title": "Could Not Initialize S3 Client",
            "resource": "S3 Service",
            "evidence": str(e),
            "recommendation": "Verify your AWS session, credentials, and region config."
        })
        return findings

    # List S3 buckets
    try:
        response = client.list_buckets()
        buckets = response.get("Buckets", [])
    except Exception as e:
        findings.append({
            "service": "S3",
            "severity": "HIGH",
            "title": "Could Not List S3 Buckets",
            "resource": "S3 Service",
            "evidence": str(e),
            "recommendation": "Ensure the scanner identity has 's3:ListAllMyBuckets' permissions."
        })
        return findings

    for bucket in buckets:
        bucket_name = bucket["Name"]
        
        # 1. Public Access Block Configuration Check
        try:
            pab = client.get_public_access_block(Bucket=bucket_name)
            config = pab.get("PublicAccessBlockConfiguration", {})
            # Check if all blocks are enabled
            is_fully_blocked = (
                config.get("BlockPublicAcls", False) and
                config.get("IgnorePublicAcls", False) and
                config.get("BlockPublicPolicy", False) and
                config.get("RestrictPublicBuckets", False)
            )
            if not is_fully_blocked:
                findings.append({
                    "service": "S3",
                    "severity": "HIGH",
                    "title": "Public Access Block is Not Fully Enabled",
                    "resource": bucket_name,
                    "evidence": f"Configuration: BlockPublicAcls={config.get('BlockPublicAcls')}, IgnorePublicAcls={config.get('IgnorePublicAcls')}, BlockPublicPolicy={config.get('BlockPublicPolicy')}, RestrictPublicBuckets={config.get('RestrictPublicBuckets')}",
                    "recommendation": "Enable all S3 Public Access Block settings for the bucket to block public access."
                })
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "NoSuchPublicAccessBlockConfiguration":
                findings.append({
                    "service": "S3",
                    "severity": "HIGH",
                    "title": "Public Access Block is Missing",
                    "resource": bucket_name,
                    "evidence": "No Public Access Block configuration exists for this bucket.",
                    "recommendation": "Enable S3 Public Access Block settings for the bucket immediately."
                })
            else:
                findings.append({
                    "service": "S3",
                    "severity": "LOW",
                    "title": "Could Not Retrieve Public Access Block Configuration",
                    "resource": bucket_name,
                    "evidence": str(e),
                    "recommendation": "Ensure the scanner identity has 's3:GetBucketPublicAccessBlock' permissions."
                })
        except Exception as e:
            findings.append({
                "service": "S3",
                "severity": "LOW",
                "title": "Could Not Retrieve Public Access Block Configuration",
                "resource": bucket_name,
                "evidence": str(e),
                "recommendation": "Verify S3 bucket connectivity and access permissions."
            })

        # 2. Default Encryption Check
        try:
            client.get_bucket_encryption(Bucket=bucket_name)
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append({
                    "service": "S3",
                    "severity": "MEDIUM",
                    "title": "Default Encryption is Missing",
                    "resource": bucket_name,
                    "evidence": "No default server-side encryption configuration is enabled.",
                    "recommendation": "Configure default S3 server-side encryption using SSE-S3 or SSE-KMS."
                })
            else:
                findings.append({
                    "service": "S3",
                    "severity": "LOW",
                    "title": "Could Not Retrieve Default Encryption Configuration",
                    "resource": bucket_name,
                    "evidence": str(e),
                    "recommendation": "Ensure the scanner identity has 's3:GetEncryptionConfiguration' permissions."
                })
        except Exception as e:
            findings.append({
                "service": "S3",
                "severity": "LOW",
                "title": "Could Not Retrieve Default Encryption Configuration",
                "resource": bucket_name,
                "evidence": str(e),
                "recommendation": "Verify S3 bucket connectivity and access permissions."
            })

        # 3. Bucket Versioning Check
        try:
            versioning = client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get("Status")
            if status != "Enabled":
                findings.append({
                    "service": "S3",
                    "severity": "LOW",
                    "title": "Versioning is Disabled",
                    "resource": bucket_name,
                    "evidence": f"Versioning status is {status or 'Suspended/Disabled'}.",
                    "recommendation": "Enable S3 bucket versioning to protect against accidental deletion or overwriting."
                })
        except Exception as e:
            findings.append({
                "service": "S3",
                "severity": "LOW",
                "title": "Could Not Retrieve Bucket Versioning Status",
                "resource": bucket_name,
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 's3:GetBucketVersioning' permissions."
            })

        # 4. Bucket Policy Public Exposure Check
        try:
            policy_status = client.get_bucket_policy_status(Bucket=bucket_name)
            is_public = policy_status.get("PolicyStatus", {}).get("IsPublic", False)
            if is_public:
                findings.append({
                    "service": "S3",
                    "severity": "CRITICAL",
                    "title": "Bucket Policy Allows Public Access",
                    "resource": bucket_name,
                    "evidence": "Bucket policy allows public read/write access ('IsPublic' is True).",
                    "recommendation": "Restrict the bucket policy to allow only authorized users and services."
                })
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            # If there is no policy, it's not public via bucket policy
            if code not in ("NoSuchBucketPolicy", "NoSuchBucket"):
                findings.append({
                    "service": "S3",
                    "severity": "LOW",
                    "title": "Could Not Retrieve Bucket Policy Status",
                    "resource": bucket_name,
                    "evidence": str(e),
                    "recommendation": "Ensure the scanner identity has 's3:GetBucketPolicyStatus' permissions."
                })
        except Exception as e:
            findings.append({
                "service": "S3",
                "severity": "LOW",
                "title": "Could Not Retrieve Bucket Policy Status",
                "resource": bucket_name,
                "evidence": str(e),
                "recommendation": "Verify S3 bucket connectivity and access permissions."
            })

    return findings
