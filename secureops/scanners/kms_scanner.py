import botocore.exceptions

def scan_kms(session):
    """
    Scans KMS keys for security posture issues. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list: A list of dict findings representing security issues.
    """
    findings = []
    
    try:
        client = session.client("kms")
    except Exception as e:
        findings.append({
            "service": "KMS",
            "severity": "CRITICAL",
            "title": "Could Not Initialize KMS Client",
            "resource": "KMS Service",
            "evidence": str(e),
            "recommendation": "Verify your AWS session, credentials, and region config."
        })
        return findings

    # Enumerate KMS Keys
    keys = []
    try:
        paginator = client.get_paginator('list_keys')
        for page in paginator.paginate():
            keys.extend(page.get('Keys', []))
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "service": "KMS",
                "severity": "HIGH",
                "title": "Access Denied: List Keys",
                "resource": "KMS Keys",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'kms:ListKeys' permissions."
            })
        else:
            findings.append({
                "service": "KMS",
                "severity": "MEDIUM",
                "title": "Could Not List KMS Keys",
                "resource": "KMS Keys",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has correct KMS permissions."
            })
        return findings
    except Exception as e:
        findings.append({
            "service": "KMS",
            "severity": "MEDIUM",
            "title": "Could Not List KMS Keys",
            "resource": "KMS Keys",
            "evidence": str(e),
            "recommendation": "Investigate errors listing KMS keys."
        })
        return findings

    # Audit each key
    for key_entry in keys:
        key_id = key_entry.get("KeyId")
        key_arn = key_entry.get("KeyArn", key_id)
        
        # Describe the key to determine manager and state
        try:
            desc = client.describe_key(KeyId=key_id)
            metadata = desc.get("KeyMetadata", {})
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            # Skip or log error for this specific key
            if error_code in ("AccessDenied", "AccessDeniedException"):
                findings.append({
                    "service": "KMS",
                    "severity": "LOW",
                    "title": f"Access Denied: Describe Key",
                    "resource": key_arn,
                    "evidence": str(e),
                    "recommendation": "Ensure the scanner identity has 'kms:DescribeKey' permissions."
                })
            else:
                findings.append({
                    "service": "KMS",
                    "severity": "LOW",
                    "title": "Could Not Describe KMS Key",
                    "resource": key_arn,
                    "evidence": str(e),
                    "recommendation": "Check permissions and key status."
                })
            continue
        except Exception as e:
            findings.append({
                "service": "KMS",
                "severity": "LOW",
                "title": "Could Not Describe KMS Key",
                "resource": key_arn,
                "evidence": str(e),
                "recommendation": "Investigate error describing key."
            })
            continue

        # Ignore AWS Managed Keys
        key_manager = metadata.get("KeyManager", "AWS")
        if key_manager == "AWS":
            continue

        key_state = metadata.get("KeyState")

        # 3. Disabled Key Check
        if key_state == "Disabled":
            findings.append({
                "service": "KMS",
                "severity": "HIGH",
                "title": "KMS Key Disabled",
                "resource": key_arn,
                "evidence": "KMS key is currently disabled.",
                "recommendation": "Review whether the key should remain disabled or be re-enabled if actively required."
            })

        # 4. Pending Deletion Check
        elif key_state == "PendingDeletion":
            findings.append({
                "service": "KMS",
                "severity": "HIGH",
                "title": "KMS Key Scheduled For Deletion",
                "resource": key_arn,
                "evidence": "KMS key is scheduled for deletion.",
                "recommendation": "Review pending deletion schedule to ensure critical encrypted resources are not impacted."
            })

        # 2. Key Rotation Check (Only for Enabled customer keys)
        # Note: Disabled keys or pending deletion keys might throw DisabledException or similar,
        # and some key types (e.g., asymmetric or HMACS) do not support rotation.
        if key_state == "Enabled":
            try:
                rotation_status = client.get_key_rotation_status(KeyId=key_id)
                rotation_enabled = rotation_status.get("KeyRotationEnabled", False)
                if not rotation_enabled:
                    findings.append({
                        "service": "KMS",
                        "severity": "MEDIUM",
                        "title": "KMS Key Rotation Disabled",
                        "resource": key_arn,
                        "evidence": "Key rotation is disabled for customer-managed key.",
                        "recommendation": "Enable automatic key rotation for long-term cryptographic hygiene and compliance."
                    })
            except botocore.exceptions.ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                # Ignore UnsupportedOperationException (asymmetric/HMAC keys do not support rotation)
                # Ignore DisabledException or KMSInvalidStateException if keys are modified concurrently
                if error_code not in ("UnsupportedOperationException", "DisabledException", "KMSInvalidStateException"):
                    findings.append({
                        "service": "KMS",
                        "severity": "LOW",
                        "title": "Could Not Get Key Rotation Status",
                        "resource": key_arn,
                        "evidence": str(e),
                        "recommendation": "Verify kms:GetKeyRotationStatus permissions and key type support."
                    })
            except Exception as e:
                # Do not stop scan on other keys
                pass

    return findings
