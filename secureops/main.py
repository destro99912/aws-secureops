import sys
import botocore.exceptions
from core.aws_session import get_aws_session
from scanners.iam_scanner import scan_iam
from scanners.s3_scanner import scan_s3
from scanners.cloudtrail_scanner import scan_cloudtrail
from scanners.config_scanner import scan_config

def print_finding(index, finding):
    severity_colors = {
        "CRITICAL": "[CRITICAL]",
        "HIGH":     "[HIGH]    ",
        "MEDIUM":   "[MEDIUM]  ",
        "LOW":      "[LOW]     "
    }
    
    sev = finding.get("severity", "INFO")
    sev_str = severity_colors.get(sev, f"[{sev}]".ljust(10))
    
    print("-" * 60)
    print(f"Finding #{index} - {sev_str} | Service: {finding.get('service')}")
    print(f"Title:          {finding.get('title')}")
    print(f"Resource:       {finding.get('resource')}")
    print(f"Evidence:       {finding.get('evidence')}")
    print(f"Recommendation: {finding.get('recommendation')}")

def main():
    print("=" * 60)
    print(" AWS SecureOps - Posture Scanner")
    print("=" * 60)
    
    profile = "secureops"
    
    try:
        # Initialize AWS session using the profile
        session = get_aws_session(profile_name=profile)
        
        # Initialize the STS client to verify identity
        sts_client = session.client("sts")
        identity = sts_client.get_caller_identity()
        
        print("\n[+] Successfully connected to AWS!")
        print(f"    Account:  {identity.get('Account')}")
        print(f"    Arn:      {identity.get('Arn')}")
        print(f"    UserId:   {identity.get('UserId')}")
        
    except botocore.exceptions.ProfileNotFound:
        print(f"\n[-] Error: The AWS profile '{profile}' was not found.")
        print("    Please ensure you have configured this profile in your AWS credentials file.")
        print(f"    You can create it by running: aws configure --profile {profile}")
        sys.exit(1)
        
    except botocore.exceptions.NoCredentialsError:
        print("\n[-] Error: No AWS credentials could be found.")
        print("    Please set up your AWS credentials using the AWS CLI or environment variables.")
        sys.exit(1)
        
    except botocore.exceptions.ClientError as e:
        print(f"\n[-] AWS Client Error: {e}")
        print("    Please check if your credentials are valid and have not expired.")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n[-] Unexpected Error: {e}")
        sys.exit(1)

    print("\nStarting IAM Scan...")
    iam_findings = scan_iam(session)
    
    print("\nStarting S3 Scan...")
    s3_findings = scan_s3(session)
    
    print("\nStarting CloudTrail Scan...")
    cloudtrail_findings = scan_cloudtrail(session)
    
    print("\nStarting AWS Config Scan...")
    config_findings = scan_config(session)
    
    all_findings = iam_findings + s3_findings + cloudtrail_findings + config_findings
    
    if not all_findings:
        print("\n[+] Scan completed. No security findings discovered!")
        return

    # Count severities
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
            
    print(f"\nScan completed. Found {len(all_findings)} issues:")
    for idx, finding in enumerate(all_findings, 1):
        print_finding(idx, finding)
        
    print("-" * 60)
    print("\nScan Summary:")
    print(f"  CRITICAL: {counts['CRITICAL']}")
    print(f"  HIGH:     {counts['HIGH']}")
    print(f"  MEDIUM:   {counts['MEDIUM']}")
    print(f"  LOW:      {counts['LOW']}")
    print(f"  Total:    {len(all_findings)}")
    print("=" * 60)

if __name__ == "__main__":
    main()
