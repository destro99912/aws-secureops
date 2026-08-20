import sys
import botocore.exceptions
from secureops.core.aws_session import get_aws_session
from secureops.scanners.iam_scanner import scan_iam
from secureops.scanners.s3_scanner import scan_s3
from secureops.scanners.cloudtrail_scanner import scan_cloudtrail
from secureops.scanners.config_scanner import scan_config
from secureops.scanners.guardduty_scanner import scan_guardduty
from secureops.scanners.securityhub_scanner import scan_securityhub
from secureops.scanners.inspector_scanner import scan_inspector
from secureops.scanners.kms_scanner import scan_kms
from secureops.scanners.securitygroup_scanner import scan_security_groups
from secureops.scanners.ec2_scanner import scan_ec2


from secureops.core.models import Finding
from secureops.core.reporting import build_json_report, write_json_report
from secureops.core.scoring import calculate_assessment

def print_finding(index, finding: Finding):
    severity_colors = {
        "CRITICAL": "[CRITICAL]",
        "HIGH":     "[HIGH]    ",
        "MEDIUM":   "[MEDIUM]  ",
        "LOW":      "[LOW]     ",
        "INFO":     "[INFO]    "
    }
    
    sev = finding.severity
    sev_str = severity_colors.get(sev, f"[{sev}]".ljust(10))
    
    print("-" * 60)
    print(f"Finding #{index} - {sev_str} | Service: {finding.service}")
    print(f"Title:          {finding.title}")
    print(f"Resource:       {finding.resource}")
    print(f"Evidence:       {finding.evidence}")
    print(f"Recommendation: {finding.recommendation}")

def main():
    import argparse
    import os
    
    parser = argparse.ArgumentParser(
        description="AWS SecureOps - Cloud Security Posture Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python secureops/main.py
  python secureops/main.py --profile secureops
  python secureops/main.py --region us-east-1
  python secureops/main.py --profile secureops --region us-east-1
"""
    )
    parser.add_argument(
        "--profile",
        help="AWS CLI profile to use."
    )
    parser.add_argument(
        "--region",
        help="AWS region to scan."
    )
    parser.add_argument(
        "--output-json",
        metavar="PATH",
        help="Write a JSON report to this local file path after scanning."
    )

    args = parser.parse_args()
    
    print("=" * 60)
    print(" AWS SecureOps - Posture Scanner")
    print("=" * 60)
    
    profile = args.profile
    region = args.region
    
    effective_region = None

    try:
        # Initialize AWS session
        session = get_aws_session(profile_name=profile, region_name=region)
        effective_region = getattr(session, "region_name", None)

        # Initialize the STS client to verify identity
        sts_client = session.client("sts")
        identity = sts_client.get_caller_identity()

        print("\n[+] Successfully authenticated to AWS.")
        
    except botocore.exceptions.ProfileNotFound:
        profile_str = profile if profile else os.environ.get("AWS_PROFILE", "default")
        print(f"\n[-] Error: The AWS profile '{profile_str}' was not found.")
        print("    Please ensure you have configured this profile in your AWS credentials file.")
        print(f"    You can create it by running: aws configure --profile {profile_str}")
        sys.exit(1)
        
    except botocore.exceptions.NoCredentialsError:
        print("\n[-] Error: No AWS credentials could be found.")
        print("    Please set up your AWS credentials using the AWS CLI or environment variables.")
        sys.exit(1)

    except botocore.exceptions.PartialCredentialsError as e:
        print(f"\n[-] Error: Incomplete credentials configuration. {e}")
        print("    Please ensure both AWS Access Key ID and Secret Access Key are provided.")
        sys.exit(1)

    except botocore.exceptions.UnknownRegionError as e:
        print(f"\n[-] Error: The specified AWS region is invalid or unknown. {e}")
        print("    Please verify the spelling of the region (e.g. 'us-east-1', 'eu-west-1').")
        sys.exit(1)

    except botocore.exceptions.EndpointConnectionError as e:
        print(f"\n[-] Error: Could not connect to AWS endpoints. {e}")
        print("    Please check your internet connection or verify if the region is correct and valid.")
        sys.exit(1)
        
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        print(f"\n[-] AWS Client Error ({error_code}):")
        
        if error_code == "InvalidClientTokenId":
            print("    The AWS Access Key ID is invalid or security token is incorrect.")
            print("    Please verify your keys in credentials config or environment variables.")
        elif error_code in ("ExpiredToken", "RequestExpired"):
            print("    The AWS security token/credentials have expired.")
            print("    Please renew your session credentials (e.g., via AWS SSO or STS).")
        elif error_code == "UnrecognizedClientException":
            print("    The security token included in the request is unrecognized.")
            print("    Please check if your account is active and credentials are correct.")
        elif error_code in ("AccessDenied", "AccessDeniedException"):
            print("    Access Denied to verify identity (STS GetCallerIdentity).")
            print("    Ensure the IAM principal has permission to perform sts:GetCallerIdentity.")
        elif error_code == "InvalidSignatureException":
            print("    The request signature is invalid. Your Secret Access Key may be incorrect.")
            print("    Please verify your secret key configuration.")
        else:
            print("    AWS returned an error while validating the current credentials or session.")
            print("    Verify credentials, permissions, region, and AWS service availability.")
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
    
    print("\nStarting GuardDuty Scan...")
    guardduty_findings = scan_guardduty(session)
    
    print("\nStarting Security Hub Scan...")
    securityhub_findings = scan_securityhub(session)
    
    print("\nStarting Amazon Inspector Scan...")
    inspector_findings = scan_inspector(session)
    
    print("\nStarting KMS Scan...")
    kms_findings = scan_kms(session)
    
    print("\nStarting Security Group Scan...")
    securitygroup_findings = scan_security_groups(session)

    print("\nStarting EC2 Scan...")
    ec2_findings = scan_ec2(session)

    all_findings = (
        iam_findings +
        s3_findings +
        cloudtrail_findings +
        config_findings +
        guardduty_findings +
        securityhub_findings +
        inspector_findings +
        kms_findings +
        securitygroup_findings +
        ec2_findings
    )
    
    if not all_findings:
        print("\n[+] Scan completed. No security findings discovered!")
    else:
        # Count severities
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            sev = f.severity
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
        print(f"  INFO:     {counts['INFO']}")
        print(f"  Total:    {len(all_findings)}")
        print("=" * 60)

    # Posture risk score: a simple, deterministic sum of severity weights for
    # observed posture findings only (capped at 100). It is NOT a compliance
    # score, certification, or a prediction of breach/exploitability
    # likelihood. Coverage gaps (permission/scanner errors) are excluded from
    # the score and reported separately as coverage status/issue count.
    assessment = calculate_assessment(all_findings)
    print("\nPosture Assessment:")
    print(f"  Risk Score:        {assessment['risk_score']}/100")
    print(f"  Risk Level:        {assessment['risk_level']}")
    print(f"  Coverage Status:   {assessment['coverage_status']}")
    print(f"  Coverage Issues:   {assessment['coverage_issue_count']}")

    if args.output_json:
        report = build_json_report(all_findings, region=effective_region)
        try:
            write_json_report(report, args.output_json)
            print(f"\n[+] JSON report written to: {args.output_json}")
        except OSError:
            print(f"\n[-] Could not write JSON report to '{args.output_json}'.")
            print("    Verify the parent directory exists and the path is writable.")
            sys.exit(1)

if __name__ == "__main__":
    main()
