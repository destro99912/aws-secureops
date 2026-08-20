"""
Generates a sanitized, entirely synthetic demonstration report for
AWS SecureOps using the project's production reporting/scoring code.

This script does NOT call boto3, does NOT create an AWS session, and does
NOT make any network request. All Finding objects below are constructed
directly in memory with obviously synthetic resource identifiers
(sg-demo-*, i-demo-*, vol-demo-*, demo-*) that mirror the exact
titles/severities/evidence text real scanners produce, without touching
any real AWS account.

Run:
    python scripts/generate_demo_report.py
"""
import sys
from pathlib import Path

# Allow running directly via `python scripts/generate_demo_report.py`
# without requiring the package to be installed.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import botocore.exceptions

from secureops.core.errors import create_permission_finding
from secureops.core.models import Finding
from secureops.core.reporting import build_json_report, write_json_report

DEMO_REGION = "us-east-1"


def build_demo_findings() -> list[Finding]:
    """
    Builds a balanced set of synthetic Finding objects that mirror real
    scanner output (titles, severities, evidence wording) for demonstration
    purposes only. No real AWS resource, account, or network data is used.
    """
    findings: list[Finding] = []

    # IAM posture finding (mirrors iam_scanner.py's Root Account MFA Missing)
    findings.append(Finding(
        service="IAM",
        severity="CRITICAL",
        title="Root Account MFA Missing",
        resource="Root Account",
        evidence="AccountMFAEnabled is 0",
        recommendation="Enable Multi-Factor Authentication (MFA) on the root account immediately.",
        region=DEMO_REGION,
    ))

    # EC2 Security Group posture findings (mirrors securitygroup_scanner.py)
    findings.append(Finding(
        service="EC2 Security Groups",
        severity="HIGH",
        title="SSH Open To Internet",
        resource="sg-demo-001 (demo-web-sg)",
        evidence="Protocol: TCP, Port Range: 22-22, Source: 0.0.0.0/0",
        recommendation="Restrict inbound port 22 access to specific trusted IP ranges instead of the entire internet.",
        region=DEMO_REGION,
    ))
    findings.append(Finding(
        service="EC2 Security Groups",
        severity="HIGH",
        title="SIP Port Exposed to Internet",
        resource="sg-demo-002 (demo-voip-sg)",
        evidence="Public inbound UDP rule includes port 5060, commonly used by SIP signaling. "
                 "Protocol: UDP, Port Range: 5060-5060, Source: 0.0.0.0/0",
        recommendation="Restrict SIP signaling access to expected provider, SBC, proxy, trunk, or trusted "
                       "network ranges where architecture allows. Use authenticated/encrypted signaling and "
                       "layered controls as appropriate.",
        region=DEMO_REGION,
    ))
    findings.append(Finding(
        service="EC2 Security Groups",
        severity="MEDIUM",
        title="SIP-TLS Port Exposed to Internet",
        resource="sg-demo-002 (demo-voip-sg)",
        evidence="Public inbound TCP rule includes port 5061, commonly used for SIP over TLS. "
                 "Protocol: TCP, Port Range: 5061-5061, Source: 0.0.0.0/0",
        recommendation="Confirm that direct internet exposure is required and restrict access to expected "
                       "communications peers/providers where feasible.",
        region=DEMO_REGION,
    ))
    findings.append(Finding(
        service="EC2 Security Groups",
        severity="MEDIUM",
        title="Broad UDP Port Range Exposed to Internet",
        resource="sg-demo-002 (demo-voip-sg)",
        evidence="Public inbound UDP rule exposes port range 10000-20000 (10001 ports). Broad UDP ranges "
                 "may be used for real-time media/RTP or other UDP-based workloads, depending on application "
                 "configuration. Source: 0.0.0.0/0",
        recommendation="Confirm the range is required, narrow it where operationally possible, and restrict "
                       "sources to trusted communication peers/providers or network boundaries where "
                       "architecture allows.",
        region=DEMO_REGION,
    ))

    # EC2 instance/EBS posture findings (mirrors ec2_scanner.py)
    findings.append(Finding(
        service="EC2",
        severity="HIGH",
        title="IMDSv2 Not Enforced",
        resource="i-demo-web-01",
        evidence="Instance metadata options allow requests without mandatory session tokens, "
                 "meaning IMDSv1 may be available.",
        recommendation="Require IMDSv2 by configuring instance metadata HttpTokens to 'required' after "
                       "validating application compatibility.",
        region=DEMO_REGION,
    ))
    findings.append(Finding(
        service="EC2",
        severity="HIGH",
        title="EBS Volume Is Not Encrypted",
        resource="vol-demo-001",
        evidence="This EBS volume is not encrypted at rest.",
        recommendation="Use encrypted EBS volumes for data at rest. For existing unencrypted volumes, plan "
                       "migration to an encrypted replacement following normal AWS operational procedures.",
        region=DEMO_REGION,
    ))

    # Assessment coverage gap (mirrors securityhub_scanner.py's AccessDenied path).
    # Built via the same create_permission_finding() helper production scanners use,
    # with a synthetic ClientError - demonstrates that coverage gaps are excluded
    # from the posture risk score while still marking coverage as DEGRADED.
    synthetic_access_denied = botocore.exceptions.ClientError(
        error_response={"Error": {"Code": "AccessDenied", "Message": "synthetic demo access denied"}},
        operation_name="DescribeHub",
    )
    findings.append(create_permission_finding(
        service="SecurityHub",
        operation="Describe Hub",
        resource="Security Hub Config",
        required_permission="securityhub:DescribeHub",
        error=synthetic_access_denied,
        severity="HIGH",
        region=DEMO_REGION,
    ))

    return findings


def main() -> None:
    findings = build_demo_findings()
    report = build_json_report(findings, region=DEMO_REGION)

    output_path = Path(__file__).resolve().parent.parent / "docs" / "examples" / "aws-secureops-demo-report.json"
    write_json_report(report, str(output_path))

    print(f"[+] Synthetic demo report written to: {output_path}")
    print(f"    Posture finding count: {report['assessment']['posture_finding_count']}")
    print(f"    Risk score:            {report['assessment']['risk_score']}/100 ({report['assessment']['risk_level']})")
    print(f"    Coverage status:       {report['assessment']['coverage_status']}")
    print(f"    Coverage issue count:  {report['assessment']['coverage_issue_count']}")


if __name__ == "__main__":
    main()
