import botocore.exceptions
from secureops.core.models import Finding
from secureops.core.errors import create_permission_finding, sanitize_error

def scan_ec2(session) -> list[Finding]:
    """
    Scans EC2 instances for public IPv4 exposure and IMDSv2 enforcement.
    Does not modify any resources.

    Args:
        session (boto3.Session): An active boto3 session.

    Returns:
        list[Finding]: A list of Finding objects representing security issues.
    """
    findings: list[Finding] = []
    service_name = "EC2"

    try:
        client = session.client("ec2")
    except Exception as e:
        findings.append(Finding(
            service=service_name,
            severity="CRITICAL",
            title="Could Not Initialize EC2 Client",
            resource="EC2 Service",
            evidence=sanitize_error(e),
            recommendation="Verify your AWS session, credentials, and region config."
        ))
        return findings

    region = getattr(client.meta, "region_name", None)

    instances = []
    try:
        paginator = client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            findings.append(create_permission_finding(
                service=service_name,
                operation="Describe EC2 Instances",
                resource="EC2 Instances",
                required_permission="ec2:DescribeInstances",
                error=e,
                severity="HIGH",
                region=region
            ))
        else:
            findings.append(Finding(
                service=service_name,
                severity="MEDIUM",
                title="Could Not Describe EC2 Instances",
                resource="EC2 Instances",
                evidence=sanitize_error(e),
                recommendation="Ensure the scanner identity has 'ec2:DescribeInstances' permissions.",
                region=region
            ))
        return findings
    except Exception as e:
        findings.append(Finding(
            service=service_name,
            severity="MEDIUM",
            title="Could Not Describe EC2 Instances",
            resource="EC2 Instances",
            evidence=sanitize_error(e),
            recommendation="Investigate errors listing EC2 instances.",
            region=region
        ))
        return findings

    for instance in instances:
        instance_id = instance.get("InstanceId", "Unknown Instance")
        try:
            state = instance.get("State", {}).get("Name")

            # Running instance public IPv4 exposure
            if state == "running" and instance.get("PublicIpAddress"):
                findings.append(Finding(
                    service=service_name,
                    severity="MEDIUM",
                    title="Running EC2 Instance Has Public IPv4 Address",
                    resource=instance_id,
                    evidence="This running instance has a public IPv4 address and may be directly reachable "
                             "depending on routing, security groups, NACLs, and host configuration.",
                    recommendation="Review whether direct internet exposure is necessary. Prefer private "
                                   "networking, load balancers, VPN/private connectivity, bastion/SSM access, "
                                   "or restricted security groups where appropriate.",
                    region=region
                ))

            # IMDSv2 enforcement
            http_tokens = instance.get("MetadataOptions", {}).get("HttpTokens")
            if http_tokens != "required":
                findings.append(Finding(
                    service=service_name,
                    severity="HIGH",
                    title="IMDSv2 Not Enforced",
                    resource=instance_id,
                    evidence="Instance metadata options allow requests without mandatory session tokens, "
                             "meaning IMDSv1 may be available.",
                    recommendation="Require IMDSv2 by configuring instance metadata HttpTokens to 'required' "
                                   "after validating application compatibility.",
                    region=region
                ))
        except Exception as e:
            findings.append(Finding(
                service=service_name,
                severity="LOW",
                title="Error Scanning EC2 Instance",
                resource=instance_id,
                evidence=sanitize_error(e),
                recommendation="Investigate execution errors for this instance.",
                region=region
            ))

    return findings
