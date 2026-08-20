import pytest
import boto3
from botocore.stub import Stubber
from secureops.scanners.securitygroup_scanner import scan_security_groups


def test_security_group_scanner_client_init_error():
    """
    Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("EC2 init error")

    session = FailSession()
    findings = scan_security_groups(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "EC2 Security Groups"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize EC2 Client"


def test_security_group_scanner_permission_denied():
    """
    Test describe_security_groups permission denied maps to high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)
    
    # 1. describe_network_interfaces (succeeds)
    stubber.add_response("describe_network_interfaces", {"NetworkInterfaces": []})
    
    # 2. describe_security_groups (AccessDenied)
    stubber.add_client_error(
        "describe_security_groups",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_security_groups(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "EC2 Security Groups"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "Describe Security Groups" in findings[0].title


def test_security_group_scanner_no_findings():
    """
    Test clean security group state (Security groups exist and are in use, rules are restricted - not public).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)
    
    # 1. describe_network_interfaces (shows group sg-1 is in use)
    stubber.add_response(
        "describe_network_interfaces",
        {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-1",
                    "Groups": [{"GroupId": "sg-1", "GroupName": "default"}]
                }
            ]
        }
    )
    
    # 2. describe_security_groups (restricted rule)
    stubber.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-1",
                    "GroupName": "default",
                    "Description": "default description",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}] # restricted!
                        }
                    ]
                }
            ]
        }
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_security_groups(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 0


def test_security_group_scanner_positive_findings():
    """
    Test that exposed SSH, RDP, Database, and All Traffic, as well as unused security groups, are flagged.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)
    
    # 1. describe_network_interfaces (only sg-in-use is in use, sg-unused is not)
    stubber.add_response(
        "describe_network_interfaces",
        {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-1",
                    "Groups": [{"GroupId": "sg-in-use"}]
                }
            ]
        }
    )
    
    # 2. describe_security_groups
    stubber.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-in-use",
                    "GroupName": "web-rules",
                    "Description": "public exposure rules",
                    "IpPermissions": [
                        # 1. Exposed SSH/22 (HIGH)
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        },
                        # 2. Exposed RDP/3389 (HIGH)
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
                        },
                        # 3. Exposed DB MySQL/3306 (CRITICAL)
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3306,
                            "ToPort": 3306,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        },
                        # 4. Exposed All Traffic (CRITICAL)
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        }
                    ]
                },
                {
                    "GroupId": "sg-unused",
                    "GroupName": "unused-rules",
                    "Description": "no rules",
                    "IpPermissions": []
                }
            ]
        }
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_security_groups(session)
    stubber.assert_no_pending_responses()
    
    # Expected:
    # From sg-in-use: SSH exposed (HIGH), RDP exposed (HIGH), MySQL exposed (CRITICAL), All Traffic open (CRITICAL)
    # From sg-unused: Unused security group (LOW)
    # Total = 5 findings
    assert len(findings) == 5
    
    ssh_f = next(f for f in findings if f.title == "SSH Open To Internet")
    assert ssh_f.severity == "HIGH"
    
    rdp_f = next(f for f in findings if f.title == "RDP Open To Internet")
    assert rdp_f.severity == "HIGH"
    
    db_f = next(f for f in findings if f.title == "Database Port Open To Internet")
    assert db_f.severity == "CRITICAL"
    
    all_f = next(f for f in findings if f.title == "All Traffic Open To Internet")
    assert all_f.severity == "CRITICAL"
    
    unused_f = next(f for f in findings if f.title == "Unused Security Group")
    assert unused_f.severity == "LOW"


def _scan_single_sg_rules(ip_permissions):
    """
    Helper: stub describe_network_interfaces/describe_security_groups with a
    single security group containing the given IpPermissions, and return findings.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_network_interfaces",
        {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-1"}]}]}
    )
    stubber.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-1",
                    "GroupName": "comms-rules",
                    "Description": "communications posture rules",
                    "IpPermissions": ip_permissions
                }
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_security_groups(session)
    stubber.assert_no_pending_responses()
    return findings


def test_sip_tcp_5060_public():
    """
    A. TCP 5060 public -> HIGH SIP finding.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "tcp", "FromPort": 5060, "ToPort": 5060, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    sip_findings = [f for f in findings if f.title == "SIP Port Exposed to Internet"]
    assert len(sip_findings) == 1
    assert sip_findings[0].severity == "HIGH"
    assert sip_findings[0].region == "us-east-1"


def test_sip_udp_5060_public():
    """
    B. UDP 5060 public -> HIGH SIP finding.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "udp", "FromPort": 5060, "ToPort": 5060, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    sip_findings = [f for f in findings if f.title == "SIP Port Exposed to Internet"]
    assert len(sip_findings) == 1
    assert sip_findings[0].severity == "HIGH"


def test_sip_tls_tcp_5061_public():
    """
    C. TCP 5061 public -> MEDIUM SIP-TLS finding.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "tcp", "FromPort": 5061, "ToPort": 5061, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    sip_tls_findings = [f for f in findings if f.title == "SIP-TLS Port Exposed to Internet"]
    assert len(sip_tls_findings) == 1
    assert sip_tls_findings[0].severity == "MEDIUM"


def test_sip_restricted_source_no_finding():
    """
    D. 5060/5061 restricted to a private range -> no communications finding.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "tcp", "FromPort": 5060, "ToPort": 5061, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
    ])

    titles = [f.title for f in findings]
    assert "SIP Port Exposed to Internet" not in titles
    assert "SIP-TLS Port Exposed to Internet" not in titles


def test_sip_ipv6_public():
    """
    E. IPv6 public SIP (::/0) -> finding produced.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "tcp", "FromPort": 5060, "ToPort": 5060, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    ])

    sip_findings = [f for f in findings if f.title == "SIP Port Exposed to Internet"]
    assert len(sip_findings) == 1


def test_broad_udp_range_public():
    """
    F. Broad UDP range (10000-20000) from 0.0.0.0/0 -> MEDIUM broad UDP finding,
    cautious "may be used" language, no RTP-service claim.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "udp", "FromPort": 10000, "ToPort": 20000, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    broad_udp = [f for f in findings if f.title == "Broad UDP Port Range Exposed to Internet"]
    assert len(broad_udp) == 1
    f = broad_udp[0]
    assert f.severity == "MEDIUM"
    assert "may be used" in f.evidence
    assert "RTP vulnerability" not in f.evidence
    assert "exposed RTP service" not in f.evidence
    assert "VoIP compromise" not in f.evidence
    assert "media attack detected" not in f.evidence


def test_narrow_udp_range_no_broad_finding():
    """
    G. Narrow UDP range (10000-10100) -> no broad UDP finding.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "udp", "FromPort": 10000, "ToPort": 10100, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    titles = [f.title for f in findings]
    assert "Broad UDP Port Range Exposed to Internet" not in titles


def test_all_traffic_rule_no_duplicate_communications_findings():
    """
    H. All-traffic rule -> existing CRITICAL finding only, no duplicate
    SIP/SIP-TLS/broad-UDP findings from the same rule.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    titles = [f.title for f in findings]
    assert titles.count("All Traffic Open To Internet") == 1
    assert "SIP Port Exposed to Internet" not in titles
    assert "SIP-TLS Port Exposed to Internet" not in titles
    assert "Broad UDP Port Range Exposed to Internet" not in titles


def test_tcp_range_containing_5060_and_5061():
    """
    I. A single TCP rule whose range spans both 5060 and 5061 produces both findings.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "tcp", "FromPort": 5060, "ToPort": 5061, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    titles = [f.title for f in findings]
    assert "SIP Port Exposed to Internet" in titles
    assert "SIP-TLS Port Exposed to Internet" in titles


def test_wide_udp_range_containing_5060():
    """
    J. Wide UDP range containing 5060 -> both SIP finding and broad UDP finding.
    """
    findings = _scan_single_sg_rules([
        {"IpProtocol": "udp", "FromPort": 5000, "ToPort": 6000, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    titles = [f.title for f in findings]
    assert "SIP Port Exposed to Internet" in titles
    assert "Broad UDP Port Range Exposed to Internet" in titles
