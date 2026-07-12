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
