import pytest
import boto3
from botocore.stub import Stubber
from secureops.scanners.ec2_scanner import scan_ec2


def _instance(instance_id, state="running", public_ip=None, http_tokens="required", include_metadata_options=True):
    inst = {
        "InstanceId": instance_id,
        "State": {"Name": state},
    }
    if public_ip:
        inst["PublicIpAddress"] = public_ip
    if include_metadata_options:
        inst["MetadataOptions"] = {"HttpTokens": http_tokens}
    return inst


def test_ec2_scanner_client_init_error():
    """
    A. Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("EC2 init error")

    session = FailSession()
    findings = scan_ec2(session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].service == "EC2"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize EC2 Client"


def test_ec2_scanner_permission_denied():
    """
    B. describe_instances AccessDenied maps to a safe permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_client_error(
        "describe_instances",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    assert findings[0].service == "EC2"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "ec2:DescribeInstances" in findings[0].evidence


def test_ec2_scanner_clean_instance_no_findings():
    """
    C. Running instance with no public IP and IMDSv2 required -> zero findings.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-clean", state="running", public_ip=None, http_tokens="required")]}
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert findings == []


def test_ec2_scanner_public_running_instance():
    """
    D. Running instance with a public IP and IMDSv2 required -> exactly the public-IP
    posture finding; the actual IP must never appear in resource/evidence.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-public", state="running", public_ip="203.0.113.10", http_tokens="required")]}
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Running EC2 Instance Has Public IPv4 Address"
    assert f.severity == "MEDIUM"
    assert f.resource == "i-public"
    assert "203.0.113.10" not in f.resource
    assert "203.0.113.10" not in f.evidence


def test_ec2_scanner_imdsv2_not_enforced():
    """
    E. HttpTokens == "optional", no public IP -> exactly the IMDSv2 finding, severity HIGH.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-imds-optional", state="running", public_ip=None, http_tokens="optional")]}
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    assert findings[0].title == "IMDSv2 Not Enforced"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "i-imds-optional"


def test_ec2_scanner_missing_metadata_options():
    """
    F. Missing MetadataOptions / missing HttpTokens -> treated as not confirmed secure,
    produces the IMDSv2 finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-no-metadata-options", state="running", public_ip=None, include_metadata_options=False)]}
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    assert findings[0].title == "IMDSv2 Not Enforced"


def test_ec2_scanner_stopped_instance_with_public_ip():
    """
    G. Stopped instance with a public IP must NOT produce the public-IP finding.
    The IMDS check still applies independently of instance state.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-stopped", state="stopped", public_ip="203.0.113.20", http_tokens="optional")]}
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    titles = [f.title for f in findings]
    assert "Running EC2 Instance Has Public IPv4 Address" not in titles
    # Insecure IMDS config still flagged regardless of instance state.
    assert "IMDSv2 Not Enforced" in titles
    assert len(findings) == 1


def test_ec2_scanner_stopped_instance_secure_imds_no_findings():
    """
    G (secondary). Stopped instance with a public IP and IMDSv2 required ->
    no findings at all (no public-IP finding, no IMDS finding).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-stopped-secure", state="stopped", public_ip="203.0.113.30", http_tokens="required")]}
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert findings == []


def test_ec2_scanner_multiple_pages_multiple_reservations():
    """
    H. Paginator processes all instances across multiple pages and reservations.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-page1-res1", state="running", public_ip="198.51.100.1", http_tokens="required")]},
                {"Instances": [_instance("i-page1-res2", state="running", public_ip=None, http_tokens="optional")]},
            ],
            "NextToken": "token-2"
        }
    )
    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-page2-res1", state="stopped", public_ip=None, http_tokens="required")]},
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    resources = {f.resource for f in findings}
    assert "i-page1-res1" in resources  # public IP finding
    assert "i-page1-res2" in resources  # IMDSv2 finding
    assert "i-page2-res1" not in resources  # clean, stopped, secure IMDS
    assert len(findings) == 2


def test_ec2_scanner_region_field_populated():
    """
    I. Findings should contain the expected region when available.
    """
    session = boto3.Session(region_name="eu-west-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-region", state="running", public_ip="203.0.113.40", http_tokens="required")]}
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    assert findings[0].region == "eu-west-1"
