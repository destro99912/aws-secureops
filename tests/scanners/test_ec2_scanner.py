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


def _volume(volume_id, encrypted, kms_key_id=None, attached_instance_id=None):
    vol = {
        "VolumeId": volume_id,
        "Encrypted": encrypted,
    }
    if kms_key_id:
        vol["KmsKeyId"] = kms_key_id
    if attached_instance_id:
        vol["Attachments"] = [{"InstanceId": attached_instance_id}]
    return vol


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
    stubber.add_response("describe_volumes", {"Volumes": []})
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
    stubber.add_response("describe_volumes", {"Volumes": []})
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
    stubber.add_response("describe_volumes", {"Volumes": []})
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
    stubber.add_response("describe_volumes", {"Volumes": []})
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
    stubber.add_response("describe_volumes", {"Volumes": []})
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
    stubber.add_response("describe_volumes", {"Volumes": []})
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
    stubber.add_response("describe_volumes", {"Volumes": []})
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
    stubber.add_response("describe_volumes", {"Volumes": []})
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    assert findings[0].region == "eu-west-1"


# --- EBS volume encryption tests ---

def test_ec2_scanner_ebs_unencrypted_volume():
    """
    EBS-A. Unencrypted volume produces exactly one HIGH finding (VolumeId only)
    when instance posture is otherwise clean.
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
    stubber.add_response(
        "describe_volumes",
        {"Volumes": [_volume("vol-unencrypted", encrypted=False, attached_instance_id="i-clean")]}
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    f = findings[0]
    assert f.title == "EBS Volume Is Not Encrypted"
    assert f.severity == "HIGH"
    assert f.resource == "vol-unencrypted"


def test_ec2_scanner_ebs_encrypted_volume_no_finding():
    """
    EBS-B. Encrypted volume produces no EBS finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response("describe_instances", {"Reservations": []})
    stubber.add_response(
        "describe_volumes",
        {"Volumes": [_volume("vol-encrypted", encrypted=True, kms_key_id="arn:aws:kms:us-east-1:123456789012:key/abc")]}
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert findings == []


def test_ec2_scanner_ebs_mixed_volumes():
    """
    EBS-C. Mix of encrypted and unencrypted volumes -> only unencrypted volumes flagged.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response("describe_instances", {"Reservations": []})
    stubber.add_response(
        "describe_volumes",
        {
            "Volumes": [
                _volume("vol-enc-1", encrypted=True),
                _volume("vol-unenc-1", encrypted=False),
                _volume("vol-enc-2", encrypted=True),
                _volume("vol-unenc-2", encrypted=False),
            ]
        }
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    resources = {f.resource for f in findings}
    assert resources == {"vol-unenc-1", "vol-unenc-2"}
    assert all(f.title == "EBS Volume Is Not Encrypted" for f in findings)


def test_ec2_scanner_ebs_pagination():
    """
    EBS-D. Volumes across multiple pages are all assessed.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response("describe_instances", {"Reservations": []})
    stubber.add_response(
        "describe_volumes",
        {
            "Volumes": [_volume("vol-page1", encrypted=False)],
            "NextToken": "vol-token-2"
        }
    )
    stubber.add_response(
        "describe_volumes",
        {"Volumes": [_volume("vol-page2", encrypted=False)]}
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    resources = {f.resource for f in findings}
    assert resources == {"vol-page1", "vol-page2"}


def test_ec2_scanner_ebs_describe_volumes_access_denied():
    """
    EBS-E. describe_volumes AccessDenied -> safe permission finding, includes
    ec2:DescribeVolumes, no raw service message / request metadata.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response("describe_instances", {"Reservations": []})
    stubber.add_client_error(
        "describe_volumes",
        service_error_code="AccessDenied",
        service_message="User arn:aws:iam::123456789012:user/scanner is not authorized (RequestId: req-abc-123)"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    f = findings[0]
    assert "Scanner Permission Error" in f.title
    assert "ec2:DescribeVolumes" in f.evidence
    assert "123456789012" not in f.evidence
    assert "arn:aws:iam" not in f.evidence
    assert "req-abc-123" not in f.evidence
    assert "not authorized" not in f.evidence


def test_ec2_scanner_ebs_describe_volumes_generic_error():
    """
    EBS-F. describe_volumes generic ClientError -> sanitized output only.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response("describe_instances", {"Reservations": []})
    stubber.add_client_error(
        "describe_volumes",
        service_error_code="InternalError",
        service_message="Something went wrong for account 123456789012 (RequestId: req-xyz-789)"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Could Not Describe EBS Volumes"
    assert f.severity == "MEDIUM"
    assert "InternalError" in f.evidence
    assert "123456789012" not in f.evidence
    assert "req-xyz-789" not in f.evidence
    assert "Something went wrong" not in f.evidence


def test_ec2_scanner_instance_findings_preserved_when_volume_scan_fails():
    """
    EBS-G. If DescribeInstances succeeds but DescribeVolumes fails, previously
    collected instance findings (e.g. IMDSv2, public-IP) are preserved, plus a
    safe scanner error finding is appended.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [_instance("i-at-risk", state="running", public_ip="203.0.113.50", http_tokens="optional")]}
            ]
        }
    )
    stubber.add_client_error(
        "describe_volumes",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    titles = [f.title for f in findings]
    assert "Running EC2 Instance Has Public IPv4 Address" in titles
    assert "IMDSv2 Not Enforced" in titles
    assert "Scanner Permission Error: Access Denied for Describe EBS Volumes" in titles
    assert len(findings) == 3


def test_ec2_scanner_ebs_region_field_populated():
    """
    EBS-H. Region field populated on EBS findings.
    """
    session = boto3.Session(region_name="ap-southeast-2")
    client = session.client("ec2")
    stubber = Stubber(client)

    stubber.add_response("describe_instances", {"Reservations": []})
    stubber.add_response(
        "describe_volumes",
        {"Volumes": [_volume("vol-region-test", encrypted=False)]}
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    assert findings[0].region == "ap-southeast-2"


def test_ec2_scanner_ebs_no_sensitive_metadata_leak():
    """
    EBS-I. No KMS ARN / attached-instance / other sensitive metadata leaks
    into the EBS finding's resource or evidence.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("ec2")
    stubber = Stubber(client)

    kms_arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    stubber.add_response("describe_instances", {"Reservations": []})
    stubber.add_response(
        "describe_volumes",
        {"Volumes": [_volume("vol-sensitive-check", encrypted=False, kms_key_id=kms_arn, attached_instance_id="i-attached-001")]}
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]

    findings = scan_ec2(session)
    stubber.assert_no_pending_responses()

    assert len(findings) == 1
    f = findings[0]
    assert f.resource == "vol-sensitive-check"
    assert kms_arn not in f.evidence
    assert kms_arn not in f.resource
    assert "123456789012" not in f.evidence
    assert "i-attached-001" not in f.evidence
    assert "i-attached-001" not in f.resource
