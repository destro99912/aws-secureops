import pytest
import boto3
from botocore.stub import Stubber
from secureops.scanners.config_scanner import scan_config


def test_config_scanner_client_init_error():
    """
    Test client initialization failure is handled.
    """
    class FailSession:
        def client(self, service_name, *args, **kwargs):
            raise Exception("Config init error")

    session = FailSession()
    findings = scan_config(session)  # type: ignore[arg-type]
    
    assert len(findings) == 1
    assert findings[0].service == "Config"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].title == "Could Not Initialize AWS Config Client"


def test_config_scanner_permission_denied():
    """
    Test describe_configuration_recorders permission denied maps to high severity permission finding.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("config")
    stubber = Stubber(client)
    
    stubber.add_client_error(
        "describe_configuration_recorders",
        service_error_code="AccessDenied",
        service_message="Access Denied"
    )
    stubber.add_response(
        "describe_delivery_channels",
        {"DeliveryChannels": [{"name": "default"}]}
    )
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_config(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "Config"
    assert findings[0].severity == "HIGH"
    assert "Scanner Permission Error" in findings[0].title
    assert "Describe Configuration Recorders" in findings[0].title


def test_config_scanner_no_findings():
    """
    Test clean AWS Config state (Recorder exists and is recording, delivery channel configured).
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("config")
    stubber = Stubber(client)
    
    # 1. describe_configuration_recorders
    stubber.add_response(
        "describe_configuration_recorders",
        {"ConfigurationRecorders": [{"name": "default", "roleARN": "arn:aws:iam::123:role/config", "recordingGroup": {"allSupported": True}}]}
    )
    
    # 2. describe_configuration_recorder_status
    stubber.add_response(
        "describe_configuration_recorder_status",
        {"ConfigurationRecordersStatus": [{"name": "default", "recording": True, "lastStatus": "SUCCESS"}]}
    )
    
    # 3. describe_delivery_channels
    stubber.add_response(
        "describe_delivery_channels",
        {"DeliveryChannels": [{"name": "default", "s3BucketName": "config-bucket"}]}
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_config(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 0


def test_config_scanner_no_recorders():
    """
    Test AWS Config not enabled when recorders list is empty.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("config")
    stubber = Stubber(client)
    
    # 1. describe_configuration_recorders (empty)
    stubber.add_response(
        "describe_configuration_recorders",
        {"ConfigurationRecorders": []}
    )
    
    # 2. describe_delivery_channels (empty)
    stubber.add_response(
        "describe_delivery_channels",
        {"DeliveryChannels": []}
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_config(session)
    stubber.assert_no_pending_responses()
    
    # Expected: AWS Config Not Enabled (CRITICAL), Delivery Channel Missing (HIGH)
    assert len(findings) == 2
    
    critical_f = next(f for f in findings if f.severity == "CRITICAL")
    assert critical_f.title == "AWS Config Not Enabled"
    
    high_f = next(f for f in findings if f.severity == "HIGH")
    assert high_f.title == "AWS Config Delivery Channel Missing"


def test_config_scanner_recording_disabled():
    """
    Test finding generated when configuration recording is disabled.
    """
    session = boto3.Session(region_name="us-east-1")
    client = session.client("config")
    stubber = Stubber(client)
    
    # 1. describe_configuration_recorders
    stubber.add_response(
        "describe_configuration_recorders",
        {"ConfigurationRecorders": [{"name": "default"}]}
    )
    
    # 2. describe_configuration_recorder_status (recording is False)
    stubber.add_response(
        "describe_configuration_recorder_status",
        {"ConfigurationRecordersStatus": [{"name": "default", "recording": False}]}
    )
    
    # 3. describe_delivery_channels
    stubber.add_response(
        "describe_delivery_channels",
        {"DeliveryChannels": [{"name": "default"}]}
    )
    
    stubber.activate()
    session.client = lambda name, *args, **kwargs: client  # type: ignore[assignment]
    
    findings = scan_config(session)
    stubber.assert_no_pending_responses()
    
    assert len(findings) == 1
    assert findings[0].service == "Config"
    assert findings[0].severity == "HIGH"
    assert findings[0].title == "AWS Config Recording is Disabled"
