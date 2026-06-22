import botocore.exceptions

def scan_config(session):
    """
    Scans AWS Config posture on AWS. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list: A list of dict findings representing security issues.
    """
    findings = []
    
    try:
        client = session.client("config")
    except Exception as e:
        findings.append({
            "service": "Config",
            "severity": "CRITICAL",
            "title": "Could Not Initialize AWS Config Client",
            "resource": "AWS Config Service",
            "evidence": str(e),
            "recommendation": "Verify your AWS session, credentials, and region config."
        })
        return findings

    recorders = []
    has_access_recorders = False
    
    # 1. Check Configuration Recorder
    try:
        response = client.describe_configuration_recorders()
        recorders = response.get("ConfigurationRecorders", [])
        has_access_recorders = True
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "service": "Config",
                "severity": "HIGH",
                "title": "Access Denied: Describe Configuration Recorders",
                "resource": "AWS Config Service",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'config:DescribeConfigurationRecorders' permissions."
            })
        elif error_code == "NoSuchConfigurationRecorderException":
            findings.append({
                "service": "Config",
                "severity": "CRITICAL",
                "title": "AWS Config Not Enabled",
                "resource": "AWS Config Config",
                "evidence": "No configuration recorders exist (NoSuchConfigurationRecorderException).",
                "recommendation": "Set up and enable AWS Config to record resource configurations."
            })
        else:
            findings.append({
                "service": "Config",
                "severity": "MEDIUM",
                "title": "Could Not Describe Configuration Recorders",
                "resource": "AWS Config Service",
                "evidence": str(e),
                "recommendation": "Investigate errors accessing AWS Config configuration recorders."
            })
    except Exception as e:
        findings.append({
            "service": "Config",
            "severity": "MEDIUM",
            "title": "Could Not Describe Configuration Recorders",
            "resource": "AWS Config Service",
            "evidence": str(e),
            "recommendation": "Investigate errors accessing AWS Config configuration recorders."
        })

    # If we successfully read configuration recorders and found none, AWS Config is not enabled
    if has_access_recorders and not recorders:
        findings.append({
            "service": "Config",
            "severity": "CRITICAL",
            "title": "AWS Config Not Enabled",
            "resource": "AWS Config Config",
            "evidence": "No configuration recorders configured in this region.",
            "recommendation": "Set up and enable AWS Config to record resource configurations."
        })

    # 2. If configuration recorders exist, check their recording status
    if recorders:
        for recorder in recorders:
            recorder_name = recorder.get("name", "default")
            try:
                status_response = client.describe_configuration_recorder_status(
                    ConfigurationRecorderNames=[recorder_name]
                )
                statuses = status_response.get("ConfigurationRecordersStatus", [])
                if not statuses:
                    findings.append({
                        "service": "Config",
                        "severity": "HIGH",
                        "title": "Configuration Recorder Status Empty",
                        "resource": recorder_name,
                        "evidence": "No status returned for configuration recorder.",
                        "recommendation": "Verify configuration recorder settings and status."
                    })
                else:
                    for status in statuses:
                        if not status.get("recording", False):
                            findings.append({
                                "service": "Config",
                                "severity": "HIGH",
                                "title": "AWS Config Recording is Disabled",
                                "resource": recorder_name,
                                "evidence": f"Recording status is inactive (recording=False) for recorder '{recorder_name}'.",
                                "recommendation": "Start recording for the configuration recorder."
                            })
            except botocore.exceptions.ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ("AccessDenied", "AccessDeniedException"):
                    findings.append({
                        "service": "Config",
                        "severity": "HIGH",
                        "title": "Access Denied: Describe Configuration Recorder Status",
                        "resource": recorder_name,
                        "evidence": str(e),
                        "recommendation": "Ensure the scanner identity has 'config:DescribeConfigurationRecorderStatus' permissions."
                    })
                elif error_code == "NoSuchConfigurationRecorderException":
                    findings.append({
                        "service": "Config",
                        "severity": "HIGH",
                        "title": "Configuration Recorder Missing Status",
                        "resource": recorder_name,
                        "evidence": f"NoSuchConfigurationRecorderException for recorder '{recorder_name}'.",
                        "recommendation": "Verify if the configuration recorder exists."
                    })
                else:
                    findings.append({
                        "service": "Config",
                        "severity": "MEDIUM",
                        "title": "Could Not Retrieve Configuration Recorder Status",
                        "resource": recorder_name,
                        "evidence": str(e),
                        "recommendation": "Ensure the scanner identity has permissions to get recorder status."
                    })
            except Exception as e:
                findings.append({
                    "service": "Config",
                    "severity": "MEDIUM",
                    "title": "Could Not Retrieve Configuration Recorder Status",
                    "resource": recorder_name,
                    "evidence": str(e),
                    "recommendation": "Investigate errors checking configuration recorder status."
                })

    # 3. Check Delivery Channel
    has_delivery_channels = False
    delivery_channels = []
    try:
        channel_response = client.describe_delivery_channels()
        delivery_channels = channel_response.get("DeliveryChannels", [])
        has_delivery_channels = True
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "service": "Config",
                "severity": "HIGH",
                "title": "Access Denied: Describe Delivery Channels",
                "resource": "AWS Config Delivery Channels",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'config:DescribeDeliveryChannels' permissions."
            })
        elif error_code == "NoSuchDeliveryChannelException":
            findings.append({
                "service": "Config",
                "severity": "HIGH",
                "title": "AWS Config Delivery Channel Missing",
                "resource": "AWS Config Delivery Channels",
                "evidence": "No delivery channels configured (NoSuchDeliveryChannelException).",
                "recommendation": "Create a delivery channel (S3 bucket, SNS topic, etc.) to deliver AWS Config data."
            })
        else:
            findings.append({
                "service": "Config",
                "severity": "MEDIUM",
                "title": "Could Not Describe Delivery Channels",
                "resource": "AWS Config Delivery Channels",
                "evidence": str(e),
                "recommendation": "Investigate errors accessing AWS Config delivery channels."
            })
    except Exception as e:
        findings.append({
            "service": "Config",
            "severity": "MEDIUM",
            "title": "Could Not Describe Delivery Channels",
            "resource": "AWS Config Delivery Channels",
            "evidence": str(e),
            "recommendation": "Investigate errors accessing AWS Config delivery channels."
        })

    if has_delivery_channels and not delivery_channels:
        findings.append({
            "service": "Config",
            "severity": "HIGH",
            "title": "AWS Config Delivery Channel Missing",
            "resource": "AWS Config Delivery Channels",
            "evidence": "No delivery channels configured in this region.",
            "recommendation": "Create a delivery channel (S3 bucket, SNS topic, etc.) to deliver AWS Config data."
        })

    return findings
