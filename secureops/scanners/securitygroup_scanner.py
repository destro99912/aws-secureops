import botocore.exceptions

def scan_security_groups(session):
    """
    Scans AWS Security Groups for security posture issues. Does not modify any resources.
    
    Args:
        session (boto3.Session): An active boto3 session.
        
    Returns:
        list: A list of dict findings representing security issues.
    """
    findings = []
    service_name = "EC2 Security Groups"
    
    try:
        client = session.client("ec2")
    except Exception as e:
        findings.append({
            "service": service_name,
            "severity": "CRITICAL",
            "title": "Could Not Initialize EC2 Client",
            "resource": "EC2 Service",
            "evidence": str(e),
            "recommendation": "Verify your AWS session, credentials, and region config."
        })
        return findings

    # Step 1: Collect all security groups in use by Network Interfaces (to find unused ones)
    in_use_sg_ids = set()
    has_eni_permission = True
    try:
        paginator = client.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []):
                for group in eni.get("Groups", []):
                    if "GroupId" in group:
                        in_use_sg_ids.add(group["GroupId"])
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            has_eni_permission = False
            findings.append({
                "service": service_name,
                "severity": "MEDIUM",
                "title": "Access Denied: Describe Network Interfaces",
                "resource": "Network Interfaces",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'ec2:DescribeNetworkInterfaces' permissions to scan for unused security groups."
            })
        else:
            has_eni_permission = False
            findings.append({
                "service": service_name,
                "severity": "MEDIUM",
                "title": "Could Not Describe Network Interfaces",
                "resource": "Network Interfaces",
                "evidence": str(e),
                "recommendation": "Ensure correct EC2 permissions to check for network interfaces."
            })
    except Exception as e:
        has_eni_permission = False
        findings.append({
            "service": service_name,
            "severity": "MEDIUM",
            "title": "Could Not Describe Network Interfaces",
            "resource": "Network Interfaces",
            "evidence": str(e),
            "recommendation": "Investigate errors describing Network Interfaces."
        })

    # Step 2: List and scan Security Groups
    security_groups = []
    try:
        paginator = client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            security_groups.extend(page.get("SecurityGroups", []))
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            findings.append({
                "service": service_name,
                "severity": "HIGH",
                "title": "Access Denied: Describe Security Groups",
                "resource": "Security Groups",
                "evidence": str(e),
                "recommendation": "Ensure the scanner identity has 'ec2:DescribeSecurityGroups' permissions."
            })
        else:
            findings.append({
                "service": service_name,
                "severity": "MEDIUM",
                "title": "Could Not Describe Security Groups",
                "resource": "Security Groups",
                "evidence": str(e),
                "recommendation": "Ensure correct EC2 permissions."
            })
        return findings
    except Exception as e:
        findings.append({
            "service": service_name,
            "severity": "MEDIUM",
            "title": "Could Not Describe Security Groups",
            "resource": "Security Groups",
            "evidence": str(e),
            "recommendation": "Investigate errors listing security groups."
        })
        return findings

    db_ports = {
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "SQL Server",
        27017: "MongoDB",
        6379: "Redis"
    }

    # Step 3: Scan each security group
    for sg in security_groups:
        try:
            sg_id = sg.get("GroupId")
            sg_name = sg.get("GroupName", "")
            resource_name = f"{sg_id} ({sg_name})" if sg_name else sg_id
            
            # Check 5: Unused Security Group
            if has_eni_permission and sg_id not in in_use_sg_ids:
                findings.append({
                    "service": service_name,
                    "severity": "LOW",
                    "title": "Unused Security Group",
                    "resource": resource_name,
                    "evidence": "Security group is not attached to any network interface in the region.",
                    "recommendation": "Review and remove unused security groups to maintain a clean and secure AWS environment."
                })

            # Check rules
            for rule in sg.get("IpPermissions", []):
                ip_protocol = rule.get("IpProtocol")
                
                # Check for public sources (0.0.0.0/0 or ::/0)
                public_sources = []
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")
                    if cidr == "0.0.0.0/0":
                        public_sources.append("0.0.0.0/0")
                for ipv6_range in rule.get("Ipv6Ranges", []):
                    cidr_ipv6 = ipv6_range.get("CidrIpv6")
                    if cidr_ipv6 == "::/0":
                        public_sources.append("::/0")
                
                if not public_sources:
                    continue
                
                sources_str = ", ".join(public_sources)
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                
                # Check 3: All Traffic Open To Internet
                if ip_protocol == "-1":
                    findings.append({
                        "service": service_name,
                        "severity": "CRITICAL",
                        "title": "All Traffic Open To Internet",
                        "resource": resource_name,
                        "evidence": f"Protocol: All Traffic, Source: {sources_str}",
                        "recommendation": "Limit security group rules to only the required ports and protocols from specific trusted sources."
                    })
                    # Skip check of individual ports if all traffic is open
                    continue

                if ip_protocol == "tcp":
                    # Check range matches helper
                    def is_port_in_range(port):
                        if from_port is not None and to_port is not None:
                            return from_port <= port <= to_port
                        return False

                    # Check 1: SSH Open To Internet
                    if is_port_in_range(22):
                        findings.append({
                            "service": service_name,
                            "severity": "HIGH",
                            "title": "SSH Open To Internet",
                            "resource": resource_name,
                            "evidence": f"Protocol: TCP, Port Range: {from_port}-{to_port}, Source: {sources_str}",
                            "recommendation": "Restrict inbound port 22 access to specific trusted IP ranges instead of the entire internet."
                        })
                    
                    # Check 2: RDP Open To Internet
                    if is_port_in_range(3389):
                        findings.append({
                            "service": service_name,
                            "severity": "HIGH",
                            "title": "RDP Open To Internet",
                            "resource": resource_name,
                            "evidence": f"Protocol: TCP, Port Range: {from_port}-{to_port}, Source: {sources_str}",
                            "recommendation": "Restrict inbound port 3389 access to specific trusted IP ranges instead of the entire internet."
                        })

                    # Check 4: Database Port Open To Internet
                    for db_port, db_name in db_ports.items():
                        if is_port_in_range(db_port):
                            findings.append({
                                "service": service_name,
                                "severity": "CRITICAL",
                                "title": "Database Port Open To Internet",
                                "resource": resource_name,
                                "evidence": f"Protocol: TCP, Port Range: {from_port}-{to_port} (contains {db_name} port {db_port}), Source: {sources_str}",
                                "recommendation": f"Restrict database port access to authorized application security groups or specific trusted IP ranges."
                            })
                            
        except Exception as e:
            # Handle failure on one security group gracefully without stopping the scan
            findings.append({
                "service": service_name,
                "severity": "LOW",
                "title": "Error Scanning Security Group",
                "resource": sg.get("GroupId", "Unknown SG"),
                "evidence": str(e),
                "recommendation": "Investigate execution errors for this security group."
            })
            
    return findings
