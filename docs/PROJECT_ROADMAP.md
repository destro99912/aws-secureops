# AWS SecureOps Project Roadmap

This document outlines the long-term vision, current status, and future milestones for AWS SecureOps.

---

## 1. Completed

We have built a simple, modular, and educational CLI tool to assess the security posture of an AWS account. The following infrastructural milestones and scanners are fully operational:

### Infrastructure & Core
- **Typed Finding Model**: Unified all scanner outputs to return structured `Finding` dataclass objects rather than raw dictionaries.
- **Unit Testing Engine**: Integrated a full mock-based test suite using botocore's `Stubber` to validate scan logic safely.
- **Standard Credential Provider Chain**: Replaced custom configuration defaults with boto3's standard credential resolution pipeline.
- **CLI Profile & Region Support**: Added native command-line option flags (`--profile` and `--region`) powered by python's `argparse`.

### Scanners
- **IAM**: Audits active credentials, MFA, and general user posture.
- **S3**: Inspects bucket public access block, default encryption, and secure transit policies.
- **CloudTrail**: Verifies trail logging status.
- **AWS Config**: Checks if configuration recording is active.
- **GuardDuty**: Verifies GuardDuty protection status.
- **Security Hub**: Checks for active hub subscriptions.
- **Amazon Inspector**: Verifies automated vulnerability scanning status.
- **KMS**: Audits key policies and key rotation settings.
- **EC2 Security Groups**: Audits exposed management ports (SSH/22, RDP/3389), database ports, open protocols, and unused security groups.

---

## 2. Compute Security (Next Phase)

Upcoming checks targeting EC2 compute security and instance configurations:

- [ ] **EC2 Scanner**: Audit security settings of running EC2 instances, public IP addresses, and SSH keys.
- [ ] **EBS**: Audit unencrypted EBS volumes and publicly shared snapshots.
- [ ] **IMDSv2**: Ensure Instance Metadata Service Version 2 is enforced on all instances (disabling IMDSv1).
- [ ] **Instance Profiles**: Check for over-privileged EC2 role associations.
- [ ] **Monitoring**: Audit host logs configurations and security agent statuses.

---

## 3. Storage & Databases

Future scanner modules to cover essential storage and database layers in AWS:

- [ ] **RDS**: Check for public accessibility, encryption status, and automated backups.
- [ ] **Secrets Manager**: Audit secrets rotation and resource-based access policies.
- [ ] **Macie**: Verify if automated sensitive data discovery is enabled.

---

## 4. Detection & Edge Security

Expanded checks for auditing monitoring, control plane policies, and network edge defenses:

- [ ] **CloudWatch**: Verify alarm configuration for critical security actions.
- [ ] **IAM Access Analyzer**: Check if Access Analyzer is active.
- [ ] **Organizations**: Audit service control policies (SCPs) and configuration.
- [ ] **WAF (Web Application Firewall)**: Verify association with CloudFront distributions and ALBs.
- [ ] **Shield**: Verify Advanced DDoS protection status.

---

## 5. Reporting & Enhancements

Visualizing and extracting findings in different document formats:

- [ ] **Multi-Region Scanning**: Sequentially query all active AWS regions instead of scanning a single target region.
- [ ] **JSON Report Export**: Output scan results to a structured JSON file for API/CI-CD ingestion.
- [ ] **Risk Score Calculation**: Implement a simple grading system (A-F) based on severity weights.
- [ ] **Configuration File**: Support scanning scopes, exclusions, and custom rules via a YAML config file.
- [ ] **Finding Suppression**: Allow users to mark specific resources or checks to be ignored in subsequent runs.
- [ ] **HTML & PDF Reports**: Generate executive-ready visual HTML dashboards and audit summaries.
