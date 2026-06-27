# AWS SecureOps Project Roadmap

This document outlines the long-term vision, current status, and future goals for AWS SecureOps.

---

## 1. Completed

We have built a simple, modular, and educational CLI tool to assess the security posture of an AWS account. The following scanners are fully operational:

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

## 2. Short-Term Roadmap

We plan to add more read-only scanner modules to cover essential AWS services:

- [ ] **EBS**: Audit unencrypted EBS volumes and publicly shared snapshots.
- [ ] **RDS**: Check for public accessibility, encryption status, and automated backups.
- [ ] **CloudWatch**: Verify alarm configuration for critical security actions.
- [ ] **Secrets Manager**: Audit secrets rotation and resource-based access policies.
- [ ] **IAM Access Analyzer**: Check if Access Analyzer is active.
- [ ] **Macie**: Verify if automated sensitive data discovery is enabled.
- [ ] **Organizations**: Audit service control policies (SCPs) and configuration.
- [ ] **WAF (Web Application Firewall)**: Verify association with CloudFront distributions and ALBs.
- [ ] **Shield**: Verify Advanced DDoS protection status.

---

## 3. Mid-Term Roadmap

To make findings easier to consume for security teams and auditors:

- [ ] **JSON Report Export**: Output scan results to a structured JSON file for API/CI-CD ingestion.
- [ ] **HTML Report Export**: Build a clean, styled, self-contained HTML report with graphs.
- [ ] **PDF Report Export**: Generate professional audit-ready executive summary PDFs.
- [ ] **Risk Score Calculation**: Implement a simple grading system (A-F) based on severity weights.
- [ ] **Compliance Mapping**: Map findings to CIS Benchmarks and standard frameworks.

---

## 4. Long-Term Vision

Scaling the auditing capabilities to multi-tenant workloads:

- [ ] **Multi-Account Support**: Query multiple AWS accounts sequentially using cross-account IAM role assumption.
- [ ] **Auto-Remediation Suggestions**: Provide copy-pasteable AWS CLI commands and Terraform snippets to automatically resolve issues.
