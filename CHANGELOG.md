# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.0] - 2026-06-27

### Added
- **Core Session Management**: Simple AWS CLI profile session retriever.
- **IAM Scanner**: Audits active access keys, MFA, and root account activity.
- **S3 Scanner**: Scans for public access block configuration, default encryption, and secure transport (SSL/TLS) policies.
- **CloudTrail Scanner**: Validates logging status and multi-region organization logging.
- **AWS Config Scanner**: Verifies if AWS Config recorders and delivery channels are active.
- **GuardDuty Scanner**: Identifies if Amazon GuardDuty is enabled.
- **Security Hub Scanner**: Checks if AWS Security Hub is enabled.
- **Amazon Inspector Scanner**: Checks if Amazon Inspector is configured and scanning for vulnerabilities.
- **AWS KMS Scanner**: Audits KMS key policies, rotation, and usage.
- **EC2 Security Group Scanner**: Inspects security groups for open SSH (22), RDP (3389), database ports (3306, 5432, 1433, 27017, 6379), all traffic (`-1`) rules exposed to the internet (`0.0.0.0/0`, `::/0`), and identifies unused security groups.
