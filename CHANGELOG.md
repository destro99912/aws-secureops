# Changelog

All notable changes to this project will be documented in this file.

## [v0.2.0] - 2026-08-21

### Added
- **EC2 instance scanner**: flags running EC2 instances with a public IPv4 address (posture signal, not a confirmed exposure).
- **IMDSv2 enforcement checks**: flags instances where `MetadataOptions.HttpTokens` is not `"required"`, including when metadata options are unavailable.
- **EBS encryption assessment**: flags unencrypted EBS volumes (`Encrypted == false`).
- **Communications-aware security-group exposure checks**: SIP (port 5060, TCP/UDP), SIP-TLS (port 5061, TCP), and broad public UDP port ranges (≥1000 ports) exposed to `0.0.0.0/0`/`::/0`. These flag exposure only and do not claim a SIP/RTP service is confirmed running or vulnerable.
- **JSON report export** (`--output-json PATH`): writes a sanitized, structured JSON report via `secureops/core/reporting.py`.
- **Posture risk scoring**: a deterministic, severity-weighted score (0–100) computed from posture findings only, via `secureops/core/scoring.py`.
- **Assessment coverage status**: `COMPLETE`/`DEGRADED` plus a coverage issue count, tracked separately so permission/scanner errors never inflate or deflate the risk score.
- **Synthetic demonstration report**: a sanitized, entirely fabricated example report under `docs/examples/`, generated through the real reporting/scoring code.

### Security
- Removed AWS account ID, ARN, and UserId from console output on successful authentication.
- Sanitized all AWS error output (permission and generic scanner errors): raw AWS exception text, request IDs, and HTTP response metadata are no longer surfaced in findings or CLI error output.
- Removed access-key identifiers (`AccessKeyId`) from IAM findings.
- Corrected IAM active-access-key handling: only keys with `Status == "Active"` count toward "Active Access Keys Found" and key-age checks; inactive keys no longer generate findings.

### Changed / Fixed
- Switched all internal imports to package-qualified form (`secureops.core...`, `secureops.scanners...`), fixing test collection and consistent execution.
- Corrected CLI documentation and `--help` examples to the supported invocation, `python -m secureops.main` (direct script invocation, `python secureops/main.py`, no longer works with package-qualified imports).
- Added/expanded test coverage for all of the above: EC2/EBS scanning, communications SG checks, error sanitization, JSON reporting, posture scoring, and CLI behavior (124 tests passing as of this entry).

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
