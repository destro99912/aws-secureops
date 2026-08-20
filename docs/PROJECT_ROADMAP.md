# AWS SecureOps Project Roadmap

This document outlines the current status and future milestones for AWS SecureOps. AWS SecureOps is a **read-only** AWS cloud security posture assessment tool — this roadmap does not include auto-remediation, compliance certification, or AI-generated remediation; any exploratory work in those directions would be clearly marked as such if it is ever added.

---

## 1. Completed (v0.1.0)

- **Typed Finding Model**: Unified all scanner outputs to return structured `Finding` dataclass objects rather than raw dictionaries.
- **Unit Testing Engine**: Mock-based test suite using botocore's `Stubber` to validate scan logic without live AWS calls.
- **Standard Credential Provider Chain**: boto3's standard credential resolution pipeline.
- **CLI Profile & Region Support**: `--profile` and `--region` flags via `argparse`.
- **Scanners**: IAM, S3, CloudTrail, AWS Config, GuardDuty, Security Hub, Amazon Inspector, KMS (key state/rotation only), EC2 Security Groups (management/database ports, all-traffic, unused groups).

---

## 2. Completed (v0.2.0)

### Security & correctness hardening
- Removed AWS account ID, ARN, and UserId from console output on successful authentication.
- Sanitized all AWS error output (permission and generic scanner errors) so raw SDK exception text, request IDs, and HTTP metadata are never surfaced.
- Corrected IAM active-access-key handling (only `Status == "Active"` keys count; access key IDs no longer appear in findings).
- Package-qualified imports (`secureops.core...`) and corrected CLI module-invocation documentation (`python -m secureops.main`).

### Compute security
- **EC2 instance scanner**: flags running instances with a public IPv4 address (posture signal, not a confirmed exposure).
- **IMDSv2 enforcement**: flags instances where `MetadataOptions.HttpTokens` is not `"required"`.
- **EBS encryption-at-rest assessment**: flags unencrypted EBS volumes.

### Communications-aware security-group exposure checks
- SIP (port 5060, TCP/UDP) exposure to `0.0.0.0/0`/`::/0`.
- SIP-TLS (port 5061, TCP) exposure to `0.0.0.0/0`/`::/0`.
- Broad public UDP port ranges (≥1000 ports) exposure to `0.0.0.0/0`/`::/0`.
- These are exposure/posture signals only — they do not confirm that a SIP/RTP or other communications service is actually running or vulnerable.

### Reporting & assessment
- **JSON report export** (`--output-json PATH`), built from a sanitized, versioned report schema.
- **Posture risk score**: deterministic, severity-weighted, bounded 0–100, posture findings only.
- **Assessment coverage status**: `COMPLETE`/`DEGRADED` plus a coverage issue count, tracked separately from the risk score.
- **Sanitized synthetic example report** under `docs/examples/`, generated through the real reporting/scoring code with no real AWS data.

---

## 3. Future / Planned

These are directional ideas, not commitments, and none of them include auto-remediation, compliance certification, or AI-generated remediation:

- **Multi-region orchestration**: sequentially scan multiple/all active AWS regions instead of a single target region.
- **Structured control/check identifiers**: stable IDs per check instead of relying on title text.
- **Structured finding categories**: an explicit posture/coverage category on `Finding` (or a companion structure) instead of classifying scanner errors by title prefix.
- **Configurable scoring weights**: allow adjusting severity weights instead of the current fixed values.
- **Finding suppression / allowlists**: let users mark specific resources or checks to ignore in subsequent runs.
- **HTML reporting**: a human-readable report format alongside JSON.
- **Additional AWS service coverage**: e.g. RDS, Secrets Manager, Macie, CloudWatch alarms, IAM Access Analyzer, Organizations SCPs, WAF, Shield.
- **Enhanced communications-context correlation**: cross-referencing SG exposure with other signals (e.g. attached ENIs, associated load balancers) to reduce false positives — still without active probing or packet inspection.
- **CI/CD integration**: running AWS SecureOps as part of a pipeline, likely built on top of the existing JSON report export.

Multi-region scanning, YAML configuration, and finding suppression remain unimplemented as of v0.2.0.
