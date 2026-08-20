# Example Reports

`aws-secureops-demo-report.json` is a **synthetic demonstration report**. It
does not contain any customer, employer, or production AWS data of any kind.

## How it was generated

- The report was produced by [`scripts/generate_demo_report.py`](../../scripts/generate_demo_report.py),
  which builds `Finding` objects directly in memory using obviously
  synthetic resource identifiers (`sg-demo-001`, `i-demo-web-01`,
  `vol-demo-001`, etc.).
- The script never calls `boto3`, never creates an AWS session, and makes no
  network request of any kind.
- The report itself was generated through AWS SecureOps' real, unmodified
  production code path: `build_json_report()`, `write_json_report()`, and
  `calculate_assessment()` from `secureops/core/reporting.py` and
  `secureops/core/scoring.py`. Nothing about the report schema was
  special-cased for this example.

## What it demonstrates

- A mix of representative posture findings (SSH exposure, IMDSv2 not
  enforced, an unencrypted EBS volume, exposed SIP/SIP-TLS ports, a broad
  UDP port range, and a root-account MFA gap) at their real scanner
  severities.
- A degraded assessment coverage scenario: one finding
  (`Scanner Permission Error: Access Denied for Describe Hub`) represents a
  case where AWS SecureOps could not fully assess a service due to a
  permission gap. That finding does **not** contribute to the risk score —
  it only marks `coverage_status` as `DEGRADED` and increments
  `coverage_issue_count`. This shows that missing permissions can never
  silently inflate (or hide) the reported risk.

## About AWS SecureOps

AWS SecureOps is a strictly **read-only** posture scanner: it only calls
read/describe/list AWS APIs and never modifies AWS resources.

The `risk_score` in the report is a transparent, deterministic **posture
risk score** — a capped sum of severity weights across observed findings.
It is **not** a compliance certification, an audit attestation, or a
prediction of breach/exploitability likelihood. It is a simple signal meant
to help prioritize review, nothing more.
