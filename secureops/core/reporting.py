import json
from datetime import datetime, timezone
from typing import Any

from secureops.core.models import Finding
from secureops.core.version import AWS_SECUREOPS_VERSION

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def build_json_report(findings: list[Finding], region: str | None = None) -> dict[str, Any]:
    """
    Builds a JSON-serializable report dict from already-sanitized Finding objects.
    Contains only Finding data plus minimal, non-identifying scan metadata
    (no account ID, ARN, UserId, profile name, or credential data).
    """
    summary = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if finding.severity in summary:
            summary[finding.severity] += 1

    return {
        "tool": {
            "name": "AWS SecureOps",
            "version": AWS_SECUREOPS_VERSION,
        },
        "scan": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "region": region,
            "finding_count": len(findings),
        },
        "summary": summary,
        "findings": [finding.to_dict() for finding in findings],
    }


def write_json_report(report: dict[str, Any], path: str) -> None:
    """
    Writes a JSON report to a local filesystem path. Does not create parent
    directories. Raises OSError on failure; callers are responsible for
    handling it safely (no traceback / raw exception exposure).
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
