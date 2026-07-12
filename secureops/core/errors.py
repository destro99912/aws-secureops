import botocore.exceptions
from core.models import Finding

ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
}

def create_permission_finding(
    *,
    service: str,
    operation: str,
    resource: str,
    required_permission: str,
    error: Exception,
    severity: str = "MEDIUM",
    region: str | None = None,
) -> Finding:
    """
    Creates a standardized Finding for AWS permission errors (Access Denied).
    Only standardizes confirmed permission-denial codes. Otherwise, returns a generic
    scanner execution error finding.
    """
    error_code = "UnknownError"
    if isinstance(error, botocore.exceptions.ClientError):
        error_code = error.response.get("Error", {}).get("Code", "")

    if error_code in ACCESS_DENIED_CODES:
        title = f"Scanner Permission Error: Access Denied for {operation}"
        evidence = f"Lacks '{required_permission}' permission. Code: {error_code}. Details: {str(error)}"
        recommendation = f"Ensure the scanner IAM identity is granted the '{required_permission}' permission."
    else:
        title = f"Scanner Execution Error: Unable to perform {operation}"
        evidence = f"Unexpected error during {operation}. Code: {error_code}. Details: {str(error)}"
        recommendation = f"Verify credentials, network connectivity, and service availability for '{service}'."

    return Finding(
        service=service,
        severity=severity,
        title=title,
        resource=resource,
        evidence=evidence,
        recommendation=recommendation,
        region=region
    )
