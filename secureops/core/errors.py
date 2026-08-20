import botocore.exceptions
from secureops.core.models import Finding

ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
}

def _get_error_code(error: Exception) -> str:
    if isinstance(error, botocore.exceptions.ClientError):
        return error.response.get("Error", {}).get("Code", "") or "UnknownError"
    return "UnknownError"


def sanitize_error(error: Exception) -> str:
    """
    Produces a safe, user-facing evidence string for an exception.
    Never includes raw SDK exception text, request IDs, HTTP metadata,
    account IDs, or ARNs.
    """
    error_code = _get_error_code(error)
    if error_code != "UnknownError":
        return f"AWS error occurred. AWS error code: {error_code}."
    return "An unexpected error occurred while contacting AWS."


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
    error_code = _get_error_code(error)

    if error_code in ACCESS_DENIED_CODES:
        title = f"Scanner Permission Error: Access Denied for {operation}"
        evidence = f"Lacks '{required_permission}' permission. AWS error code: {error_code}."
        recommendation = f"Ensure the scanner IAM identity is granted the '{required_permission}' permission."
    else:
        title = f"Scanner Execution Error: Unable to perform {operation}"
        evidence = f"Unexpected error during {operation}. AWS error code: {error_code}."
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
