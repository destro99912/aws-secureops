# Contributing to AWS SecureOps

Thank you for your interest in contributing to AWS SecureOps! We welcome community contributions to make this educational security tool better.

## Project Goals

- **Educational**: Keep the code clean, linear, and well-commented so it serves as an educational resource for AWS security auditing.
- **Read-Only**: The tool must remain strictly read-only. It should never perform modifying actions on AWS resources.
- **Simplicity**: Maintain a direct, flat, and beginner-friendly structure. Avoid overly complex abstraction layers.

## Folder Structure

```text
secureops/
├── core/
│   └── aws_session.py        # AWS session initialization helper
├── scanners/
│   ├── iam_scanner.py        # IAM security checks
│   ├── s3_scanner.py        # S3 security checks
│   ├── ...
│   └── securitygroup_scanner.py # Security Groups checks
└── main.py                   # Main orchestrator / CLI entry point
```

## Coding Style

- Follow PEP 8 guidelines.
- Keep execution paths simple and readable.
- Provide clear docstrings explaining the purpose of each scanning function.
- Include descriptive error handling to capture AWS access issues (like `AccessDenied` or `UnauthorizedOperation`) without crashing the application.

## Scanner Development Guidelines

When creating or updating a scanner, follow these rules:

1. **Naming Conventions**: Name scanner files in snake_case ending with `_scanner.py` (e.g. `kms_scanner.py`).
2. **Main Function**: Define a single entry point named `scan_<service>(session) -> list[Finding]` that takes a `boto3.Session` object.
3. **Finding Object Usage**: Every issue must return a typed `Finding` dataclass object. Import it from `core.models`:
   ```python
   from core.models import Finding
   
   Finding(
       service="KMS",
       severity="HIGH",
       title="KMS Key Disabled",
       resource="arn:aws:kms:...",
       evidence="KMS key is currently disabled.",
       recommendation="Review whether the key should remain disabled or be re-enabled if actively required."
   )
   ```
4. **Handling Permission Errors**: If a read API call fails due to permission errors (e.g. `AccessDenied`), do not let the scanner crash. Standardize permission findings using the `create_permission_finding` helper from `core.errors`:
   ```python
   from core.errors import create_permission_finding
   # Inside except botocore.exceptions.ClientError block
   create_permission_finding(
       service="KMS",
       operation="List Keys",
       resource="KMS Keys",
       required_permission="kms:ListKeys",
       error=e,
       severity="HIGH"
   )
   ```
5. **Unit Tests**: Every new scanner must be accompanied by mock-based tests under `tests/scanners/test_<service>_scanner.py`. Unit tests must leverage botocore's `Stubber` or `unittest.mock` to validate code flows without attempting live network connections.
6. **Integration**: Update `secureops/main.py` to import and execute the new scanner, compiling its results into the console output engine.

## Pull Request Process

1. Fork the repository and create a descriptive branch.
2. Implement your scanner or fix.
3. Test your changes locally against a sandbox AWS account.
4. Ensure code formatting is clean.
5. Submit a pull request detailing the new check, tested resources, and sample CLI output.
