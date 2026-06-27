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
2. **Main Function**: Define a single entry point named `scan_<service>(session)` that takes a `boto3.Session` object.
3. **Finding Dictionary Schema**: Every issue must return a dictionary conforming to the standard structure:
   ```python
   {
       "service": "<Service Name>",
       "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
       "title": "<Short Descriptive Title>",
       "resource": "<Resource ID or Name>",
       "evidence": "<Details of the issue, e.g. Port Range, Policy statement>",
       "recommendation": "<Actionable fix recommendation>"
   }
   ```
4. **Integration**: Update `secureops/main.py` to import and execute the new scanner, append findings to the consolidated list, and update summary outputs.

## Pull Request Process

1. Fork the repository and create a descriptive branch.
2. Implement your scanner or fix.
3. Test your changes locally against a sandbox AWS account.
4. Ensure code formatting is clean.
5. Submit a pull request detailing the new check, tested resources, and sample CLI output.
