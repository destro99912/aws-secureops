# Security Policy

## Responsible Disclosure

We take the security of AWS SecureOps seriously. If you find a security vulnerability, please report it responsibly instead of opening a public issue.

## Reporting a Vulnerability

Please report security vulnerabilities by emailing the maintainer or opening a private draft security advisory on GitHub. 

When reporting, please include:
- A description of the issue.
- Steps to reproduce the issue.
- The potential impact.

We will acknowledge your report and work to resolve the issue as quickly as possible.

## Scope

This security policy applies only to the AWS SecureOps codebase itself. Since AWS SecureOps operates in a **strictly read-only mode** using standard AWS APIs via boto3, it does not modify any infrastructure or resources. 

However, users are responsible for securing the AWS credentials used to run the tool. Always run the tool using credentials with the minimum necessary read-only permissions.
