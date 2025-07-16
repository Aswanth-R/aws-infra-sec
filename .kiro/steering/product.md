# AWS Sentinel Product Overview

AWS Sentinel is a command-line security scanner for AWS resources that identifies common security vulnerabilities and misconfigurations in AWS accounts.

## Core Purpose
- Automated security scanning of AWS environments
- Detection of common security issues across multiple AWS services
- Multiple output formats for integration with security workflows

## Key Features
- **S3 Security**: Identifies publicly accessible buckets
- **EC2 Security**: Finds security groups with SSH (port 22) open to public
- **EBS Security**: Detects unencrypted volumes
- **IAM Security**: Identifies users without Multi-Factor Authentication (MFA)

## Target Users
- DevOps engineers and security professionals
- AWS administrators managing cloud security
- Teams implementing security compliance checks

## Output Formats
- Table format (default, human-readable)
- JSON format (for automation and integration)
- CSV format (for reporting and analysis)

## Security Focus
The tool prioritizes HIGH severity issues like public access and missing MFA, with MEDIUM severity for encryption-related findings.