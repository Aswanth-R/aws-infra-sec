
# AWS InfraSec

AWS InfraSec is a comprehensive command-line security scanner for AWS resources. It helps identify security issues and misconfigurations across multiple AWS services to strengthen your cloud security posture.

## Features

AWS InfraSec performs security checks across **10+ AWS services** with **25+ security validations**:

### 🪣 **S3 Security**
- Public bucket detection
- Bucket encryption validation
- Access logging configuration

### 🖥️ **EC2 & EBS Security**
- Security groups with SSH/RDP open to public (0.0.0.0/0)
- Unencrypted EBS volumes
- Public EBS snapshots
- Public AMI detection
- EC2 detailed monitoring status
- Default security group usage

### 👤 **IAM Security**
- Users without Multi-Factor Authentication (MFA)
- Unused credentials detection
- Access key rotation validation
- Password policy compliance
- Wildcard permission policies
- Overly permissive trust relationships

### 📊 **CloudTrail Security**
- Trail logging status
- Log file validation
- Management event logging
- Multi-region trail coverage

### 🗄️ **RDS Security**
- Publicly accessible RDS instances
- Unencrypted RDS instances
- Insufficient backup retention periods
- Public RDS snapshots

### ⚡ **Lambda Security**
- Overly permissive execution roles
- Environment variable encryption
- VPC configuration validation
- Runtime version compliance

### 🌐 **VPC & Network Security**
- VPC Flow Logs configuration
- Overly permissive Network ACLs
- Broad route table routes

### 🌍 **Route53 Security**
- Query logging configuration
- Wildcard DNS records detection

### 🔒 **Enhanced IAM Analysis**
- Advanced policy analysis
- Cross-account trust relationships
- Service-linked role validation

## Installation

You can install AWS InfraSec using pip:

```bash
pip install aws-infrasec
```

Or using uv
```bash
uv pip install aws-infrasec
```

## Usage

### Basic Usage

Run a full security scan using your default AWS profile:

```bash
aws-infrasec scan
```

If you don't specify a profile or region, it will use the default profile and `us-east-1` region.

### Command Options

```
Usage: aws-infrasec scan [OPTIONS]

  Run a comprehensive security scan on your AWS resources.

  Security Check Categories:
  • s3          - S3 bucket public access vulnerabilities
  • ec2         - EC2 security groups, monitoring, and AMI issues
  • ebs         - EBS volume encryption and snapshot exposure
  • iam         - IAM users without MFA and basic access issues
  • cloudtrail  - CloudTrail logging and validation configuration
  • rds         - RDS instance security and snapshot exposure
  • lambda      - Lambda function security and configuration issues
  • vpc         - VPC network security and flow log configuration
  • route53     - Route53 DNS security and logging configuration
  • iam-enhanced- Advanced IAM policy and access key analysis

Options:
  --profile TEXT                  AWS profile to use for authentication (from
                                  ~/.aws/credentials)
  --region TEXT                   AWS region to scan for security issues
  --checks TEXT                   Comma-separated list of checks to run.
                                  Available: s3, ec2, ebs, iam, cloudtrail, rds,
                                  lambda, vpc, route53, iam-enhanced, or "all"
  --output [table|json|csv|html]  Output format for scan results
  --severity [low|medium|high|all]
                                  Filter results by minimum severity level
  -v, --verbose                   Enable verbose output
  -h, --help                      Show this message and exit.
```

### Examples

**Run a comprehensive scan with all security checks:**
```bash
aws-infrasec scan --checks all
```

**Run a scan with specific AWS profile and region:**
```bash
aws-infrasec scan --profile production --region us-west-2
```

**Run targeted security checks:**
```bash
# Basic security essentials
aws-infrasec scan --checks s3,iam,ec2

# Database and storage security
aws-infrasec scan --checks rds,ebs,s3

# Network and infrastructure security
aws-infrasec scan --checks vpc,ec2,cloudtrail

# Serverless security
aws-infrasec scan --checks lambda,iam-enhanced
```

**Export results in different formats:**
```bash
# JSON format for automation
aws-infrasec scan --output json > security_report.json

# CSV format for spreadsheet analysis
aws-infrasec scan --output csv > security_report.csv

# HTML format for web viewing
aws-infrasec scan --output html > security_report.html
```

**Filter by severity levels:**
```bash
# Show only critical issues
aws-infrasec scan --severity high

# Show medium and high severity issues
aws-infrasec scan --severity medium

# Show all issues including recommendations
aws-infrasec scan --severity low
```

**Advanced usage:**
```bash
# Comprehensive production scan
aws-infrasec scan --profile prod --region us-west-2 --checks all --severity high --output json

# Quick security assessment
aws-infrasec scan --checks s3,iam,ec2 --severity high

# Detailed verbose output
aws-infrasec scan --checks all --verbose
```

## Example Output

### Table Format (Default)

```bash
 █████╗ ██╗    ██╗███████╗    ██╗███╗   ██╗███████╗██████╗  █████╗ ███████╗███████╗ ██████╗
██╔══██╗██║    ██║██╔════╝    ██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
███████║██║ █╗ ██║███████╗    ██║██╔██╗ ██║█████╗  ██████╔╝███████║███████╗█████╗  ██║     
██╔══██║██║███╗██║╚════██║    ██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║╚════██║██╔══╝  ██║     
██║  ██║╚███╔███╔╝███████║    ██║██║ ╚████║██║     ██║  ██║██║  ██║███████║███████╗╚██████╗
╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝    ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
                                                                        
                       AWS Security InfraSec

Scanning AWS account using profile: default in region: us-east-1
Initializing security checks...

+------------+----------------------------------------------------------+--------------------------------------------------+----------+
|                                              AWS Security Issues Detected                                                    |
+------------+----------------------------------------------------------+--------------------------------------------------+----------+
| Service    | Resource                                                 | Issue                                            | Severity |
+------------+----------------------------------------------------------+--------------------------------------------------+----------+
| S3         | public-bucket                                            | Public bucket                                    | HIGH     |
| EC2        | sg-12345abcde                                            | Security group with port 22 open to public      | HIGH     |
| EBS        | vol-67890fghij                                           | Unencrypted volume                               | MEDIUM   |
| IAM        | alice                                                    | User without MFA                                 | HIGH     |
| CloudTrail | audit-trail                                              | Trail not logging                                | HIGH     |
| RDS        | prod-database                                            | Publicly accessible RDS instance                 | HIGH     |
| Lambda     | data-processor                                           | Function with overly permissive execution role   | HIGH     |
| VPC        | vpc-12345678                                             | VPC without flow logs enabled                    | MEDIUM   |
| Route53    | example.com                                              | Wildcard DNS record detected                     | MEDIUM   |
| IAM        | service-account:policy-name                              | Policy with wildcard permissions                 | HIGH     |
+------------+----------------------------------------------------------+--------------------------------------------------+----------+

Scan complete. Found 10 security issues.
```

### JSON Format

```json
{
  "scan_results": {
    "profile": "default",
    "region": "us-east-1",
    "scan_time": "2025-07-16T15:32:17.654321",
    "issues_count": 10,
    "issues": [
      {
        "service": "S3",
        "resource": "public-bucket",
        "issue": "Public bucket",
        "severity": "HIGH"
      },
      {
        "service": "EC2",
        "resource": "sg-12345abcde",
        "issue": "Security group with port 22 open to public",
        "severity": "HIGH"
      },
      {
        "service": "CloudTrail",
        "resource": "audit-trail",
        "issue": "Trail not logging",
        "severity": "HIGH"
      },
      {
        "service": "RDS",
        "resource": "prod-database",
        "issue": "Publicly accessible RDS instance",
        "severity": "HIGH"
      },
      {
        "service": "Lambda",
        "resource": "data-processor",
        "issue": "Function with overly permissive execution role",
        "severity": "HIGH"
      }
    ]
  }
}
```

### CSV Format

```csv
Service,Resource,Issue,Severity
S3,public-bucket,Public bucket,HIGH
EC2,sg-12345abcde,Security group with port 22 open to public,HIGH
EBS,vol-67890fghij,Unencrypted volume,MEDIUM
IAM,alice,User without MFA,HIGH
CloudTrail,audit-trail,Trail not logging,HIGH
RDS,prod-database,Publicly accessible RDS instance,HIGH
Lambda,data-processor,Function with overly permissive execution role,HIGH
VPC,vpc-12345678,VPC without flow logs enabled,MEDIUM
Route53,example.com,Wildcard DNS record detected,MEDIUM
IAM,service-account:policy-name,Policy with wildcard permissions,HIGH
```

## Security Coverage

### Severity Levels

- **🔴 HIGH**: Critical security issues requiring immediate attention
  - Public access to resources
  - Missing MFA on privileged accounts
  - Overly permissive policies
  - Disabled security logging

- **🟡 MEDIUM**: Important security improvements
  - Unencrypted data at rest
  - Missing monitoring/logging
  - Suboptimal configurations

- **🟢 LOW**: Security best practices and recommendations
  - Configuration optimizations
  - Compliance improvements

### Compliance Frameworks

AWS InfraSec checks align with multiple security frameworks:
- **AWS Well-Architected Framework** - Security Pillar
- **CIS AWS Foundations Benchmark** - Selected controls
- **AWS Security Best Practices**
- **NIST Cybersecurity Framework** - Protect function

## Requirements

- **Python 3.9+**
- **AWS credentials configured** (via AWS CLI, environment variables, or IAM roles)
- **Required AWS permissions** to access resources (see below)

### AWS Permissions

AWS InfraSec requires read-only permissions for the following AWS services:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetAccountPasswordPolicy",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListRoles",
        "iam:GetRole",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSnapshotAttributes",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "lambda:GetPolicy",
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",
        "route53:GetQueryLoggingConfig"
      ],
      "Resource": "*"
    }
  ]
}
```

### Minimal IAM Policy

For basic security scanning, you can use this minimal policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "iam:ListUsers",
        "iam:ListMFADevices"
      ],
      "Resource": "*"
    }
  ]
}
```

## Development

To set up the project for development:

1. Clone the repository:

    ```bash
    git clone https://github.com/aswanth/aws-infrasec.git
    cd aws-infrasec
    ```

2. Create a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate    
    ```

3. Install development dependencies:

    ```bash
    pip install -e '.[dev]'
    ```

4. Run the tests:

    ```bash
    # Run all tests
    python -m unittest discover tests
    
    # Run specific test categories
    python -m pytest tests/test_aws_infrasec.py -v
    python -m pytest tests/test_end_to_end.py -v
    python -m pytest tests/test_lambda_checks.py -v
    ```

### Project Structure

```
aws-infrasec/
├── aws_infrasec/          # Main package
│   ├── __init__.py        # Package initialization
│   ├── cli.py             # Command-line interface
│   ├── core.py            # Security check functions
│   ├── utils.py           # Utility functions
│   └── ascii_art.py       # Visual branding
├── tests/                 # Test suite
│   ├── test_aws_infrasec.py      # Core function tests
│   ├── test_end_to_end.py        # Integration tests
│   ├── test_lambda_checks.py     # Lambda-specific tests
│   └── end_to_end_validation_report.md
├── README.md              # This file
├── setup.py               # Package configuration
└── requirements.txt       # Dependencies
```

### Testing

The project includes comprehensive test coverage:
- **Unit Tests**: Individual security check functions
- **Integration Tests**: Complete CLI workflow testing
- **End-to-End Tests**: Full scan validation with mocked AWS services
- **Performance Tests**: Execution time and resource usage validation

### Adding New Security Checks

To add a new security check:

1. **Implement the check function** in `aws_infrasec/core.py`
2. **Add CLI integration** in `aws_infrasec/cli.py`
3. **Write comprehensive tests** in `tests/`
4. **Update documentation** in README.md

## License

This project is licensed under the MIT License.  
Original project by [Rishab Kumar](https://github.com/rishabkumar7/aws-sentinel).  

## Contributing

Contributions are welcome! Please feel free to submit an Issue and a Pull Request.


