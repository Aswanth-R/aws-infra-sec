# Design Document

## Overview

This design extends AWS Sentinel with 11 additional security check functions across 6 AWS service categories, bringing the total from 4 to 15+ comprehensive security validations. The design maintains the existing architectural patterns while adding robust coverage for CloudTrail, RDS, Lambda, VPC networking, Route53, and enhanced IAM checks.

The enhanced security checks will integrate seamlessly with the existing CLI interface, supporting all current output formats and filtering options while maintaining backward compatibility.

## Architecture

### Core Design Principles

1. **Consistency**: New security check functions follow the same patterns as existing checks
2. **Modularity**: Each service category is logically grouped but independently testable
3. **Error Resilience**: Graceful handling of AWS API errors and missing permissions
4. **Extensibility**: Design allows for easy addition of future security checks

### Function Signature Pattern

All new security check functions will follow the established pattern:
```python
def check_security_issue(aws_client, **kwargs):
    """
    Check for specific security issue.
    
    Args:
        aws_client: Boto3 client for the relevant AWS service
        **kwargs: Optional parameters for filtering or configuration
        
    Returns:
        list: List of resource identifiers with security issues
    """
```

## Components and Interfaces

### Enhanced Core Module (`core.py`)

The core module will be extended with new security check functions organized by AWS service:

#### CloudTrail Security Checks
- `check_cloudtrail_logging(cloudtrail_client)` - Identifies trails not actively logging
- `check_cloudtrail_log_validation(cloudtrail_client)` - Finds trails without log file validation
- `check_cloudtrail_management_events(cloudtrail_client)` - Detects trails not logging management events

#### RDS Security Checks  
- `check_public_rds_instances(rds_client)` - Identifies publicly accessible RDS instances
- `check_unencrypted_rds_instances(rds_client)` - Finds RDS instances without encryption at rest
- `check_rds_backup_retention(rds_client)` - Detects instances with insufficient backup retention
- `check_public_rds_snapshots(rds_client)` - Identifies public RDS snapshots

#### Lambda Security Checks
- `check_lambda_execution_roles(lambda_client, iam_client)` - Identifies functions with overly permissive roles
- `check_lambda_environment_encryption(lambda_client)` - Finds functions without environment variable encryption
- `check_lambda_vpc_config(lambda_client, ec2_client)` - Detects functions in public subnets
- `check_lambda_runtime_versions(lambda_client)` - Identifies functions with outdated runtimes

#### VPC Security Checks
- `check_vpc_flow_logs(ec2_client)` - Identifies VPCs without flow logs enabled
- `check_permissive_nacls(ec2_client)` - Finds overly permissive Network ACL rules
- `check_broad_route_table_routes(ec2_client)` - Detects routes with overly broad CIDR blocks

#### Enhanced EC2/EBS Checks
- `check_ec2_detailed_monitoring(ec2_client)` - Identifies instances without detailed monitoring
- `check_default_security_groups(ec2_client)` - Finds instances using default security groups
- `check_public_ebs_snapshots(ec2_client)` - Identifies public EBS snapshots
- `check_public_amis(ec2_client)` - Finds public AMIs owned by the account

#### Route53 Security Checks
- `check_route53_query_logging(route53_client)` - Identifies hosted zones without query logging
- `check_route53_wildcard_records(route53_client)` - Finds potentially risky wildcard DNS records

#### Enhanced IAM Checks
- `check_iam_wildcard_policies(iam_client)` - Identifies policies with wildcard permissions
- `check_iam_broad_trust_relationships(iam_client)` - Finds roles with overly broad trust policies
- `check_iam_unused_access_keys(iam_client)` - Identifies old or unused access keys
- `check_iam_password_policy(iam_client)` - Validates password policy strength

### Enhanced CLI Module (`cli.py`)

#### New Check Categories
The CLI will support new service-specific check categories:
- `cloudtrail` - CloudTrail logging and validation checks
- `rds` - RDS security configuration checks  
- `lambda` - Lambda function security checks
- `vpc` - VPC and network security checks
- `route53` - Route53 DNS security checks
- `iam-enhanced` - Additional IAM security validations

#### Backward Compatibility
- Existing check names (`s3`, `ec2`, `ebs`, `iam`) remain unchanged
- `all` option includes all new checks
- New checks can be combined with existing ones: `--checks s3,rds,lambda`

#### Enhanced Error Handling
- Service-specific error handling for new AWS APIs
- Graceful degradation when permissions are insufficient
- Detailed error messages in verbose mode

## Data Models

### Security Check Result Structure
```python
SecurityIssue = {
    'service': str,      # AWS service name (e.g., 'CloudTrail', 'RDS')
    'resource': str,     # Resource identifier
    'issue': str,        # Human-readable issue description
    'severity': str,     # 'LOW', 'MEDIUM', 'HIGH'
    'region': str,       # AWS region (optional)
    'account_id': str    # AWS account ID (optional)
}
```

### Severity Classification
- **HIGH**: Public access, missing encryption for sensitive data, excessive permissions
- **MEDIUM**: Missing monitoring, weak configurations, compliance issues
- **LOW**: Best practice recommendations, optimization opportunities

## Error Handling

### AWS API Error Categories
1. **Permission Errors**: Handle `AccessDenied` exceptions gracefully
2. **Service Unavailable**: Retry logic for temporary service issues
3. **Resource Not Found**: Skip missing resources without failing entire scan
4. **Rate Limiting**: Implement exponential backoff for API throttling

### Error Reporting Strategy
- Log errors in verbose mode
- Continue scanning other checks when individual checks fail
- Provide summary of failed checks at end of scan
- Return partial results rather than failing completely

## Testing Strategy

### Unit Testing Approach
- Use `@mock_aws` decorator from moto for all new AWS service mocking
- Create realistic test scenarios for each security check
- Test both positive (issues found) and negative (no issues) cases
- Verify error handling for common AWS API exceptions

### Test Coverage Requirements
- Each new security check function has dedicated test methods
- CLI integration tests for new check categories
- Error handling tests for permission and API failures
- Output format tests for table, JSON, and CSV formats

### Mock Data Strategy
- Create representative AWS resources in moto mocks
- Include both secure and insecure configurations
- Test edge cases like empty results and API errors
- Validate severity classifications and resource identification

## Implementation Considerations

### Performance Optimization
- Batch API calls where possible to reduce latency
- Implement concurrent checking for independent services
- Cache client connections within scan session
- Provide progress indicators for long-running scans

### AWS Service Permissions
Required IAM permissions for new checks:
```json
{
    "CloudTrail": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
    "RDS": ["rds:DescribeDBInstances", "rds:DescribeDBSnapshots"],
    "Lambda": ["lambda:ListFunctions", "lambda:GetFunction"],
    "VPC": ["ec2:DescribeVpcs", "ec2:DescribeFlowLogs", "ec2:DescribeNetworkAcls"],
    "Route53": ["route53:ListHostedZones", "route53:ListResourceRecordSets"],
    "IAM": ["iam:ListPolicies", "iam:GetPolicy", "iam:ListRoles"]
}
```

### Configuration Management
- Support for service-specific configuration options
- Ability to customize severity thresholds
- Region-specific scanning capabilities
- Profile-based permission validation

This design maintains the simplicity and effectiveness of the current AWS Sentinel architecture while significantly expanding its security coverage across the AWS ecosystem.