"""
CLI interface for AWS InfraSec
"""
import boto3
import click
import sys
import json
from datetime import datetime
from .utils import import_datetime_for_json
from .core import (
    check_public_buckets,
    check_public_security_groups,
    check_unencrypted_ebs_volumes,
    check_iam_users_without_mfa,
    # CloudTrail checks
    check_cloudtrail_logging,
    check_cloudtrail_log_validation,
    check_cloudtrail_management_events,
    # RDS checks
    check_public_rds_instances,
    check_unencrypted_rds_instances,
    check_rds_backup_retention,
    check_public_rds_snapshots,
    # Lambda checks
    check_lambda_execution_roles,
    check_lambda_environment_encryption,
    check_lambda_vpc_config,
    check_lambda_runtime_versions,
    # VPC checks
    check_vpc_flow_logs,
    check_permissive_nacls,
    check_broad_route_table_routes,
    # Enhanced EC2/EBS checks
    check_ec2_detailed_monitoring,
    check_default_security_groups,
    check_public_ebs_snapshots,
    check_public_amis,
    # Route53 checks
    check_route53_query_logging,
    check_route53_wildcard_records,
    # Enhanced IAM checks
    check_iam_wildcard_policies,
    check_iam_broad_trust_relationships,
    check_iam_unused_access_keys,
    check_iam_password_policy
)
from .utils import create_pretty_table, create_html_report
from .ascii_art import BANNER

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(
    version='0.1.1', 
    prog_name='AWS InfraSec',
    message='%(prog)s v%(version)s - A security scanner for AWS resources'
)
def main():
    """
    \b
    ╔═══════════════════════════════════════════════╗
    ║               AWS INFRASEC                    ║
    ║        Security Scanner for AWS Resources     ║
    ╚═══════════════════════════════════════════════╝
    
    AWS InfraSec scans your AWS account for security vulnerabilities 
    and misconfigurations, helping you maintain a secure cloud environment.
    
    \b
    Commands:
      scan            Run a security scan on your AWS resources
      docs            Display detailed documentation and check descriptions
      version         Show the version and exit
      
    \b
    Examples:
      aws-infrasec scan --profile production --region us-west-2
      aws-infrasec scan --checks s3,iam,cloudtrail --output json
      aws-infrasec docs
    """
    pass

@main.command('scan')
@click.option('--profile', default='default', 
              help='AWS profile to use for authentication (from ~/.aws/credentials)')
@click.option('--region', default='us-east-1', 
              help='AWS region to scan for security issues')
@click.option('--checks', default='all',
              help='Comma-separated list of checks to run. Available: s3, ec2, ebs, iam, cloudtrail, rds, lambda, vpc, route53, iam-enhanced, or "all"')
@click.option('--output', type=click.Choice(['table', 'json', 'csv', 'html']), default='table',
              help='Output format for scan results')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'all']), default='all',
              help='Filter results by minimum severity level')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def scan(profile, region, checks, output, severity, verbose):
    """
    Run a comprehensive security scan on your AWS resources.
    
    This command analyzes your AWS account for security issues across multiple services:
    
    \b
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
    
    \b
    Examples:
    aws-infrasec scan --checks s3,iam --severity high
    aws-infrasec scan --profile prod --region us-west-2 --output json
    """
    if output == 'table':
        print(BANNER)
        click.echo(f"Scanning AWS account using profile: {profile} in region: {region}")
    if verbose:
        click.echo(f"Checks: {checks}")
        click.echo(f"Output format: {output}")
        click.echo(f"Severity filter: {severity}")
    
    if output == 'table':
        click.echo("Initializing security checks...\n")

    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        s3_client = session.client('s3')
        ec2_client = session.client('ec2')
        iam_client = session.client('iam')
        cloudtrail_client = session.client('cloudtrail')
        rds_client = session.client('rds')
        lambda_client = session.client('lambda')
        route53_client = session.client('route53')
    except Exception as e:
        click.echo(f"Error connecting to AWS: {str(e)}", err=True)
        sys.exit(1)

    results = []
    checks_to_run = checks.lower().split(',') if checks.lower() != 'all' else ['s3', 'ec2', 'ebs', 'iam', 'cloudtrail', 'rds', 'lambda', 'vpc', 'route53', 'iam-enhanced']
    
    if verbose:
        click.echo(f"Starting scan with the following checks: {', '.join(checks_to_run)}")
    
    # S3 Buckets Check
    if 's3' in checks_to_run:
        if verbose:
            click.echo("Checking for public S3 buckets...")
        public_buckets = check_public_buckets(s3_client)
        for bucket in public_buckets:
            results.append(["S3", bucket, "Public bucket", "HIGH"])
    
    # Security Groups Check
    if 'ec2' in checks_to_run:
        if verbose:
            click.echo("Checking for security groups with public access...")
        public_sgs = check_public_security_groups(ec2_client)
        for sg in public_sgs:
            results.append(["EC2", sg, "Security group with port 22 open to public", "HIGH"])
    
    # EBS Volumes Check
    if 'ebs' in checks_to_run:
        if verbose:
            click.echo("Checking for unencrypted EBS volumes...")
        unencrypted_volumes = check_unencrypted_ebs_volumes(ec2_client)
        for volume in unencrypted_volumes:
            results.append(["EBS", volume, "Unencrypted volume", "MEDIUM"])
    
    # IAM Users Check
    if 'iam' in checks_to_run:
        if verbose:
            click.echo("Checking for IAM users without MFA...")
        users_without_mfa = check_iam_users_without_mfa(iam_client)
        for user in users_without_mfa:
            results.append(["IAM", user, "User without MFA", "HIGH"])

    # CloudTrail Checks
    if 'cloudtrail' in checks_to_run:
        if verbose:
            click.echo("Checking CloudTrail logging configuration...")
        
        # Check for trails not logging
        non_logging_trails = check_cloudtrail_logging(cloudtrail_client)
        for trail in non_logging_trails:
            results.append(["CloudTrail", trail, "Trail not logging", "HIGH"])
        
        # Check for trails without log validation
        trails_without_validation = check_cloudtrail_log_validation(cloudtrail_client)
        for trail in trails_without_validation:
            results.append(["CloudTrail", trail, "Trail without log file validation", "HIGH"])
        
        # Check for trails not logging management events
        trails_without_mgmt_events = check_cloudtrail_management_events(cloudtrail_client)
        for trail in trails_without_mgmt_events:
            results.append(["CloudTrail", trail, "Trail not logging management events", "HIGH"])

    # RDS Checks
    if 'rds' in checks_to_run:
        if verbose:
            click.echo("Checking RDS security configurations...")
        
        # Check for public RDS instances
        public_rds_instances = check_public_rds_instances(rds_client)
        for instance in public_rds_instances:
            results.append(["RDS", instance, "Publicly accessible RDS instance", "HIGH"])
        
        # Check for unencrypted RDS instances
        unencrypted_rds_instances = check_unencrypted_rds_instances(rds_client)
        for instance in unencrypted_rds_instances:
            results.append(["RDS", instance, "Unencrypted RDS instance", "MEDIUM"])
        
        # Check for insufficient backup retention
        insufficient_backup_instances = check_rds_backup_retention(rds_client)
        for instance in insufficient_backup_instances:
            results.append(["RDS", instance, "Insufficient backup retention period", "MEDIUM"])
        
        # Check for public RDS snapshots
        public_rds_snapshots = check_public_rds_snapshots(rds_client)
        for snapshot in public_rds_snapshots:
            results.append(["RDS", snapshot, "Public RDS snapshot", "HIGH"])

    # Lambda Checks
    if 'lambda' in checks_to_run:
        if verbose:
            click.echo("Checking Lambda function security settings...")
        
        # Check for functions with overly permissive execution roles
        functions_with_permissive_roles = check_lambda_execution_roles(lambda_client, iam_client)
        for function in functions_with_permissive_roles:
            results.append(["Lambda", function, "Function with overly permissive execution role", "HIGH"])
        
        # Check for functions without environment variable encryption
        functions_without_env_encryption = check_lambda_environment_encryption(lambda_client)
        for function in functions_without_env_encryption:
            results.append(["Lambda", function, "Function without environment variable encryption", "MEDIUM"])
        
        # Check for functions in public subnets
        functions_in_public_subnets = check_lambda_vpc_config(lambda_client, ec2_client)
        for function in functions_in_public_subnets:
            results.append(["Lambda", function, "Function in public subnet", "HIGH"])
        
        # Check for functions with outdated runtime versions
        functions_with_outdated_runtimes = check_lambda_runtime_versions(lambda_client)
        for function in functions_with_outdated_runtimes:
            results.append(["Lambda", function, "Function with outdated runtime version", "MEDIUM"])

    # VPC Checks
    if 'vpc' in checks_to_run:
        if verbose:
            click.echo("Checking VPC and network security configurations...")
        
        # Check for VPCs without flow logs
        vpcs_without_flow_logs = check_vpc_flow_logs(ec2_client)
        for vpc in vpcs_without_flow_logs:
            results.append(["VPC", vpc, "VPC without flow logs enabled", "MEDIUM"])
        
        # Check for overly permissive NACLs
        permissive_nacls = check_permissive_nacls(ec2_client)
        for nacl in permissive_nacls:
            results.append(["VPC", nacl, "Overly permissive Network ACL", "HIGH"])
        
        # Check for route tables with broad CIDR blocks
        broad_route_tables = check_broad_route_table_routes(ec2_client)
        for route_table in broad_route_tables:
            results.append(["VPC", route_table, "Route table with overly broad CIDR block", "HIGH"])

    # Enhanced EC2/EBS Checks (additional to existing ec2/ebs checks)
    if 'ec2' in checks_to_run or 'ebs' in checks_to_run:
        if verbose:
            click.echo("Checking additional EC2/EBS security configurations...")
        
        # Check for EC2 instances without detailed monitoring
        instances_without_detailed_monitoring = check_ec2_detailed_monitoring(ec2_client)
        for instance in instances_without_detailed_monitoring:
            results.append(["EC2", instance, "Instance without detailed monitoring", "LOW"])
        
        # Check for instances using default security groups
        instances_with_default_sg = check_default_security_groups(ec2_client)
        for instance in instances_with_default_sg:
            results.append(["EC2", instance, "Instance using default security group", "MEDIUM"])
        
        # Check for public EBS snapshots
        public_ebs_snapshots = check_public_ebs_snapshots(ec2_client)
        for snapshot in public_ebs_snapshots:
            results.append(["EBS", snapshot, "Public EBS snapshot", "HIGH"])
        
        # Check for public AMIs
        public_amis = check_public_amis(ec2_client)
        for ami in public_amis:
            results.append(["EC2", ami, "Public AMI owned by account", "HIGH"])

    # Route53 Checks
    if 'route53' in checks_to_run:
        if verbose:
            click.echo("Checking Route53 DNS security configurations...")
        
        # Check for hosted zones without query logging
        zones_without_query_logging = check_route53_query_logging(route53_client)
        for zone in zones_without_query_logging:
            results.append(["Route53", zone, "Hosted zone without query logging", "LOW"])
        
        # Check for risky wildcard records
        risky_wildcard_records = check_route53_wildcard_records(route53_client)
        for record in risky_wildcard_records:
            results.append(["Route53", record, "Potentially risky wildcard DNS record", "MEDIUM"])

    # Enhanced IAM Checks
    if 'iam-enhanced' in checks_to_run:
        if verbose:
            click.echo("Checking additional IAM security configurations...")
        
        # Check for policies with wildcard permissions
        policies_with_wildcards = check_iam_wildcard_policies(iam_client)
        for policy in policies_with_wildcards:
            results.append(["IAM", policy, "Policy with wildcard permissions", "HIGH"])
        
        # Check for roles with broad trust relationships
        roles_with_broad_trust = check_iam_broad_trust_relationships(iam_client)
        for role in roles_with_broad_trust:
            results.append(["IAM", role, "Role with overly broad trust relationship", "HIGH"])
        
        # Check for users with unused access keys
        users_with_unused_keys = check_iam_unused_access_keys(iam_client)
        for user in users_with_unused_keys:
            results.append(["IAM", user, "User with old or unused access keys", "MEDIUM"])
        
        # Check password policy
        password_policy_issues = check_iam_password_policy(iam_client)
        for issue in password_policy_issues:
            results.append(["IAM", "password-policy", f"Password policy issue: {issue}", "MEDIUM"])

    # Filter by severity if needed
    if severity != 'all':
        severity_levels = {
            'low': ['LOW', 'MEDIUM', 'HIGH'],
            'medium': ['MEDIUM', 'HIGH'],
            'high': ['HIGH']
        }
        results = [r for r in results if r[3] in severity_levels[severity]]
    
    # Output results
    if results:
        if output == 'table':
            table = create_pretty_table(
                "AWS Security Issues Detected",
                ["Service", "Resource", "Issue", "Severity"],
                results
            )
            print(table)
            click.echo(f"\nScan complete. Found {len(results)} security issues.")
        elif output == 'json':
            json_results = {
                'scan_results': {
                    'profile': profile,
                    'region': region,
                    'scan_time': import_datetime_for_json(),
                    'issues_count': len(results),
                    'issues': []
                }
            }
            
            for r in results:
                json_results['scan_results']['issues'].append({
                    'service': r[0],
                    'resource': r[1],
                    'issue': r[2],
                    'severity': r[3]
                })
            
            # Only output the JSON with no additional text
            print(json.dumps(json_results, indent=2, sort_keys=False, ensure_ascii=False))
        elif output == 'csv':
            import csv
            from io import StringIO
            output_buffer = StringIO()
            writer = csv.writer(output_buffer)
            writer.writerow(["Service", "Resource", "Issue", "Severity"])
            writer.writerows(results)
            # Only output the CSV with no additional text
            print(output_buffer.getvalue().strip())
        elif output == 'html':
            html_report = create_html_report(profile, region, results)
            print(html_report)
    else:
        if output == 'table':
            click.echo("No security issues found. Your AWS environment looks secure!")
        elif output == 'json':
            empty_result = {
                'scan_results': {
                    'profile': profile,
                    'region': region,
                    'scan_time': import_datetime_for_json(),
                    'issues_count': 0,
                    'issues': []
                }
            }
            print(json.dumps(empty_result, indent=2, sort_keys=False, ensure_ascii=False))
        elif output == 'csv':
            print("Service,Resource,Issue,Severity")
        elif output == 'html':
            html_report = create_html_report(profile, region, [])
            print(html_report)

@main.command('version')
def version():
    """Display the version of AWS InfraSec."""
    click.echo("AWS InfraSec v0.1.1")

# Add a docs command to show more detailed usage instructions
@main.command('docs')
def docs():
    """Display detailed documentation about AWS InfraSec security checks and usage."""
    doc_text = """
    AWS InfraSec Documentation
    =========================
    
    DESCRIPTION
    -----------
    AWS InfraSec is a comprehensive security scanner for AWS resources that identifies
    security vulnerabilities and misconfigurations across multiple AWS services to help
    maintain a secure cloud environment.
    
    SECURITY CHECK CATEGORIES
    ------------------------
    
    S3 (Simple Storage Service)
    • Public bucket access - Identifies S3 buckets with public read/write access
    
    EC2 (Elastic Compute Cloud)
    • Security groups with SSH open to public - Finds security groups allowing SSH (port 22) from 0.0.0.0/0
    • Instances without detailed monitoring - Identifies EC2 instances without CloudWatch detailed monitoring
    • Instances using default security groups - Finds instances using the default security group
    • Public AMIs owned by account - Identifies AMIs that are publicly accessible
    
    EBS (Elastic Block Store)
    • Unencrypted volumes - Finds EBS volumes without encryption at rest
    • Public EBS snapshots - Identifies EBS snapshots with public access permissions
    
    IAM (Identity and Access Management)
    • Users without MFA - Identifies IAM users without Multi-Factor Authentication enabled
    
    CloudTrail (Audit Logging)
    • Trails not logging - Finds CloudTrail trails that are not actively logging events
    • Trails without log file validation - Identifies trails without log file integrity validation
    • Trails not logging management events - Finds trails not capturing management API calls
    
    RDS (Relational Database Service)
    • Publicly accessible instances - Identifies RDS instances with public accessibility enabled
    • Unencrypted instances - Finds RDS instances without encryption at rest
    • Insufficient backup retention - Identifies instances with backup retention period less than 7 days
    • Public snapshots - Finds RDS snapshots with public access permissions
    
    Lambda (Serverless Functions)
    • Functions with overly permissive execution roles - Identifies functions with excessive IAM permissions
    • Functions without environment variable encryption - Finds functions with unencrypted environment variables
    • Functions in public subnets - Identifies Lambda functions deployed in public subnets
    • Functions with outdated runtime versions - Finds functions using deprecated or outdated runtime versions
    
    VPC (Virtual Private Cloud)
    • VPCs without flow logs - Identifies VPCs without VPC Flow Logs enabled for network monitoring
    • Overly permissive Network ACLs - Finds Network ACLs with rules allowing broad access
    • Route tables with overly broad CIDR blocks - Identifies route tables with routes to 0.0.0.0/0
    
    Route53 (DNS Service)
    • Hosted zones without query logging - Identifies DNS zones without query logging enabled
    • Potentially risky wildcard DNS records - Finds wildcard (*) DNS records that may pose security risks
    
    IAM-Enhanced (Advanced Identity Checks)
    • Policies with wildcard permissions - Identifies IAM policies using wildcard (*) permissions
    • Roles with overly broad trust relationships - Finds IAM roles with permissive trust policies
    • Users with old or unused access keys - Identifies access keys that are old or haven't been used recently
    • Password policy issues - Validates IAM password policy strength and requirements
    
    SEVERITY LEVELS
    --------------
    • HIGH    - Critical security issues requiring immediate attention (public access, missing MFA)
    • MEDIUM  - Important security configurations that should be addressed (encryption, monitoring)
    • LOW     - Best practice recommendations and optimization opportunities
    
    PREREQUISITES
    ------------
    1. AWS CLI configured with appropriate credentials
    2. Required IAM permissions to access resources in your AWS account
    3. Python 3.9+ with boto3, click, prettytable, and colorama packages
    
    USAGE EXAMPLES
    -------------
    # Run a comprehensive scan of all security checks
    aws-infrasec scan
    
    # Scan specific AWS profile and region
    aws-infrasec scan --profile production --region us-west-2
    
    # Run only specific security check categories
    aws-infrasec scan --checks s3,iam,cloudtrail
    
    # Filter results by severity level
    aws-infrasec scan --severity high
    
    # Export results in different formats
    aws-infrasec scan --output json > security_report.json
    aws-infrasec scan --output csv > security_report.csv
    aws-infrasec scan --output html > security_report.html
    
    # Enable verbose output for debugging
    aws-infrasec scan --verbose
    
    # Combine multiple options
    aws-infrasec scan --profile prod --checks rds,lambda,vpc --severity medium --output json
    
    OUTPUT FORMATS
    -------------
    • table - Human-readable table format (default)
    • json  - Machine-readable JSON format for automation
    • csv   - Comma-separated values for spreadsheet analysis
    • html  - HTML report format for sharing and presentation
    """
    click.echo(doc_text)

if __name__ == '__main__':
    main()