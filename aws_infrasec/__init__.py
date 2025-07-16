"""
AWS InfraSec - Security Scanner for AWS Resources

A command-line tool to identify security vulnerabilities and 
misconfigurations in your AWS account.
"""

__version__ = '2.0'
__author__ = 'Aswanth'
__email__ = 'aswanthrajan97@gmail.com'
__description__ = 'Security scanner for AWS resources'
__url__ = 'https://github.com/'

from .core import (
    check_public_buckets,
    check_public_security_groups,
    check_unencrypted_ebs_volumes,
    check_iam_users_without_mfa,
    check_cloudtrail_logging,
    check_cloudtrail_log_validation,
    check_cloudtrail_management_events,
    check_public_rds_instances,
    check_unencrypted_rds_instances,
    check_rds_backup_retention,
    check_public_rds_snapshots,
    check_lambda_execution_roles,
    check_lambda_environment_encryption,
    check_lambda_vpc_config,
    check_lambda_runtime_versions,
    check_vpc_flow_logs,
    check_permissive_nacls,
    check_broad_route_table_routes,
    check_ec2_detailed_monitoring,
    check_default_security_groups,
    check_public_ebs_snapshots,
    check_public_amis,
    check_route53_query_logging,
    check_route53_wildcard_records,
    check_iam_wildcard_policies,
    check_iam_broad_trust_relationships,
    check_iam_unused_access_keys,
    check_iam_password_policy
)