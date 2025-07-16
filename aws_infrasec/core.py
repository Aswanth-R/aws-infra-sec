"""
Core functionality for AWS InfraSec security checks based on CIS AWS Foundations Benchmark
"""
import boto3
import json
from datetime import datetime, timedelta

def check_public_buckets(s3_client):
    """
    Check for S3 buckets with public access.
    
    Args:
        s3_client: Boto3 S3 client
        
    Returns:
        list: List of public bucket names
    """
    public_buckets = []
    try:
        buckets = s3_client.list_buckets()['Buckets']
        for bucket in buckets:
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket['Name'])
                for grant in acl['Grants']:
                    if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        public_buckets.append(bucket['Name'])
                        break
            except Exception as e:
                print(f"Error checking bucket {bucket['Name']}: {str(e)}")
    except Exception as e:
        print(f"Error listing S3 buckets: {str(e)}")
    return public_buckets

def check_public_security_groups(ec2_client):
    """
    Check for security groups with port 22 open to the world.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of security group IDs with port 22 open
    """
    public_sgs = []
    try:
        sgs = ec2_client.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if rule.get('FromPort') == 22 or rule.get('ToPort') == 22:
                            public_sgs.append(sg['GroupId'])
                            break
    except Exception as e:
        print(f"Error checking security groups: {str(e)}")
    return public_sgs

def check_unencrypted_ebs_volumes(ec2_client):
    """
    Check for unencrypted EBS volumes.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of unencrypted volume IDs
    """
    unencrypted_volumes = []
    try:
        volumes = ec2_client.describe_volumes()['Volumes']
        for volume in volumes:
            if not volume['Encrypted']:
                unencrypted_volumes.append(volume['VolumeId'])
    except Exception as e:
        print(f"Error checking EBS volumes: {str(e)}")
    return unencrypted_volumes

def check_iam_users_without_mfa(iam_client):
    """
    Check for IAM users without MFA enabled.
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of IAM usernames without MFA
    """
    users_without_mfa = []
    try:
        users = iam_client.list_users()['Users']
        for user in users:
            try:
                mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                if not mfa_devices:
                    users_without_mfa.append(user['UserName'])
            except Exception as e:
                print(f"Error checking MFA for user {user['UserName']}: {str(e)}")
    except Exception as e:
        print(f"Error listing IAM users: {str(e)}")
    return users_without_mfa

def check_cloudtrail_logging(cloudtrail_client):
    """
    Check for CloudTrail trails that are not logging.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client
        
    Returns:
        list: List of trail names that are not logging
    """
    non_logging_trails = []
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        for trail in trails:
            try:
                status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                if not status['IsLogging']:
                    non_logging_trails.append(trail['Name'])
            except Exception as e:
                print(f"Error checking trail status {trail['Name']}: {str(e)}")
    except Exception as e:
        print(f"Error describing CloudTrail trails: {str(e)}")
    return non_logging_trails

def check_cloudtrail_log_validation(cloudtrail_client):
    """
    Check for CloudTrail trails without log file validation enabled.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client
        
    Returns:
        list: List of trail names without log file validation
    """
    trails_without_validation = []
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        for trail in trails:
            if not trail.get('LogFileValidationEnabled', False):
                trails_without_validation.append(trail['Name'])
    except Exception as e:
        print(f"Error describing CloudTrail trails: {str(e)}")
    return trails_without_validation

def check_cloudtrail_management_events(cloudtrail_client):
    """
    Check for CloudTrail trails not logging management events.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client
        
    Returns:
        list: List of trail names not logging management events
    """
    trails_without_mgmt_events = []
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        for trail in trails:
            try:
                # Get event selectors to check if management events are being logged
                event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail['TrailARN'])
                
                # Check if any event selector includes management events
                has_mgmt_events = False
                for selector in event_selectors.get('EventSelectors', []):
                    if selector.get('IncludeManagementEvents', False):
                        has_mgmt_events = True
                        break
                
                if not has_mgmt_events:
                    trails_without_mgmt_events.append(trail['Name'])
            except Exception as e:
                print(f"Error checking event selectors for trail {trail['Name']}: {str(e)}")
    except Exception as e:
        print(f"Error describing CloudTrail trails: {str(e)}")
    return trails_without_mgmt_events

# CIS AWS Foundations Benchmark v1.5.0 Controls

def cis_1_3_ensure_credentials_unused_are_disabled(iam_client):
    """
    CIS 1.3: Ensure credentials unused for 90 days or greater are disabled
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of IAM users with unused credentials
    """
    unused_credentials = []
    try:
        users = iam_client.list_users()['Users']
        cutoff_date = datetime.now() - timedelta(days=90)
        
        for user in users:
            username = user['UserName']
            
            # Check console password last used
            try:
                login_profile = iam_client.get_login_profile(UserName=username)
                if user.get('PasswordLastUsed'):
                    if user['PasswordLastUsed'].replace(tzinfo=None) < cutoff_date:
                        unused_credentials.append(f"{username} (console)")
                else:
                    # Password exists but never used
                    unused_credentials.append(f"{username} (console-never-used)")
            except iam_client.exceptions.NoSuchEntityException:
                pass  # No console access
            
            # Check access keys
            access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                if key['Status'] == 'Active':
                    try:
                        last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        if last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate'):
                            last_used_date = last_used['AccessKeyLastUsed']['LastUsedDate'].replace(tzinfo=None)
                            if last_used_date < cutoff_date:
                                unused_credentials.append(f"{username} (access-key-{key['AccessKeyId'][:8]})")
                        else:
                            # Key exists but never used
                            unused_credentials.append(f"{username} (access-key-{key['AccessKeyId'][:8]}-never-used)")
                    except Exception as e:
                        print(f"Error checking access key usage for {username}: {str(e)}")
                        
    except Exception as e:
        print(f"Error checking unused credentials: {str(e)}")
    return unused_credentials

def cis_1_4_ensure_access_keys_rotated_90_days(iam_client):
    """
    CIS 1.4: Ensure access keys are rotated every 90 days or less
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of access keys older than 90 days
    """
    old_access_keys = []
    try:
        users = iam_client.list_users()['Users']
        cutoff_date = datetime.now() - timedelta(days=90)
        
        for user in users:
            username = user['UserName']
            access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            
            for key in access_keys:
                if key['Status'] == 'Active':
                    create_date = key['CreateDate'].replace(tzinfo=None)
                    if create_date < cutoff_date:
                        old_access_keys.append(f"{username}:{key['AccessKeyId'][:8]}")
                        
    except Exception as e:
        print(f"Error checking access key rotation: {str(e)}")
    return old_access_keys

def cis_1_5_ensure_iam_password_policy_requires_uppercase(iam_client):
    """
    CIS 1.5: Ensure IAM password policy requires at least one uppercase letter
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List indicating if password policy lacks uppercase requirement
    """
    policy_issues = []
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        if not policy.get('RequireUppercaseCharacters', False):
            policy_issues.append('password-policy-no-uppercase')
    except iam_client.exceptions.NoSuchEntityException:
        policy_issues.append('password-policy-not-set')
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    return policy_issues

def cis_1_6_ensure_iam_password_policy_requires_lowercase(iam_client):
    """
    CIS 1.6: Ensure IAM password policy requires at least one lowercase letter
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List indicating if password policy lacks lowercase requirement
    """
    policy_issues = []
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        if not policy.get('RequireLowercaseCharacters', False):
            policy_issues.append('password-policy-no-lowercase')
    except iam_client.exceptions.NoSuchEntityException:
        policy_issues.append('password-policy-not-set')
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    return policy_issues

def cis_1_7_ensure_iam_password_policy_requires_symbols(iam_client):
    """
    CIS 1.7: Ensure IAM password policy requires at least one symbol
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List indicating if password policy lacks symbol requirement
    """
    policy_issues = []
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        if not policy.get('RequireSymbols', False):
            policy_issues.append('password-policy-no-symbols')
    except iam_client.exceptions.NoSuchEntityException:
        policy_issues.append('password-policy-not-set')
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    return policy_issues

def cis_1_8_ensure_iam_password_policy_requires_numbers(iam_client):
    """
    CIS 1.8: Ensure IAM password policy requires at least one number
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List indicating if password policy lacks number requirement
    """
    policy_issues = []
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        if not policy.get('RequireNumbers', False):
            policy_issues.append('password-policy-no-numbers')
    except iam_client.exceptions.NoSuchEntityException:
        policy_issues.append('password-policy-not-set')
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    return policy_issues

def cis_1_9_ensure_iam_password_policy_minimum_length(iam_client):
    """
    CIS 1.9: Ensure IAM password policy requires minimum length of 14 or greater
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List indicating if password policy has insufficient minimum length
    """
    policy_issues = []
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        min_length = policy.get('MinimumPasswordLength', 0)
        if min_length < 14:
            policy_issues.append(f'password-policy-min-length-{min_length}')
    except iam_client.exceptions.NoSuchEntityException:
        policy_issues.append('password-policy-not-set')
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    return policy_issues

def cis_1_10_ensure_iam_password_policy_prevents_reuse(iam_client):
    """
    CIS 1.10: Ensure IAM password policy prevents password reuse
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List indicating if password policy allows password reuse
    """
    policy_issues = []
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        reuse_prevention = policy.get('PasswordReusePrevention', 0)
        if reuse_prevention < 24:  # CIS recommends 24
            policy_issues.append(f'password-policy-reuse-prevention-{reuse_prevention}')
    except iam_client.exceptions.NoSuchEntityException:
        policy_issues.append('password-policy-not-set')
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    return policy_issues

def cis_1_11_ensure_iam_password_policy_expires_passwords(iam_client):
    """
    CIS 1.11: Ensure IAM password policy expires passwords within 90 days or less
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List indicating if password policy doesn't expire passwords
    """
    policy_issues = []
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        max_age = policy.get('MaxPasswordAge')
        if not max_age or max_age > 90:
            policy_issues.append(f'password-policy-max-age-{max_age or "unlimited"}')
    except iam_client.exceptions.NoSuchEntityException:
        policy_issues.append('password-policy-not-set')
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    return policy_issues

def cis_2_1_1_ensure_cloudtrail_enabled_all_regions(cloudtrail_client):
    """
    CIS 2.1.1: Ensure CloudTrail is enabled in all regions
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client
        
    Returns:
        list: List indicating if CloudTrail is not enabled in all regions
    """
    issues = []
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        multi_region_trails = [trail for trail in trails if trail.get('IsMultiRegionTrail', False)]
        
        if not multi_region_trails:
            issues.append('no-multi-region-cloudtrail')
        else:
            # Check if any multi-region trail is logging
            active_multi_region = False
            for trail in multi_region_trails:
                try:
                    status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                    if status['IsLogging']:
                        active_multi_region = True
                        break
                except Exception as e:
                    print(f"Error checking trail status {trail['Name']}: {str(e)}")
            
            if not active_multi_region:
                issues.append('multi-region-cloudtrail-not-logging')
                
    except Exception as e:
        print(f"Error checking CloudTrail multi-region: {str(e)}")
    return issues

def cis_2_1_2_ensure_cloudtrail_log_file_validation_enabled(cloudtrail_client):
    """
    CIS 2.1.2: Ensure CloudTrail log file validation is enabled
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client
        
    Returns:
        list: List of trails without log file validation
    """
    return check_cloudtrail_log_validation(cloudtrail_client)

def cis_2_2_ensure_cloudtrail_s3_bucket_not_public(s3_client, cloudtrail_client):
    """
    CIS 2.2: Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible
    
    Args:
        s3_client: Boto3 S3 client
        cloudtrail_client: Boto3 CloudTrail client
        
    Returns:
        list: List of public CloudTrail S3 buckets
    """
    public_cloudtrail_buckets = []
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        cloudtrail_buckets = set()
        
        for trail in trails:
            bucket_name = trail.get('S3BucketName')
            if bucket_name:
                cloudtrail_buckets.add(bucket_name)
        
        # Check if CloudTrail buckets are public
        for bucket_name in cloudtrail_buckets:
            try:
                # Check bucket ACL
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        public_cloudtrail_buckets.append(bucket_name)
                        break
                
                # Check bucket policy for public access
                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy['Policy'])
                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow' and statement.get('Principal') == '*':
                            public_cloudtrail_buckets.append(f"{bucket_name}-policy")
                            break
                except s3_client.exceptions.NoSuchBucketPolicy:
                    pass  # No bucket policy is fine
                    
            except Exception as e:
                print(f"Error checking CloudTrail bucket {bucket_name}: {str(e)}")
                
    except Exception as e:
        print(f"Error checking CloudTrail S3 buckets: {str(e)}")
    return public_cloudtrail_buckets

def cis_4_1_ensure_no_security_groups_allow_ingress_0_0_0_0_to_port_22(ec2_client):
    """
    CIS 4.1: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of security group IDs with SSH open to world
    """
    return check_public_security_groups(ec2_client)

def cis_4_2_ensure_no_security_groups_allow_ingress_0_0_0_0_to_port_3389(ec2_client):
    """
    CIS 4.2: Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of security group IDs with RDP open to world
    """
    public_rdp_sgs = []
    try:
        sgs = ec2_client.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if rule.get('FromPort') == 3389 or rule.get('ToPort') == 3389:
                            public_rdp_sgs.append(sg['GroupId'])
                            break
    except Exception as e:
        print(f"Error checking security groups for RDP: {str(e)}")
    return public_rdp_sgs

def check_public_rds_instances(rds_client):
    """
    Check for RDS instances that are publicly accessible.
    
    Args:
        rds_client: Boto3 RDS client
        
    Returns:
        list: List of publicly accessible RDS instance identifiers
    """
    public_rds_instances = []
    try:
        instances = rds_client.describe_db_instances()['DBInstances']
        for instance in instances:
            if instance.get('PubliclyAccessible', False):
                public_rds_instances.append(instance['DBInstanceIdentifier'])
    except Exception as e:
        print(f"Error checking RDS instances for public access: {str(e)}")
    return public_rds_instances

def check_unencrypted_rds_instances(rds_client):
    """
    Check for RDS instances without encryption at rest.
    
    Args:
        rds_client: Boto3 RDS client
        
    Returns:
        list: List of unencrypted RDS instance identifiers
    """
    unencrypted_rds_instances = []
    try:
        instances = rds_client.describe_db_instances()['DBInstances']
        for instance in instances:
            if not instance.get('StorageEncrypted', False):
                unencrypted_rds_instances.append(instance['DBInstanceIdentifier'])
    except Exception as e:
        print(f"Error checking RDS instances for encryption: {str(e)}")
    return unencrypted_rds_instances

def check_rds_backup_retention(rds_client):
    """
    Check for RDS instances with insufficient backup retention period.
    
    Args:
        rds_client: Boto3 RDS client
        
    Returns:
        list: List of RDS instance identifiers with insufficient backup retention
    """
    insufficient_backup_instances = []
    try:
        instances = rds_client.describe_db_instances()['DBInstances']
        for instance in instances:
            # Check if backup retention period is less than 7 days (recommended minimum)
            backup_retention = instance.get('BackupRetentionPeriod', 0)
            if backup_retention < 7:
                insufficient_backup_instances.append(instance['DBInstanceIdentifier'])
    except Exception as e:
        print(f"Error checking RDS instances for backup retention: {str(e)}")
    return insufficient_backup_instances

def check_public_rds_snapshots(rds_client):
    """
    Check for RDS snapshots that are publicly accessible.
    
    Args:
        rds_client: Boto3 RDS client
        
    Returns:
        list: List of public RDS snapshot identifiers
    """
    public_rds_snapshots = []
    try:
        # Check manual snapshots
        manual_snapshots = rds_client.describe_db_snapshots(SnapshotType='manual')['DBSnapshots']
        for snapshot in manual_snapshots:
            try:
                # Get snapshot attributes to check if it's public
                attributes = rds_client.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier']
                )['DBSnapshotAttributesResult']
                
                for attribute in attributes['DBSnapshotAttributes']:
                    if attribute['AttributeName'] == 'restore' and 'all' in attribute['AttributeValues']:
                        public_rds_snapshots.append(snapshot['DBSnapshotIdentifier'])
                        break
            except Exception as e:
                print(f"Error checking snapshot attributes for {snapshot['DBSnapshotIdentifier']}: {str(e)}")
        
        # Check automated snapshots
        automated_snapshots = rds_client.describe_db_snapshots(SnapshotType='automated')['DBSnapshots']
        for snapshot in automated_snapshots:
            try:
                # Get snapshot attributes to check if it's public
                attributes = rds_client.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier']
                )['DBSnapshotAttributesResult']
                
                for attribute in attributes['DBSnapshotAttributes']:
                    if attribute['AttributeName'] == 'restore' and 'all' in attribute['AttributeValues']:
                        public_rds_snapshots.append(snapshot['DBSnapshotIdentifier'])
                        break
            except Exception as e:
                print(f"Error checking snapshot attributes for {snapshot['DBSnapshotIdentifier']}: {str(e)}")
                
    except Exception as e:
        print(f"Error checking RDS snapshots for public access: {str(e)}")
    return public_rds_snapshots

def check_lambda_execution_roles(lambda_client, iam_client):
    """
    Check for Lambda functions with overly permissive execution roles.
    
    Args:
        lambda_client: Boto3 Lambda client
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of Lambda function names with overly permissive roles
    """
    functions_with_permissive_roles = []
    try:
        functions = lambda_client.list_functions()['Functions']
        
        for function in functions:
            function_name = function['FunctionName']
            role_arn = function['Role']
            
            try:
                # Extract role name from ARN
                role_name = role_arn.split('/')[-1]
                
                # Get attached policies for the role
                attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
                
                # Check for overly permissive policies
                for policy in attached_policies:
                    policy_arn = policy['PolicyArn']
                    
                    # Check for AWS managed policies that are overly permissive
                    if any(permissive in policy_arn for permissive in [
                        'PowerUserAccess', 'AdministratorAccess', 'IAMFullAccess', 
                        'EC2FullAccess', 'S3FullAccess'
                    ]):
                        functions_with_permissive_roles.append(function_name)
                        break
                    
                    # For custom policies, get the policy document
                    if not policy_arn.startswith('arn:aws:iam::aws:policy/'):
                        try:
                            policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                            policy_doc = iam_client.get_policy_version(
                                PolicyArn=policy_arn, 
                                VersionId=policy_version
                            )['PolicyVersion']['Document']
                            
                            # Check for wildcard permissions
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    
                                    if any('*' in action for action in actions):
                                        functions_with_permissive_roles.append(function_name)
                                        break
                        except Exception as e:
                            print(f"Error checking policy {policy_arn}: {str(e)}")
                
                # Check inline policies for wildcard permissions
                for policy_name in inline_policies:
                    try:
                        policy_doc = iam_client.get_role_policy(
                            RoleName=role_name, 
                            PolicyName=policy_name
                        )['PolicyDocument']
                        
                        for statement in policy_doc.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                
                                if any('*' in action for action in actions):
                                    functions_with_permissive_roles.append(function_name)
                                    break
                    except Exception as e:
                        print(f"Error checking inline policy {policy_name}: {str(e)}")
                        
            except Exception as e:
                print(f"Error checking execution role for function {function_name}: {str(e)}")
                
    except Exception as e:
        print(f"Error checking Lambda execution roles: {str(e)}")
    return functions_with_permissive_roles

def check_lambda_environment_encryption(lambda_client):
    """
    Check for Lambda functions without environment variable encryption.
    
    Args:
        lambda_client: Boto3 Lambda client
        
    Returns:
        list: List of Lambda function names without environment variable encryption
    """
    functions_without_env_encryption = []
    try:
        functions = lambda_client.list_functions()['Functions']
        
        for function in functions:
            function_name = function['FunctionName']
            
            # Check if function has environment variables
            environment = function.get('Environment', {})
            if environment.get('Variables'):
                # Check if KMS key is configured for environment variables
                kms_key_arn = environment.get('KMSKeyArn')
                if not kms_key_arn:
                    functions_without_env_encryption.append(function_name)
                    
    except Exception as e:
        print(f"Error checking Lambda environment encryption: {str(e)}")
    return functions_without_env_encryption

def check_vpc_flow_logs(ec2_client):
    """
    Check for VPCs without flow logs enabled.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of VPC IDs without flow logs enabled
    """
    vpcs_without_flow_logs = []
    try:
        # Get all VPCs
        vpcs = ec2_client.describe_vpcs()['Vpcs']
        
        # Get all flow logs
        flow_logs = ec2_client.describe_flow_logs()['FlowLogs']
        
        # Create set of VPC IDs that have flow logs
        vpcs_with_flow_logs = set()
        for flow_log in flow_logs:
            if flow_log.get('ResourceId') and flow_log.get('FlowLogStatus') == 'ACTIVE':
                vpcs_with_flow_logs.add(flow_log['ResourceId'])
        
        # Check which VPCs don't have flow logs
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            if vpc_id not in vpcs_with_flow_logs:
                vpcs_without_flow_logs.append(vpc_id)
                
    except Exception as e:
        print(f"Error checking VPC flow logs: {str(e)}")
    return vpcs_without_flow_logs

def check_permissive_nacls(ec2_client):
    """
    Check for overly permissive Network ACL rules.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of Network ACL IDs with overly permissive rules
    """
    permissive_nacls = []
    try:
        nacls = ec2_client.describe_network_acls()['NetworkAcls']
        
        for nacl in nacls:
            nacl_id = nacl['NetworkAclId']
            
            # Check entries for overly permissive rules
            for entry in nacl['Entries']:
                # Skip default deny rules
                if entry.get('RuleAction') == 'deny':
                    continue
                
                # Check for rules allowing all traffic from anywhere
                cidr_block = entry.get('CidrBlock', '')
                ipv6_cidr_block = entry.get('Ipv6CidrBlock', '')
                
                # Check for overly broad CIDR blocks
                if cidr_block == '0.0.0.0/0' or ipv6_cidr_block == '::/0':
                    # Check if it's allowing all ports or sensitive ports
                    port_range = entry.get('PortRange', {})
                    protocol = entry.get('Protocol', '')
                    
                    # Protocol -1 means all protocols
                    if protocol == '-1':
                        permissive_nacls.append(nacl_id)
                        break
                    
                    # Check for common sensitive ports being open to all
                    if port_range:
                        from_port = port_range.get('From', 0)
                        to_port = port_range.get('To', 65535)
                        
                        # Check if sensitive ports are included in the range
                        sensitive_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
                        for port in sensitive_ports:
                            if from_port <= port <= to_port:
                                permissive_nacls.append(nacl_id)
                                break
                        
                        # Also flag if the entire port range is open
                        if from_port == 0 and to_port == 65535:
                            permissive_nacls.append(nacl_id)
                            break
                    
                    # If no port range specified, it might be allowing all
                    elif not port_range and protocol in ['6', '17']:  # TCP or UDP
                        permissive_nacls.append(nacl_id)
                        break
                        
    except Exception as e:
        print(f"Error checking Network ACLs: {str(e)}")
    return list(set(permissive_nacls))  # Remove duplicates

def check_broad_route_table_routes(ec2_client):
    """
    Check for route tables with overly broad CIDR blocks pointing to internet gateways.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of route table IDs with overly broad routes
    """
    broad_route_tables = []
    try:
        route_tables = ec2_client.describe_route_tables()['RouteTables']
        
        for route_table in route_tables:
            route_table_id = route_table['RouteTableId']
            
            for route in route_table['Routes']:
                destination_cidr = route.get('DestinationCidrBlock', '')
                destination_ipv6_cidr = route.get('DestinationIpv6CidrBlock', '')
                gateway_id = route.get('GatewayId', '')
                
                # Check for default routes (0.0.0.0/0 or ::/0) pointing to internet gateways
                if (destination_cidr == '0.0.0.0/0' or destination_ipv6_cidr == '::/0'):
                    # Check if it's pointing to an internet gateway
                    if gateway_id and gateway_id.startswith('igw-'):
                        # This is expected for public subnets, but we'll flag it for review
                        # In a more sophisticated check, we'd verify if this is a public subnet
                        broad_route_tables.append(route_table_id)
                        break
                
                # Check for overly broad private network routes
                elif destination_cidr:
                    # Flag routes that are broader than typical private network ranges
                    # but not the default route (which we handled above)
                    try:
                        # Parse CIDR to check prefix length
                        if '/' in destination_cidr:
                            prefix_length = int(destination_cidr.split('/')[1])
                            # Flag routes with very broad CIDR blocks (less than /16)
                            # that aren't pointing to local gateways
                            if prefix_length < 16 and not gateway_id.startswith('local'):
                                broad_route_tables.append(route_table_id)
                                break
                    except (ValueError, IndexError):
                        # Skip malformed CIDR blocks
                        continue
                        
    except Exception as e:
        print(f"Error checking route tables: {str(e)}")
    return list(set(broad_route_tables))  # Remove duplicates

def check_lambda_vpc_config(lambda_client, ec2_client):
    """
    Check for Lambda functions configured in public subnets.
    
    Args:
        lambda_client: Boto3 Lambda client
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of Lambda function names in public subnets
    """
    functions_in_public_subnets = []
    try:
        functions = lambda_client.list_functions()['Functions']
        
        for function in functions:
            function_name = function['FunctionName']
            vpc_config = function.get('VpcConfig', {})
            
            if vpc_config.get('SubnetIds'):
                subnet_ids = vpc_config['SubnetIds']
                
                try:
                    # Get subnet details
                    subnets = ec2_client.describe_subnets(SubnetIds=subnet_ids)['Subnets']
                    
                    for subnet in subnets:
                        # Check if subnet is public by looking at route tables
                        subnet_id = subnet['SubnetId']
                        vpc_id = subnet['VpcId']
                        
                        try:
                            # Get route tables for this subnet
                            route_tables = ec2_client.describe_route_tables(
                                Filters=[
                                    {'Name': 'association.subnet-id', 'Values': [subnet_id]}
                                ]
                            )['RouteTables']
                            
                            # If no explicit association, check main route table
                            if not route_tables:
                                route_tables = ec2_client.describe_route_tables(
                                    Filters=[
                                        {'Name': 'vpc-id', 'Values': [vpc_id]},
                                        {'Name': 'association.main', 'Values': ['true']}
                                    ]
                                )['RouteTables']
                            
                            # Check if any route table has an internet gateway route
                            for route_table in route_tables:
                                for route in route_table.get('Routes', []):
                                    if (route.get('DestinationCidrBlock') == '0.0.0.0/0' and 
                                        route.get('GatewayId', '').startswith('igw-')):
                                        functions_in_public_subnets.append(function_name)
                                        break
                                if function_name in functions_in_public_subnets:
                                    break
                                    
                        except Exception as e:
                            print(f"Error checking route tables for subnet {subnet_id}: {str(e)}")
                            
                except Exception as e:
                    print(f"Error checking subnets for function {function_name}: {str(e)}")
                    
    except Exception as e:
        print(f"Error checking Lambda VPC configuration: {str(e)}")
    return functions_in_public_subnets

def check_lambda_runtime_versions(lambda_client):
    """
    Check for Lambda functions with outdated runtime versions.
    
    Args:
        lambda_client: Boto3 Lambda client
        
    Returns:
        list: List of Lambda function names with outdated runtime versions
    """
    functions_with_outdated_runtimes = []
    
    # Define current supported runtime versions (as of 2024)
    # These should be updated periodically as AWS updates supported versions
    outdated_runtimes = {
        'python3.6', 'python3.7', 'python3.8',  # Python < 3.9
        'nodejs12.x', 'nodejs14.x', 'nodejs16.x',  # Node.js < 18.x
        'java8', 'java8.al2',  # Java < 11
        'dotnetcore2.1', 'dotnetcore3.1',  # .NET Core < 6
        'go1.x',  # Go < 1.18
        'ruby2.5', 'ruby2.7',  # Ruby < 3.0
        'provided'  # Custom runtime (flagged for review)
    }
    
    try:
        functions = lambda_client.list_functions()['Functions']
        
        for function in functions:
            function_name = function['FunctionName']
            runtime = function.get('Runtime', '')
            
            if runtime in outdated_runtimes:
                functions_with_outdated_runtimes.append(f"{function_name}:{runtime}")
                
    except Exception as e:
        print(f"Error checking Lambda runtime versions: {str(e)}")
    return functions_with_outdated_runtimes

def check_ec2_detailed_monitoring(ec2_client):
    """
    Check for EC2 instances without detailed monitoring enabled.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of EC2 instance IDs without detailed monitoring
    """
    instances_without_detailed_monitoring = []
    try:
        reservations = ec2_client.describe_instances()['Reservations']
        
        for reservation in reservations:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                
                # Skip terminated instances
                if instance['State']['Name'] in ['terminated', 'terminating']:
                    continue
                
                # Check monitoring state
                monitoring = instance.get('Monitoring', {})
                monitoring_state = monitoring.get('State', 'disabled')
                
                if monitoring_state != 'enabled':
                    instances_without_detailed_monitoring.append(instance_id)
                    
    except Exception as e:
        print(f"Error checking EC2 detailed monitoring: {str(e)}")
    return instances_without_detailed_monitoring

def check_default_security_groups(ec2_client):
    """
    Check for EC2 instances using default security groups.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of EC2 instance IDs using default security groups
    """
    instances_with_default_sg = []
    try:
        reservations = ec2_client.describe_instances()['Reservations']
        
        for reservation in reservations:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                
                # Skip terminated instances
                if instance['State']['Name'] in ['terminated', 'terminating']:
                    continue
                
                # Check security groups
                security_groups = instance.get('SecurityGroups', [])
                
                for sg in security_groups:
                    sg_name = sg.get('GroupName', '')
                    if sg_name == 'default':
                        instances_with_default_sg.append(instance_id)
                        break
                        
    except Exception as e:
        print(f"Error checking EC2 default security groups: {str(e)}")
    return instances_with_default_sg

def check_public_ebs_snapshots(ec2_client):
    """
    Check for EBS snapshots that are publicly accessible.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of public EBS snapshot IDs
    """
    public_ebs_snapshots = []
    try:
        # Get snapshots owned by the current account
        snapshots = ec2_client.describe_snapshots(OwnerIds=['self'])['Snapshots']
        
        for snapshot in snapshots:
            snapshot_id = snapshot['SnapshotId']
            
            try:
                # Check snapshot permissions
                permissions = ec2_client.describe_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    Attribute='createVolumePermission'
                )
                
                # Check if snapshot is public
                create_volume_permissions = permissions.get('CreateVolumePermissions', [])
                for permission in create_volume_permissions:
                    if permission.get('Group') == 'all':
                        public_ebs_snapshots.append(snapshot_id)
                        break
                        
            except Exception as e:
                # Skip snapshots we can't check (might be shared from other accounts)
                print(f"Error checking snapshot permissions for {snapshot_id}: {str(e)}")
                continue
                
    except Exception as e:
        print(f"Error checking EBS snapshots for public access: {str(e)}")
    return public_ebs_snapshots

def check_public_amis(ec2_client):
    """
    Check for AMIs owned by the account that are publicly accessible.
    
    Args:
        ec2_client: Boto3 EC2 client
        
    Returns:
        list: List of public AMI IDs owned by the account
    """
    public_amis = []
    try:
        # Get AMIs owned by the current account
        amis = ec2_client.describe_images(Owners=['self'])['Images']
        
        for ami in amis:
            ami_id = ami['ImageId']
            
            # Check if AMI is public
            if ami.get('Public', False):
                public_amis.append(ami_id)
                
    except Exception as e:
        print(f"Error checking AMIs for public access: {str(e)}")
    return public_amis

def check_route53_query_logging(route53_client):
    """
    Check for Route53 hosted zones without query logging enabled.
    
    Args:
        route53_client: Boto3 Route53 client
        
    Returns:
        list: List of hosted zone IDs without query logging
    """
    zones_without_query_logging = []
    try:
        # Get all hosted zones
        hosted_zones = route53_client.list_hosted_zones()['HostedZones']
        
        for zone in hosted_zones:
            zone_id = zone['Id'].replace('/hostedzone/', '')  # Remove prefix
            zone_name = zone['Name']
            
            try:
                # Check if query logging is configured for this zone
                query_logging_configs = route53_client.list_query_logging_configs(
                    HostedZoneId=zone_id
                )['QueryLoggingConfigs']
                
                # If no query logging configurations found, add to list
                if not query_logging_configs:
                    zones_without_query_logging.append(f"{zone_name}({zone_id})")
                    
            except Exception as e:
                print(f"Error checking query logging for zone {zone_name}: {str(e)}")
                
    except Exception as e:
        print(f"Error checking Route53 query logging: {str(e)}")
    return zones_without_query_logging

def check_route53_wildcard_records(route53_client):
    """
    Check for Route53 wildcard records that may be overly permissive.
    
    Args:
        route53_client: Boto3 Route53 client
        
    Returns:
        list: List of wildcard record identifiers that may pose security risks
    """
    risky_wildcard_records = []
    try:
        # Get all hosted zones
        hosted_zones = route53_client.list_hosted_zones()['HostedZones']
        
        for zone in hosted_zones:
            zone_id = zone['Id'].replace('/hostedzone/', '')  # Remove prefix
            zone_name = zone['Name']
            
            try:
                # Get all resource record sets for this zone
                paginator = route53_client.get_paginator('list_resource_record_sets')
                page_iterator = paginator.paginate(HostedZoneId=zone_id)
                
                for page in page_iterator:
                    for record_set in page['ResourceRecordSets']:
                        record_name = record_set['Name']
                        record_type = record_set['Type']
                        
                        # Check for wildcard records (starting with *)
                        if record_name.startswith('*.'):
                            # Focus on potentially risky record types
                            if record_type in ['A', 'AAAA', 'CNAME', 'MX']:
                                # Check if it's a broad wildcard (e.g., *.example.com vs *.api.example.com)
                                subdomain_parts = record_name.replace('*.', '').split('.')
                                
                                # Flag wildcards that are too broad (directly under main domain)
                                if len(subdomain_parts) <= 2:  # e.g., *.example.com
                                    risky_wildcard_records.append(f"{record_name}({record_type})")
                                # Also flag wildcards pointing to public IPs or external domains
                                elif record_type in ['A', 'AAAA'] and 'ResourceRecords' in record_set:
                                    for resource_record in record_set['ResourceRecords']:
                                        value = resource_record['Value']
                                        # Check for public IP ranges (simplified check)
                                        if not (value.startswith('10.') or value.startswith('172.') or 
                                               value.startswith('192.168.') or value.startswith('127.')):
                                            risky_wildcard_records.append(f"{record_name}({record_type})->{value}")
                                            break
                                            
            except Exception as e:
                print(f"Error checking wildcard records for zone {zone_name}: {str(e)}")
                
    except Exception as e:
        print(f"Error checking Route53 wildcard records: {str(e)}")
    return risky_wildcard_records

def check_iam_wildcard_policies(iam_client):
    """
    Check for IAM policies with wildcard permissions that may be overly permissive.
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of policy identifiers with wildcard permissions
    """
    policies_with_wildcards = []
    try:
        # Check customer managed policies
        paginator = iam_client.get_paginator('list_policies')
        page_iterator = paginator.paginate(Scope='Local')  # Only customer managed policies
        
        for page in page_iterator:
            for policy in page['Policies']:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                
                try:
                    # Get the default policy version
                    policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                    policy_doc = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy_version
                    )['PolicyVersion']['Document']
                    
                    # Check for wildcard permissions in statements
                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            # Convert to lists if they're strings
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            
                            # Check for wildcard actions
                            has_wildcard_action = any('*' in action for action in actions)
                            # Check for wildcard resources
                            has_wildcard_resource = any('*' in resource for resource in resources)
                            
                            # Flag policies with both wildcard actions and resources (most dangerous)
                            if has_wildcard_action and has_wildcard_resource:
                                policies_with_wildcards.append(f"{policy_name}(full-wildcard)")
                                break
                            # Also flag policies with just wildcard actions on sensitive services
                            elif has_wildcard_action:
                                # Check if wildcard applies to sensitive services
                                sensitive_wildcards = ['*', 'iam:*', 'ec2:*', 's3:*', 'rds:*', 'lambda:*']
                                if any(action in sensitive_wildcards for action in actions):
                                    policies_with_wildcards.append(f"{policy_name}(action-wildcard)")
                                    break
                                    
                except Exception as e:
                    print(f"Error checking policy {policy_name}: {str(e)}")
        
        # Check inline policies for users
        users = iam_client.list_users()['Users']
        for user in users:
            username = user['UserName']
            try:
                inline_policies = iam_client.list_user_policies(UserName=username)['PolicyNames']
                for policy_name in inline_policies:
                    try:
                        policy_doc = iam_client.get_user_policy(
                            UserName=username,
                            PolicyName=policy_name
                        )['PolicyDocument']
                        
                        # Check for wildcard permissions
                        for statement in policy_doc.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                resources = statement.get('Resource', [])
                                
                                if isinstance(actions, str):
                                    actions = [actions]
                                if isinstance(resources, str):
                                    resources = [resources]
                                
                                has_wildcard_action = any('*' in action for action in actions)
                                has_wildcard_resource = any('*' in resource for resource in resources)
                                
                                if has_wildcard_action and has_wildcard_resource:
                                    policies_with_wildcards.append(f"{username}:{policy_name}(user-inline-full-wildcard)")
                                    break
                                elif has_wildcard_action:
                                    sensitive_wildcards = ['*', 'iam:*', 'ec2:*', 's3:*', 'rds:*', 'lambda:*']
                                    if any(action in sensitive_wildcards for action in actions):
                                        policies_with_wildcards.append(f"{username}:{policy_name}(user-inline-action-wildcard)")
                                        break
                    except Exception as e:
                        print(f"Error checking inline policy {policy_name} for user {username}: {str(e)}")
            except Exception as e:
                print(f"Error checking inline policies for user {username}: {str(e)}")
        
        # Check inline policies for roles
        paginator = iam_client.get_paginator('list_roles')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for role in page['Roles']:
                role_name = role['RoleName']
                try:
                    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
                    for policy_name in inline_policies:
                        try:
                            policy_doc = iam_client.get_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name
                            )['PolicyDocument']
                            
                            # Check for wildcard permissions
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    resources = statement.get('Resource', [])
                                    
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    if isinstance(resources, str):
                                        resources = [resources]
                                    
                                    has_wildcard_action = any('*' in action for action in actions)
                                    has_wildcard_resource = any('*' in resource for resource in resources)
                                    
                                    if has_wildcard_action and has_wildcard_resource:
                                        policies_with_wildcards.append(f"{role_name}:{policy_name}(role-inline-full-wildcard)")
                                        break
                                    elif has_wildcard_action:
                                        sensitive_wildcards = ['*', 'iam:*', 'ec2:*', 's3:*', 'rds:*', 'lambda:*']
                                        if any(action in sensitive_wildcards for action in actions):
                                            policies_with_wildcards.append(f"{role_name}:{policy_name}(role-inline-action-wildcard)")
                                            break
                        except Exception as e:
                            print(f"Error checking inline policy {policy_name} for role {role_name}: {str(e)}")
                except Exception as e:
                    print(f"Error checking inline policies for role {role_name}: {str(e)}")
                    
    except Exception as e:
        print(f"Error checking IAM wildcard policies: {str(e)}")
    return policies_with_wildcards

def check_iam_broad_trust_relationships(iam_client):
    """
    Check for IAM roles with overly broad trust relationships.
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of role names with overly broad trust relationships
    """
    roles_with_broad_trust = []
    try:
        paginator = iam_client.get_paginator('list_roles')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for role in page['Roles']:
                role_name = role['RoleName']
                assume_role_policy = role['AssumeRolePolicyDocument']
                
                try:
                    # Check trust policy statements
                    for statement in assume_role_policy.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            principal = statement.get('Principal', {})
                            
                            # Check for overly broad principals
                            if principal == '*':
                                roles_with_broad_trust.append(f"{role_name}(wildcard-principal)")
                                break
                            elif isinstance(principal, dict):
                                # Check AWS principals
                                aws_principals = principal.get('AWS', [])
                                if isinstance(aws_principals, str):
                                    aws_principals = [aws_principals]
                                
                                for aws_principal in aws_principals:
                                    # Check for wildcard AWS principals
                                    if aws_principal == '*':
                                        roles_with_broad_trust.append(f"{role_name}(wildcard-aws-principal)")
                                        break
                                    # Check for root account access from unknown accounts
                                    elif aws_principal.endswith(':root'):
                                        # Extract account ID
                                        account_id = aws_principal.split(':')[4]
                                        # Flag if it's not the current account (cross-account root access)
                                        # Note: We can't easily get current account ID here, so we flag all root access
                                        roles_with_broad_trust.append(f"{role_name}(root-access-{account_id})")
                                        break
                                
                                # Check service principals that might be too broad
                                service_principals = principal.get('Service', [])
                                if isinstance(service_principals, str):
                                    service_principals = [service_principals]
                                
                                # Flag roles that can be assumed by potentially risky services
                                risky_services = ['*', '*.amazonaws.com']
                                for service_principal in service_principals:
                                    if service_principal in risky_services:
                                        roles_with_broad_trust.append(f"{role_name}(broad-service-{service_principal})")
                                        break
                                
                                # Check federated principals
                                federated_principals = principal.get('Federated', [])
                                if isinstance(federated_principals, str):
                                    federated_principals = [federated_principals]
                                
                                for federated_principal in federated_principals:
                                    # Flag SAML providers without conditions (potentially risky)
                                    if 'saml-provider' in federated_principal:
                                        conditions = statement.get('Condition', {})
                                        if not conditions:
                                            roles_with_broad_trust.append(f"{role_name}(unconditioned-saml)")
                                            break
                                    # Flag OIDC providers without conditions
                                    elif 'oidc-provider' in federated_principal:
                                        conditions = statement.get('Condition', {})
                                        if not conditions:
                                            roles_with_broad_trust.append(f"{role_name}(unconditioned-oidc)")
                                            break
                                            
                except Exception as e:
                    print(f"Error checking trust relationship for role {role_name}: {str(e)}")
                    
    except Exception as e:
        print(f"Error checking IAM trust relationships: {str(e)}")
    return roles_with_broad_trust

def check_iam_unused_access_keys(iam_client):
    """
    Check for IAM users with old or unused access keys.
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of users with old or unused access keys
    """
    users_with_unused_keys = []
    try:
        users = iam_client.list_users()['Users']
        cutoff_date = datetime.now() - timedelta(days=90)  # Keys older than 90 days
        
        for user in users:
            username = user['UserName']
            
            try:
                access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
                
                for key in access_keys:
                    if key['Status'] == 'Active':
                        access_key_id = key['AccessKeyId']
                        create_date = key['CreateDate'].replace(tzinfo=None)
                        
                        try:
                            # Check when the key was last used
                            last_used_info = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                            last_used_data = last_used_info.get('AccessKeyLastUsed', {})
                            last_used_date = last_used_data.get('LastUsedDate')
                            
                            if last_used_date:
                                last_used_date = last_used_date.replace(tzinfo=None)
                                # Key hasn't been used in 90+ days
                                if last_used_date < cutoff_date:
                                    days_unused = (datetime.now() - last_used_date).days
                                    users_with_unused_keys.append(f"{username}:{access_key_id[:8]}(unused-{days_unused}d)")
                            else:
                                # Key has never been used
                                days_old = (datetime.now() - create_date).days
                                if days_old > 7:  # Give some grace period for new keys
                                    users_with_unused_keys.append(f"{username}:{access_key_id[:8]}(never-used-{days_old}d)")
                            
                            # Also check if key is very old regardless of usage
                            if create_date < cutoff_date:
                                days_old = (datetime.now() - create_date).days
                                # Only flag if not already flagged for non-usage
                                key_identifier = f"{username}:{access_key_id[:8]}"
                                if not any(key_identifier in existing for existing in users_with_unused_keys):
                                    users_with_unused_keys.append(f"{username}:{access_key_id[:8]}(old-{days_old}d)")
                                    
                        except Exception as e:
                            print(f"Error checking access key usage for {username}:{access_key_id[:8]}: {str(e)}")
                            
            except Exception as e:
                print(f"Error checking access keys for user {username}: {str(e)}")
                
    except Exception as e:
        print(f"Error checking unused access keys: {str(e)}")
    return users_with_unused_keys

def check_iam_password_policy(iam_client):
    """
    Check IAM password policy for security weaknesses.
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of password policy issues
    """
    password_policy_issues = []
    try:
        try:
            policy = iam_client.get_account_password_policy()['PasswordPolicy']
            
            # Check minimum password length (should be at least 14 characters)
            min_length = policy.get('MinimumPasswordLength', 0)
            if min_length < 14:
                password_policy_issues.append(f'min-length-{min_length}(recommended-14+)')
            
            # Check character requirements
            if not policy.get('RequireUppercaseCharacters', False):
                password_policy_issues.append('no-uppercase-required')
            
            if not policy.get('RequireLowercaseCharacters', False):
                password_policy_issues.append('no-lowercase-required')
            
            if not policy.get('RequireNumbers', False):
                password_policy_issues.append('no-numbers-required')
            
            if not policy.get('RequireSymbols', False):
                password_policy_issues.append('no-symbols-required')
            
            # Check password expiration (should be set and reasonable)
            max_age = policy.get('MaxPasswordAge')
            if not max_age:
                password_policy_issues.append('no-password-expiration')
            elif max_age > 90:
                password_policy_issues.append(f'max-age-{max_age}d(recommended-90d)')
            
            # Check password reuse prevention (should prevent reuse of recent passwords)
            reuse_prevention = policy.get('PasswordReusePrevention', 0)
            if reuse_prevention < 12:  # AWS recommends 24, but 12 is reasonable minimum
                password_policy_issues.append(f'reuse-prevention-{reuse_prevention}(recommended-12+)')
            
            # Check if users can change their own passwords
            if not policy.get('AllowUsersToChangePassword', False):
                password_policy_issues.append('users-cannot-change-password')
            
            # Check hard expiry (whether users are prevented from setting new password after expiry)
            if policy.get('HardExpiry', False):
                # Hard expiry can lock users out, which might not be desirable
                password_policy_issues.append('hard-expiry-enabled(review-needed)')
                
        except iam_client.exceptions.NoSuchEntityException:
            # No password policy is set
            password_policy_issues.append('no-password-policy-set')
            
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    return password_policy_issues