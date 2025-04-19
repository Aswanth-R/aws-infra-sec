"""
Core functionality for AWS Sentinel security checks
"""
import boto3

def check_public_buckets(s3_client):
    """
    Check for S3 buckets with public access.
    
    Args:
        s3_client: Boto3 S3 client
        
    Returns:
        list: List of public bucket names
    """
    public_buckets = []
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
    sgs = ec2_client.describe_security_groups()['SecurityGroups']
    for sg in sgs:
        for rule in sg['IpPermissions']:
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if rule.get('FromPort') == 22 or rule.get('ToPort') == 22:
                        public_sgs.append(sg['GroupId'])
                        break
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
    volumes = ec2_client.describe_volumes()['Volumes']
    for volume in volumes:
        if not volume['Encrypted']:
            unencrypted_volumes.append(volume['VolumeId'])
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
    users = iam_client.list_users()['Users']
    for user in users:
        mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            users_without_mfa.append(user['UserName'])
    return users_without_mfa