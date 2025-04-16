"""
Tests for AWS Sentinel core functionality
"""
import unittest
from unittest.mock import patch
from moto import mock_aws
import boto3
import logging
import sys
import colorama
from colorama import Fore, Style

from aws_sentinel.core import (
    check_public_buckets,
    check_public_security_groups,
    check_unencrypted_ebs_volumes,
    check_iam_users_without_mfa
)

# Set up colorful logging
colorama.init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('AWSSecurityTest')

class TestAWSSentinel(unittest.TestCase):
    
    def setUp(self):
        logger.info(f"{Fore.CYAN}Starting test: {self._testMethodName}{Style.RESET_ALL}")
        
    def tearDown(self):
        logger.info(f"{Fore.CYAN}Completed test: {self._testMethodName}{Style.RESET_ALL}")
        print("-" * 70)

    @mock_aws
    def test_check_public_buckets(self):
        logger.info("Creating test S3 buckets...")
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='private-bucket')
        logger.info(f"{Fore.GREEN}Created private bucket: 'private-bucket'{Style.RESET_ALL}")
        
        s3.create_bucket(Bucket='public-bucket')
        s3.put_bucket_acl(Bucket='public-bucket', ACL='public-read')
        logger.info(f"{Fore.YELLOW}Created public bucket: 'public-bucket' with public-read ACL{Style.RESET_ALL}")

        logger.info("Running check_public_buckets function...")
        public_buckets = check_public_buckets(s3)
        
        logger.info(f"Found {len(public_buckets)} public buckets: {public_buckets}")
        self.assertEqual(len(public_buckets), 1, f"{Fore.RED}Expected 1 public bucket, found {len(public_buckets)}{Style.RESET_ALL}")
        self.assertEqual(public_buckets[0], 'public-bucket', f"{Fore.RED}Expected 'public-bucket', found {public_buckets[0]}{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Public buckets check passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_public_security_groups(self):
        logger.info("Setting up EC2 security groups...")
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        sg_private = ec2.create_security_group(GroupName='private', Description='private')
        logger.info(f"{Fore.GREEN}Created private security group: {sg_private['GroupId']}{Style.RESET_ALL}")
        
        sg_public = ec2.create_security_group(GroupName='public', Description='public')
        logger.info(f"Created security group: {sg_public['GroupId']}")
        
        logger.info(f"{Fore.YELLOW}Opening port 22 to the world (0.0.0.0/0) on security group: {sg_public['GroupId']}{Style.RESET_ALL}")
        ec2.authorize_security_group_ingress(
            GroupId=sg_public['GroupId'],
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )

        logger.info("Running check_public_security_groups function...")
        public_sgs = check_public_security_groups(ec2)
        
        logger.info(f"Found {len(public_sgs)} public security groups: {public_sgs}")
        self.assertEqual(len(public_sgs), 1, f"{Fore.RED}Expected 1 public security group, found {len(public_sgs)}{Style.RESET_ALL}")
        self.assertEqual(public_sgs[0], sg_public['GroupId'], 
                        f"{Fore.RED}Expected {sg_public['GroupId']}, found {public_sgs[0]}{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Security groups check passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_unencrypted_ebs_volumes(self):
        logger.info("Setting up EC2 volumes...")
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        encrypted_volume = ec2.create_volume(Size=10, AvailabilityZone='us-east-1a', Encrypted=True)
        logger.info(f"{Fore.GREEN}Created encrypted volume: {encrypted_volume['VolumeId']}{Style.RESET_ALL}")
        
        unencrypted_volume = ec2.create_volume(Size=10, AvailabilityZone='us-east-1a', Encrypted=False)
        logger.info(f"{Fore.YELLOW}Created unencrypted volume: {unencrypted_volume['VolumeId']}{Style.RESET_ALL}")

        logger.info("Running check_unencrypted_ebs_volumes function...")
        unencrypted_volumes = check_unencrypted_ebs_volumes(ec2)
        
        logger.info(f"Found {len(unencrypted_volumes)} unencrypted volumes: {unencrypted_volumes}")
        self.assertEqual(len(unencrypted_volumes), 1, 
                        f"{Fore.RED}Expected 1 unencrypted volume, found {len(unencrypted_volumes)}{Style.RESET_ALL}")
        self.assertEqual(unencrypted_volumes[0], unencrypted_volume['VolumeId'], 
                        f"{Fore.RED}Expected {unencrypted_volume['VolumeId']}, found {unencrypted_volumes[0]}{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}EBS volumes check passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_iam_users_without_mfa(self):
        logger.info("Setting up IAM users...")
        iam = boto3.client('iam')
        
        iam.create_user(UserName='user_with_mfa')
        logger.info("Created IAM user: 'user_with_mfa'")
        
        iam.create_user(UserName='user_without_mfa')
        logger.info("Created IAM user: 'user_without_mfa'")
        
        logger.info("Creating MFA device...")
        iam.create_virtual_mfa_device(VirtualMFADeviceName='mfa_device')
        
        logger.info(f"{Fore.GREEN}Enabling MFA for user: 'user_with_mfa'{Style.RESET_ALL}")
        iam.enable_mfa_device(UserName='user_with_mfa', SerialNumber='mfa_device', AuthenticationCode1='123456', AuthenticationCode2='123456')
        logger.info(f"{Fore.YELLOW}No MFA enabled for user: 'user_without_mfa'{Style.RESET_ALL}")

        logger.info("Running check_iam_users_without_mfa function...")
        users_without_mfa = check_iam_users_without_mfa(iam)
        
        logger.info(f"Found {len(users_without_mfa)} users without MFA: {users_without_mfa}")
        self.assertEqual(len(users_without_mfa), 1, 
                        f"{Fore.RED}Expected 1 user without MFA, found {len(users_without_mfa)}{Style.RESET_ALL}")
        self.assertEqual(users_without_mfa[0], 'user_without_mfa', 
                        f"{Fore.RED}Expected 'user_without_mfa', found {users_without_mfa[0]}{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}IAM users MFA check passed!{Style.RESET_ALL}")

if __name__ == '__main__':
    print(f"\n{Fore.CYAN}======= AWS SENTINEL TEST SUITE ======={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Starting tests at: {logging.Formatter().formatTime()}{Style.RESET_ALL}")
    print("=" * 40)
    unittest.main(verbosity=2)