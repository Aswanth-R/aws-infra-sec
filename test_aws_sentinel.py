import unittest
from unittest.mock import patch
from moto import mock_aws
import boto3
from main import (
    check_public_buckets,
    check_public_security_groups,
    check_unencrypted_ebs_volumes,
    check_iam_users_without_mfa
)

class TestAWSSentinel(unittest.TestCase):

    @mock_aws
    def test_check_public_buckets(self):
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='private-bucket')
        s3.create_bucket(Bucket='public-bucket')
        s3.put_bucket_acl(Bucket='public-bucket', ACL='public-read')

        public_buckets = check_public_buckets(s3)
        self.assertEqual(len(public_buckets), 1)
        self.assertEqual(public_buckets[0], 'public-bucket')

    @mock_aws
    def test_check_public_security_groups(self):
        ec2 = boto3.client('ec2', region_name='us-east-1')
        sg_private = ec2.create_security_group(GroupName='private', Description='private')
        sg_public = ec2.create_security_group(GroupName='public', Description='public')
        ec2.authorize_security_group_ingress(
            GroupId=sg_public['GroupId'],
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )

        public_sgs = check_public_security_groups(ec2)
        self.assertEqual(len(public_sgs), 1)
        self.assertEqual(public_sgs[0], sg_public['GroupId'])

    @mock_aws
    def test_check_unencrypted_ebs_volumes(self):
        ec2 = boto3.client('ec2', region_name='us-east-1')
        encrypted_volume = ec2.create_volume(Size=10, AvailabilityZone='us-east-1a', Encrypted=True)
        unencrypted_volume = ec2.create_volume(Size=10, AvailabilityZone='us-east-1a', Encrypted=False)

        unencrypted_volumes = check_unencrypted_ebs_volumes(ec2)
        self.assertEqual(len(unencrypted_volumes), 1)
        self.assertEqual(unencrypted_volumes[0], unencrypted_volume['VolumeId'])

    @mock_aws
    def test_check_iam_users_without_mfa(self):
        iam = boto3.client('iam')
        iam.create_user(UserName='user_with_mfa')
        iam.create_user(UserName='user_without_mfa')
        iam.create_virtual_mfa_device(VirtualMFADeviceName='mfa_device')
        iam.enable_mfa_device(UserName='user_with_mfa', SerialNumber='mfa_device', AuthenticationCode1='123456', AuthenticationCode2='123456')

        users_without_mfa = check_iam_users_without_mfa(iam)
        self.assertEqual(len(users_without_mfa), 1)
        self.assertEqual(users_without_mfa[0], 'user_without_mfa')

if __name__ == '__main__':
    unittest.main()