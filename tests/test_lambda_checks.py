"""
Tests for AWS InfraSec Lambda security check functionality
"""
import unittest
from unittest.mock import Mock
from moto import mock_aws
import boto3
import json
import logging
import sys
import colorama
from colorama import Fore, Style

from aws_infrasec.core import (
    check_lambda_execution_roles,
    check_lambda_environment_encryption,
    check_lambda_vpc_config,
    check_lambda_runtime_versions
)

# Set up colorful logging
colorama.init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('LambdaSecurityTest')

class TestLambdaSecurityChecks(unittest.TestCase):
    
    def setUp(self):
        logger.info(f"{Fore.CYAN}Starting test: {self._testMethodName}{Style.RESET_ALL}")
        
    def tearDown(self):
        logger.info(f"{Fore.CYAN}Completed test: {self._testMethodName}{Style.RESET_ALL}")
        print("-" * 70)

    @mock_aws
    def test_check_lambda_execution_roles(self):
        """Test Lambda execution roles check for overly permissive roles"""
        logger.info("Setting up Lambda functions for execution roles test...")
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        iam_client = boto3.client('iam', region_name='us-east-1')
        
        # Create IAM roles with different permission levels
        
        # 1. Create a restrictive role (good)
        restrictive_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    "Resource": "arn:aws:logs:*:*:*"
                }
            ]
        }
        
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        # Create restrictive role
        iam_client.create_role(
            RoleName='lambda-restrictive-role',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        iam_client.put_role_policy(
            RoleName='lambda-restrictive-role',
            PolicyName='RestrictivePolicy',
            PolicyDocument=json.dumps(restrictive_policy)
        )
        logger.info(f"{Fore.GREEN}Created restrictive IAM role: 'lambda-restrictive-role'{Style.RESET_ALL}")
        
        # 2. Create a permissive role with wildcard actions (bad)
        permissive_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        
        iam_client.create_role(
            RoleName='lambda-permissive-role',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        iam_client.put_role_policy(
            RoleName='lambda-permissive-role',
            PolicyName='PermissivePolicy',
            PolicyDocument=json.dumps(permissive_policy)
        )
        logger.info(f"{Fore.YELLOW}Created permissive IAM role: 'lambda-permissive-role'{Style.RESET_ALL}")
        
        # Create Lambda functions with different roles
        
        # Function with restrictive role (good)
        lambda_client.create_function(
            FunctionName='secure-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-restrictive-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Description='Function with restrictive role'
        )
        logger.info(f"{Fore.GREEN}Created Lambda function with restrictive role: 'secure-function'{Style.RESET_ALL}")
        
        # Function with permissive inline policy (bad)
        lambda_client.create_function(
            FunctionName='permissive-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-permissive-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Description='Function with permissive role'
        )
        logger.info(f"{Fore.YELLOW}Created Lambda function with permissive role: 'permissive-function'{Style.RESET_ALL}")

        logger.info("Running check_lambda_execution_roles function...")
        permissive_functions = check_lambda_execution_roles(lambda_client, iam_client)
        
        logger.info(f"Found {len(permissive_functions)} functions with permissive roles: {permissive_functions}")
        self.assertEqual(len(permissive_functions), 1, "Expected 1 function with permissive role")
        self.assertIn('permissive-function', permissive_functions)
        self.assertNotIn('secure-function', permissive_functions)
        logger.info(f"{Fore.GREEN}Lambda execution roles check passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_lambda_execution_roles_error_handling(self):
        """Test error handling for Lambda execution roles check"""
        logger.info("Testing Lambda execution roles error handling...")
        
        mock_lambda_client = Mock()
        mock_iam_client = Mock()
        mock_lambda_client.list_functions.side_effect = Exception("Access Denied")
        
        permissive_functions = check_lambda_execution_roles(mock_lambda_client, mock_iam_client)
        self.assertEqual(len(permissive_functions), 0, "Should return empty list on error")
        logger.info(f"{Fore.GREEN}Lambda execution roles error handling test passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_lambda_environment_encryption(self):
        """Test Lambda environment variable encryption check"""
        logger.info("Setting up Lambda functions for environment encryption test...")
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        iam_client = boto3.client('iam', region_name='us-east-1')
        
        # Create IAM role for Lambda functions
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam_client.create_role(
            RoleName='lambda-test-role',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        
        # Create a function without environment variables (should not be flagged)
        lambda_client.create_function(
            FunctionName='no-env-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-test-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Description='Function without environment variables'
        )
        logger.info(f"{Fore.GREEN}Created Lambda function without env vars: 'no-env-function'{Style.RESET_ALL}")
        
        # Create a function with environment variables but no encryption (should be flagged)
        lambda_client.create_function(
            FunctionName='env-no-encryption-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-test-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Environment={
                'Variables': {
                    'DB_PASSWORD': 'secret123',
                    'API_KEY': 'key456'
                }
                # No KMSKeyArn specified - should be flagged
            },
            Description='Function with environment variables but no encryption'
        )
        logger.info(f"{Fore.YELLOW}Created Lambda function with env vars but no encryption: 'env-no-encryption-function'{Style.RESET_ALL}")
        
        # Create a function with unencrypted environment variables (should be flagged)
        lambda_client.create_function(
            FunctionName='unencrypted-env-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-test-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Environment={
                'Variables': {
                    'DB_PASSWORD': 'secret123',
                    'API_KEY': 'key456'
                }
                # No KMSKeyArn specified
            },
            Description='Function with unencrypted environment variables'
        )
        logger.info(f"{Fore.YELLOW}Created Lambda function with unencrypted env vars: 'unencrypted-env-function'{Style.RESET_ALL}")

        logger.info("Running check_lambda_environment_encryption function...")
        unencrypted_functions = check_lambda_environment_encryption(lambda_client)
        
        logger.info(f"Found {len(unencrypted_functions)} functions without env encryption: {unencrypted_functions}")
        self.assertEqual(len(unencrypted_functions), 2, "Expected 2 functions without environment encryption")
        self.assertIn('env-no-encryption-function', unencrypted_functions)
        self.assertIn('unencrypted-env-function', unencrypted_functions)
        logger.info(f"{Fore.GREEN}Lambda environment encryption check passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_lambda_environment_encryption_error_handling(self):
        """Test error handling for Lambda environment encryption check"""
        logger.info("Testing Lambda environment encryption error handling...")
        
        mock_client = Mock()
        mock_client.list_functions.side_effect = Exception("Permission denied")
        
        unencrypted_functions = check_lambda_environment_encryption(mock_client)
        self.assertEqual(len(unencrypted_functions), 0, "Should return empty list on error")
        logger.info(f"{Fore.GREEN}Lambda environment encryption error handling test passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_lambda_vpc_config(self):
        """Test Lambda VPC configuration check for public subnets"""
        logger.info("Setting up Lambda functions for VPC configuration test...")
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        iam_client = boto3.client('iam', region_name='us-east-1')
        
        # Create IAM role for Lambda functions
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam_client.create_role(
            RoleName='lambda-vpc-test-role',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        
        # Create VPC and networking components
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        logger.info(f"Created VPC: {vpc_id}")
        
        # Create Internet Gateway
        igw = ec2_client.create_internet_gateway()
        igw_id = igw['InternetGateway']['InternetGatewayId']
        ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        logger.info(f"Created and attached Internet Gateway: {igw_id}")
        
        # Create public subnet
        public_subnet = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock='10.0.1.0/24',
            AvailabilityZone='us-east-1a'
        )
        public_subnet_id = public_subnet['Subnet']['SubnetId']
        logger.info(f"Created public subnet: {public_subnet_id}")
        
        # Create private subnet
        private_subnet = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock='10.0.2.0/24',
            AvailabilityZone='us-east-1b'
        )
        private_subnet_id = private_subnet['Subnet']['SubnetId']
        logger.info(f"Created private subnet: {private_subnet_id}")
        
        # Create route table for public subnet with internet gateway route
        public_route_table = ec2_client.create_route_table(VpcId=vpc_id)
        public_rt_id = public_route_table['RouteTable']['RouteTableId']
        
        ec2_client.create_route(
            RouteTableId=public_rt_id,
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=igw_id
        )
        
        ec2_client.associate_route_table(
            RouteTableId=public_rt_id,
            SubnetId=public_subnet_id
        )
        logger.info(f"{Fore.YELLOW}Created public route table with IGW route: {public_rt_id}{Style.RESET_ALL}")
        
        # Create route table for private subnet (no internet gateway route)
        private_route_table = ec2_client.create_route_table(VpcId=vpc_id)
        private_rt_id = private_route_table['RouteTable']['RouteTableId']
        
        ec2_client.associate_route_table(
            RouteTableId=private_rt_id,
            SubnetId=private_subnet_id
        )
        logger.info(f"{Fore.GREEN}Created private route table without IGW route: {private_rt_id}{Style.RESET_ALL}")
        
        # Create Lambda functions with different VPC configurations
        
        # Function not in VPC (should not be flagged)
        lambda_client.create_function(
            FunctionName='no-vpc-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-vpc-test-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Description='Function not in VPC'
        )
        logger.info(f"{Fore.GREEN}Created Lambda function not in VPC: 'no-vpc-function'{Style.RESET_ALL}")
        
        # Function in private subnet (should not be flagged)
        lambda_client.create_function(
            FunctionName='private-subnet-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-vpc-test-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            VpcConfig={
                'SubnetIds': [private_subnet_id],
                'SecurityGroupIds': []
            },
            Description='Function in private subnet'
        )
        logger.info(f"{Fore.GREEN}Created Lambda function in private subnet: 'private-subnet-function'{Style.RESET_ALL}")
        
        # Function in public subnet (should be flagged)
        lambda_client.create_function(
            FunctionName='public-subnet-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-vpc-test-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            VpcConfig={
                'SubnetIds': [public_subnet_id],
                'SecurityGroupIds': []
            },
            Description='Function in public subnet'
        )
        logger.info(f"{Fore.YELLOW}Created Lambda function in public subnet: 'public-subnet-function'{Style.RESET_ALL}")

        logger.info("Running check_lambda_vpc_config function...")
        functions_in_public = check_lambda_vpc_config(lambda_client, ec2_client)
        
        logger.info(f"Found {len(functions_in_public)} functions in public subnets: {functions_in_public}")
        self.assertEqual(len(functions_in_public), 1, "Expected 1 function in public subnet")
        self.assertEqual(functions_in_public[0], 'public-subnet-function')
        logger.info(f"{Fore.GREEN}Lambda VPC configuration check passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_lambda_vpc_config_error_handling(self):
        """Test error handling for Lambda VPC configuration check"""
        logger.info("Testing Lambda VPC configuration error handling...")
        
        mock_lambda_client = Mock()
        mock_ec2_client = Mock()
        mock_lambda_client.list_functions.side_effect = Exception("Access Denied")
        
        functions_in_public = check_lambda_vpc_config(mock_lambda_client, mock_ec2_client)
        self.assertEqual(len(functions_in_public), 0, "Should return empty list on error")
        logger.info(f"{Fore.GREEN}Lambda VPC configuration error handling test passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_lambda_runtime_versions(self):
        """Test Lambda runtime versions check for outdated runtimes"""
        logger.info("Setting up Lambda functions for runtime versions test...")
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        iam_client = boto3.client('iam', region_name='us-east-1')
        
        # Create IAM role for Lambda functions
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam_client.create_role(
            RoleName='lambda-runtime-test-role',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        
        # Create functions with current/supported runtimes (should not be flagged)
        lambda_client.create_function(
            FunctionName='current-python-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-runtime-test-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Description='Function with current Python runtime'
        )
        logger.info(f"{Fore.GREEN}Created Lambda function with current Python runtime: 'current-python-function'{Style.RESET_ALL}")
        
        lambda_client.create_function(
            FunctionName='current-nodejs-function',
            Runtime='nodejs18.x',
            Role='arn:aws:iam::123456789012:role/lambda-runtime-test-role',
            Handler='index.handler',
            Code={'ZipFile': b'fake code'},
            Description='Function with current Node.js runtime'
        )
        logger.info(f"{Fore.GREEN}Created Lambda function with current Node.js runtime: 'current-nodejs-function'{Style.RESET_ALL}")
        
        # Create functions with outdated runtimes (should be flagged)
        lambda_client.create_function(
            FunctionName='outdated-python-function',
            Runtime='python3.7',
            Role='arn:aws:iam::123456789012:role/lambda-runtime-test-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Description='Function with outdated Python runtime'
        )
        logger.info(f"{Fore.YELLOW}Created Lambda function with outdated Python runtime: 'outdated-python-function'{Style.RESET_ALL}")
        
        lambda_client.create_function(
            FunctionName='outdated-nodejs-function',
            Runtime='nodejs14.x',
            Role='arn:aws:iam::123456789012:role/lambda-runtime-test-role',
            Handler='index.handler',
            Code={'ZipFile': b'fake code'},
            Description='Function with outdated Node.js runtime'
        )
        logger.info(f"{Fore.YELLOW}Created Lambda function with outdated Node.js runtime: 'outdated-nodejs-function'{Style.RESET_ALL}")
        
        lambda_client.create_function(
            FunctionName='outdated-java-function',
            Runtime='java8',
            Role='arn:aws:iam::123456789012:role/lambda-runtime-test-role',
            Handler='com.example.Handler',
            Code={'ZipFile': b'fake code'},
            Description='Function with outdated Java runtime'
        )
        logger.info(f"{Fore.YELLOW}Created Lambda function with outdated Java runtime: 'outdated-java-function'{Style.RESET_ALL}")

        logger.info("Running check_lambda_runtime_versions function...")
        outdated_functions = check_lambda_runtime_versions(lambda_client)
        
        logger.info(f"Found {len(outdated_functions)} functions with outdated runtimes: {outdated_functions}")
        self.assertEqual(len(outdated_functions), 3, "Expected 3 functions with outdated runtimes")
        
        # Check that function names and runtimes are included in results
        outdated_function_names = [func.split(':')[0] for func in outdated_functions]
        self.assertIn('outdated-python-function', outdated_function_names)
        self.assertIn('outdated-nodejs-function', outdated_function_names)
        self.assertIn('outdated-java-function', outdated_function_names)
        
        # Check that current functions are not flagged
        self.assertNotIn('current-python-function', outdated_function_names)
        self.assertNotIn('current-nodejs-function', outdated_function_names)
        
        # Verify runtime information is included
        self.assertIn('outdated-python-function:python3.7', outdated_functions)
        self.assertIn('outdated-nodejs-function:nodejs14.x', outdated_functions)
        self.assertIn('outdated-java-function:java8', outdated_functions)
        
        logger.info(f"{Fore.GREEN}Lambda runtime versions check passed!{Style.RESET_ALL}")

    @mock_aws
    def test_check_lambda_runtime_versions_error_handling(self):
        """Test error handling for Lambda runtime versions check"""
        logger.info("Testing Lambda runtime versions error handling...")
        
        mock_client = Mock()
        mock_client.list_functions.side_effect = Exception("Permission denied")
        
        outdated_functions = check_lambda_runtime_versions(mock_client)
        self.assertEqual(len(outdated_functions), 0, "Should return empty list on error")
        logger.info(f"{Fore.GREEN}Lambda runtime versions error handling test passed!{Style.RESET_ALL}")

    @mock_aws
    def test_lambda_cross_service_functionality(self):
        """Test Lambda checks that require multiple AWS services"""
        logger.info("Testing Lambda cross-service functionality...")
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        iam_client = boto3.client('iam', region_name='us-east-1')
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        
        # Create IAM role for Lambda
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        # Create a permissive policy for cross-service testing
        admin_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        
        iam_client.create_role(
            RoleName='lambda-cross-service-role',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        iam_client.put_role_policy(
            RoleName='lambda-cross-service-role',
            PolicyName='AdminPolicy',
            PolicyDocument=json.dumps(admin_policy)
        )
        
        # Create VPC and public subnet
        vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        
        igw = ec2_client.create_internet_gateway()
        igw_id = igw['InternetGateway']['InternetGatewayId']
        ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        
        public_subnet = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock='10.0.1.0/24', AvailabilityZone='us-east-1a')
        public_subnet_id = public_subnet['Subnet']['SubnetId']
        
        rt = ec2_client.create_route_table(VpcId=vpc_id)['RouteTable']['RouteTableId']
        ec2_client.create_route(RouteTableId=rt, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)
        ec2_client.associate_route_table(RouteTableId=rt, SubnetId=public_subnet_id)
        
        # Create Lambda function with multiple security issues
        lambda_client.create_function(
            FunctionName='problematic-function',
            Runtime='python3.7',  # Outdated runtime
            Role='arn:aws:iam::123456789012:role/lambda-cross-service-role',  # Overly permissive role
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Environment={
                'Variables': {
                    'SECRET_KEY': 'unencrypted-secret'  # Unencrypted environment variable
                }
            },
            VpcConfig={
                'SubnetIds': [public_subnet_id],  # Public subnet
                'SecurityGroupIds': []
            },
            Description='Function with multiple security issues'
        )
        
        logger.info("Testing cross-service Lambda security checks...")
        
        # Test execution roles check
        permissive_functions = check_lambda_execution_roles(lambda_client, iam_client)
        self.assertIn('problematic-function', permissive_functions, "Should detect overly permissive role")
        
        # Test environment encryption check
        unencrypted_functions = check_lambda_environment_encryption(lambda_client)
        self.assertIn('problematic-function', unencrypted_functions, "Should detect unencrypted environment variables")
        
        # Test VPC configuration check
        public_functions = check_lambda_vpc_config(lambda_client, ec2_client)
        self.assertIn('problematic-function', public_functions, "Should detect function in public subnet")
        
        # Test runtime versions check
        outdated_functions = check_lambda_runtime_versions(lambda_client)
        outdated_function_names = [func.split(':')[0] for func in outdated_functions]
        self.assertIn('problematic-function', outdated_function_names, "Should detect outdated runtime")
        
        logger.info(f"{Fore.GREEN}Lambda cross-service functionality test passed!{Style.RESET_ALL}")


if __name__ == '__main__':
    unittest.main()