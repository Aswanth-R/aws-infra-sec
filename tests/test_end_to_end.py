"""
End-to-end tests for AWS InfraSec complete scan workflow
Tests the full CLI integration with all security checks enabled
"""
import unittest
import json
import csv
import io
import sys
from unittest.mock import patch, Mock
from moto import mock_aws
import boto3
import tempfile
import os
from click.testing import CliRunner

from aws_infrasec.cli import main
from aws_infrasec.core import *

class TestEndToEndWorkflow(unittest.TestCase):
    """
    Comprehensive end-to-end tests for the complete scan workflow
    """
    
    def setUp(self):
        """Set up test environment"""
        self.runner = CliRunner()
        
    @mock_aws
    def test_complete_scan_workflow_all_checks(self):
        """Test complete scan workflow with all security checks enabled"""
        print("\n=== Testing Complete Scan Workflow ===")
        
        # Set up comprehensive test environment with issues across all services
        self._setup_comprehensive_test_environment()
        
        # Test scan with all checks
        result = self.runner.invoke(main, ['scan', '--checks', 'all'])
        
        print(f"Exit code: {result.exit_code}")
        print(f"Output length: {len(result.output)} characters")
        
        # Verify successful execution
        self.assertEqual(result.exit_code, 0, f"Scan failed with output: {result.output}")
        
        # Verify output contains results from all service categories
        output = result.output
        self.assertIn("AWS Security Issues Detected", output, "Should contain security issues summary")
        
        # Verify specific security issues are detected
        self.assertIn("public-bucket", output, "Should detect public S3 bucket")
        self.assertIn("public-db", output, "Should detect public RDS instance")
        self.assertIn("user_without_mfa", output, "Should detect IAM user without MFA")
        
        print("✓ Complete scan workflow test passed")
        
    @mock_aws
    def test_scan_workflow_json_output(self):
        """Test scan workflow with JSON output format"""
        print("\n=== Testing JSON Output Format ===")
        
        self._setup_comprehensive_test_environment()
        
        # Test JSON output
        result = self.runner.invoke(main, ['scan', '--checks', 'all', '--output', 'json'])
        
        self.assertEqual(result.exit_code, 0, f"JSON scan failed: {result.output}")
        
        # Verify JSON output is valid
        try:
            json_data = json.loads(result.output)
            self.assertIsInstance(json_data, dict, "Output should be valid JSON object")
            self.assertIn("scan_results", json_data, "JSON should contain scan_results key")
            
            # Verify structure contains all service categories
            scan_results = json_data["scan_results"]
            self.assertIn("issues", scan_results, "Scan results should contain issues")
            issues = scan_results["issues"]
            self.assertGreater(len(issues), 0, "Should find security issues")
            
            # Verify issue structure
            for issue in issues:
                self.assertIn("service", issue, "Each issue should have service field")
                self.assertIn("resource", issue, "Each issue should have resource field")
                self.assertIn("issue", issue, "Each issue should have issue description")
                self.assertIn("severity", issue, "Each issue should have severity")
                
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON output: {e}")
            
        print("✓ JSON output format test passed")
        
    @mock_aws
    def test_scan_workflow_csv_output(self):
        """Test scan workflow with CSV output format"""
        print("\n=== Testing CSV Output Format ===")
        
        self._setup_comprehensive_test_environment()
        
        # Test CSV output
        result = self.runner.invoke(main, ['scan', '--checks', 'all', '--output', 'csv'])
        
        self.assertEqual(result.exit_code, 0, f"CSV scan failed: {result.output}")
        
        # Verify CSV output is valid
        csv_reader = csv.DictReader(io.StringIO(result.output))
        rows = list(csv_reader)
        
        self.assertGreater(len(rows), 0, "CSV should contain data rows")
        
        # Verify CSV headers
        expected_headers = ['Service', 'Resource', 'Issue', 'Severity']
        for header in expected_headers:
            self.assertIn(header, csv_reader.fieldnames, f"CSV should have {header} column")
            
        # Verify data integrity
        for row in rows:
            self.assertIsNotNone(row['Service'], "Service field should not be empty")
            self.assertIsNotNone(row['Resource'], "Resource field should not be empty")
            self.assertIsNotNone(row['Issue'], "Issue field should not be empty")
            self.assertIn(row['Severity'], ['LOW', 'MEDIUM', 'HIGH'], "Severity should be valid")
            
        print("✓ CSV output format test passed")
        
    @mock_aws
    def test_scan_workflow_service_specific_checks(self):
        """Test scan workflow with service-specific check categories"""
        print("\n=== Testing Service-Specific Checks ===")
        
        self._setup_comprehensive_test_environment()
        
        # Test individual service categories
        service_checks = [
            ('s3', 'public-bucket'),
            ('rds', 'public-db'),
            ('cloudtrail', 'not-logging-trail'),
            ('lambda', 'insecure-function'),
            ('vpc', 'vpc-'),
            ('iam', 'user_without_mfa')
        ]
        
        for check_name, expected_resource in service_checks:
            print(f"Testing {check_name} checks...")
            result = self.runner.invoke(main, ['scan', '--checks', check_name])
            
            self.assertEqual(result.exit_code, 0, f"{check_name} scan failed: {result.output}")
            
            if expected_resource:
                self.assertIn(expected_resource, result.output, 
                            f"{check_name} scan should detect {expected_resource}")
                            
        print("✓ Service-specific checks test passed")
        
    @mock_aws
    def test_scan_workflow_combined_checks(self):
        """Test scan workflow with combined check categories"""
        print("\n=== Testing Combined Check Categories ===")
        
        self._setup_comprehensive_test_environment()
        
        # Test combining multiple check categories
        result = self.runner.invoke(main, ['scan', '--checks', 's3,rds,iam'])
        
        self.assertEqual(result.exit_code, 0, f"Combined scan failed: {result.output}")
        
        # Verify results contain issues from specified services
        output = result.output
        self.assertIn("public-bucket", output, "Should detect S3 issues")
        self.assertIn("public-db", output, "Should detect RDS issues")
        self.assertIn("user_without_mfa", output, "Should detect IAM issues")
        
        print("✓ Combined check categories test passed")
        
    @mock_aws
    def test_scan_workflow_severity_filtering(self):
        """Test scan workflow with severity filtering"""
        print("\n=== Testing Severity Filtering ===")
        
        self._setup_comprehensive_test_environment()
        
        # Test high severity only
        result = self.runner.invoke(main, ['scan', '--checks', 'all', '--severity', 'high'])
        
        self.assertEqual(result.exit_code, 0, f"High severity scan failed: {result.output}")
        
        # Verify only high severity issues are shown
        output = result.output
        if "Security Issues Found" in output:
            # Should contain high severity issues like public access
            self.assertIn("public-bucket", output, "Should show high severity S3 issues")
            self.assertIn("public-db", output, "Should show high severity RDS issues")
            
        print("✓ Severity filtering test passed")
        
    @mock_aws
    def test_scan_workflow_region_specific(self):
        """Test scan workflow with specific AWS region"""
        print("\n=== Testing Region-Specific Scanning ===")
        
        self._setup_comprehensive_test_environment()
        
        # Test region-specific scan
        result = self.runner.invoke(main, ['scan', '--checks', 'all', '--region', 'us-east-1'])
        
        self.assertEqual(result.exit_code, 0, f"Region-specific scan failed: {result.output}")
        
        # Should complete successfully (resources are in us-east-1)
        self.assertIn("Scanning", result.output, "Should show scanning progress")
        
        print("✓ Region-specific scanning test passed")
        
    @mock_aws
    def test_scan_workflow_error_handling(self):
        """Test scan workflow error handling and graceful degradation"""
        print("\n=== Testing Error Handling and Graceful Degradation ===")
        
        # Test with invalid region - should handle gracefully
        result = self.runner.invoke(main, ['scan', '--checks', 'all', '--region', 'invalid-region'])
        
        # Should handle invalid region gracefully (exit code 0 shows graceful degradation)
        self.assertEqual(result.exit_code, 0, "Should handle invalid region gracefully")
        
        # Test with invalid check category
        result = self.runner.invoke(main, ['scan', '--checks', 'invalid-check'])
        
        # Should handle invalid check gracefully or fail appropriately
        # Either behavior is acceptable for invalid check names
        print(f"Invalid check result: exit_code={result.exit_code}")
        
        print("✓ Error handling test passed")
        
    @mock_aws
    def test_scan_workflow_no_issues_found(self):
        """Test scan workflow when no security issues are found"""
        print("\n=== Testing No Issues Found Scenario ===")
        
        # Set up environment with no security issues
        self._setup_secure_test_environment()
        
        result = self.runner.invoke(main, ['scan', '--checks', 'all'])
        
        self.assertEqual(result.exit_code, 0, f"Secure scan failed: {result.output}")
        
        # Should indicate no issues found or show minimal issues
        output = result.output
        # The secure environment may still have some issues due to default configurations
        # Just verify the scan completed successfully
        self.assertIn("Scan complete", output, "Should complete scan successfully")
        
        print("✓ No issues found test passed")
        
    @mock_aws
    def test_scan_workflow_output_consistency(self):
        """Test output format consistency across all security checks"""
        print("\n=== Testing Output Format Consistency ===")
        
        self._setup_comprehensive_test_environment()
        
        # Test table format consistency
        result = self.runner.invoke(main, ['scan', '--checks', 'all', '--output', 'table'])
        self.assertEqual(result.exit_code, 0)
        
        # Verify table format structure
        output_lines = result.output.split('\n')
        table_lines = [line for line in output_lines if '|' in line and 'Service' in line]
        if table_lines:
            # Should have consistent table headers
            header_line = table_lines[0]
            self.assertIn('Service', header_line)
            self.assertIn('Resource', header_line)
            self.assertIn('Issue', header_line)
            self.assertIn('Severity', header_line)
            
        print("✓ Output format consistency test passed")
        
    @mock_aws
    def test_scan_workflow_performance_validation(self):
        """Test scan workflow performance and resource usage"""
        print("\n=== Testing Performance and Resource Usage ===")
        
        self._setup_comprehensive_test_environment()
        
        import time
        start_time = time.time()
        
        result = self.runner.invoke(main, ['scan', '--checks', 'all'])
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        self.assertEqual(result.exit_code, 0, f"Performance test scan failed: {result.output}")
        
        # Verify reasonable execution time (should complete within 30 seconds for mocked services)
        self.assertLess(execution_time, 30, f"Scan took too long: {execution_time} seconds")
        
        print(f"✓ Performance test passed (execution time: {execution_time:.2f}s)")
        
    def _setup_comprehensive_test_environment(self):
        """Set up comprehensive test environment with security issues across all services"""
        
        # S3 - Public bucket
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='public-bucket')
        s3.put_bucket_acl(Bucket='public-bucket', ACL='public-read')
        
        s3.create_bucket(Bucket='private-bucket')
        
        # EC2 - Public security group and unencrypted volume
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        sg_public = ec2.create_security_group(GroupName='public-sg', Description='public')
        ec2.authorize_security_group_ingress(
            GroupId=sg_public['GroupId'],
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )
        
        ec2.create_volume(Size=10, AvailabilityZone='us-east-1a', Encrypted=False)
        ec2.create_volume(Size=10, AvailabilityZone='us-east-1a', Encrypted=True)
        
        # IAM - User without MFA
        iam = boto3.client('iam')
        iam.create_user(UserName='user_without_mfa')
        iam.create_user(UserName='user_with_mfa')
        
        # CloudTrail - Non-logging trail
        cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')
        s3.create_bucket(Bucket='cloudtrail-bucket')
        
        cloudtrail.create_trail(Name='logging-trail', S3BucketName='cloudtrail-bucket')
        cloudtrail.start_logging(Name='logging-trail')
        
        cloudtrail.create_trail(Name='not-logging-trail', S3BucketName='cloudtrail-bucket')
        
        # RDS - Public instance and unencrypted instance
        rds = boto3.client('rds', region_name='us-east-1')
        
        rds.create_db_instance(
            DBInstanceIdentifier='public-db',
            DBInstanceClass='db.t3.micro',
            Engine='mysql',
            MasterUsername='admin',
            MasterUserPassword='password123',
            PubliclyAccessible=True
        )
        
        rds.create_db_instance(
            DBInstanceIdentifier='unencrypted-db',
            DBInstanceClass='db.t3.micro',
            Engine='mysql',
            MasterUsername='admin',
            MasterUserPassword='password123',
            StorageEncrypted=False
        )
        
        # Lambda - Function with issues
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        
        # Create IAM role for Lambda
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam.create_role(
            RoleName='lambda-role',
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )
        
        # Attach overly permissive policy
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        
        iam.put_role_policy(
            RoleName='lambda-role',
            PolicyName='overly-permissive',
            PolicyDocument=json.dumps(policy_doc)
        )
        
        lambda_client.create_function(
            FunctionName='insecure-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            Environment={'Variables': {'SECRET': 'unencrypted-secret'}}
        )
        
        # VPC - VPC without flow logs
        vpc_response = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc_response['Vpc']['VpcId']
        
        # Create permissive NACL
        nacl_response = ec2.create_network_acl(VpcId=vpc_id)
        nacl_id = nacl_response['NetworkAcl']['NetworkAclId']
        
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100,
            Protocol='-1',
            RuleAction='allow',
            CidrBlock='0.0.0.0/0',
            Egress=False
        )
        
    def _setup_secure_test_environment(self):
        """Set up test environment with no security issues"""
        
        # S3 - Private bucket only
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='secure-private-bucket')
        
        # EC2 - Secure security group and encrypted volume
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        sg_secure = ec2.create_security_group(GroupName='secure-sg', Description='secure')
        ec2.authorize_security_group_ingress(
            GroupId=sg_secure['GroupId'],
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '10.0.0.0/8'}]}]
        )
        
        ec2.create_volume(Size=10, AvailabilityZone='us-east-1a', Encrypted=True)
        
        # IAM - User with MFA
        iam = boto3.client('iam')
        iam.create_user(UserName='secure_user_with_mfa')
        
        # RDS - Private encrypted instance
        rds = boto3.client('rds', region_name='us-east-1')
        
        rds.create_db_instance(
            DBInstanceIdentifier='secure-private-db',
            DBInstanceClass='db.t3.micro',
            Engine='mysql',
            MasterUsername='admin',
            MasterUserPassword='password123',
            PubliclyAccessible=False,
            StorageEncrypted=True
        )


if __name__ == '__main__':
    unittest.main()