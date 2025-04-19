"""
AWS Sentinel - Security Scanner for AWS Resources

A command-line tool to identify security vulnerabilities and 
misconfigurations in your AWS account.
"""

__version__ = '0.1.0'
__author__ = 'Rishab Kumar'
__email__ = 'rishabkumar7@gmail.com'
__license__ = 'MIT'
__description__ = 'Security scanner for AWS resources'
__url__ = 'https://github.com/rishabkumar7/aws-sentinel'

from .core import (
    check_public_buckets,
    check_public_security_groups,
    check_unencrypted_ebs_volumes,
    check_iam_users_without_mfa
)