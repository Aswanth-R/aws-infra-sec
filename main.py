import boto3
import click
from prettytable import PrettyTable

ASCII_ART = """
 █████╗ ██╗    ██╗███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔══██╗██║    ██║██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████║██║ █╗ ██║███████╗    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██╔══██║██║███╗██║╚════██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
██║  ██║╚███╔███╔╝███████║    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                                        
                       AWS Security Sentinel
"""

def check_public_buckets(s3_client):
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
    unencrypted_volumes = []
    volumes = ec2_client.describe_volumes()['Volumes']
    for volume in volumes:
        if not volume['Encrypted']:
            unencrypted_volumes.append(volume['VolumeId'])
    return unencrypted_volumes

def check_iam_users_without_mfa(iam_client):
    users_without_mfa = []
    users = iam_client.list_users()['Users']
    for user in users:
        mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            users_without_mfa.append(user['UserName'])
    return users_without_mfa

def create_pretty_table(title, headers, rows):
    table = PrettyTable()
    table.title = title
    table.field_names = headers
    for row in rows:
        table.add_row(row)
    table.align = 'l'  # Left-align text
    return table

@click.command()
@click.option('--profile', default='default', help='AWS profile to use')
@click.option('--region', default='us-east-1', help='AWS region to check')
def main(profile, region):
    print(ASCII_ART)
    click.echo(f"Scanning AWS account using profile: {profile} in region: {region}")
    click.echo("Initializing security checks...\n")

    session = boto3.Session(profile_name=profile, region_name=region)
    s3_client = session.client('s3')
    ec2_client = session.client('ec2')
    iam_client = session.client('iam')

    results = []

    public_buckets = check_public_buckets(s3_client)
    for bucket in public_buckets:
        results.append(["S3", bucket, "Public bucket"])

    public_sgs = check_public_security_groups(ec2_client)
    for sg in public_sgs:
        results.append(["EC2", sg, "Security group with port 22 open to public"])

    unencrypted_volumes = check_unencrypted_ebs_volumes(ec2_client)
    for volume in unencrypted_volumes:
        results.append(["EBS", volume, "Unencrypted volume"])

    users_without_mfa = check_iam_users_without_mfa(iam_client)
    for user in users_without_mfa:
        results.append(["IAM", user, "User without MFA"])

    if results:
        table = create_pretty_table(
            "AWS Security Issues Detected",
            ["Service", "Resource", "Issue"],
            results
        )
        print(table)
    else:
        click.echo("No security issues found. Your AWS environment looks secure!")

if __name__ == '__main__':
    main()