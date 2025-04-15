# AWS Sentinel

AWS Sentinel is a command-line security scanner for AWS resources. It helps identify common security issues in your AWS account, such as:

- Public S3 buckets
- Security groups with port 22 (SSH) open to the public
- Unencrypted EBS volumes
- IAM users without Multi-Factor Authentication (MFA)

## Usage

You can clone this repo:

``` bash
git clone https://github.com/rishabkumar7/aws-sentinel
```

Once clone, you can run AWS Sentinel from the command line:

``` bash
python main.py --profile your-aws-profile --region your-aws-region
```

If you don't specify a profile or region, it will use the default profile and `us-east-1` region.

### Options

- `--profile`: AWS profile to use (default: "default")
- `--region`: AWS region to check (default: "us-east-1")

## Example Output

``` bash
 █████╗ ██╗    ██╗███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔══██╗██║    ██║██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████║██║ █╗ ██║███████╗    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██╔══██║██║███╗██║╚════██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
██║  ██║╚███╔███╔╝███████║    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                                        
                      AWS Security Sentinel

Scanning AWS account using profile: default in region: us-east-1
Initializing security checks...
+-------------------------+
| AWS Security Issues Detected |
+--------+---------------+------------------------------------------+
| Service| Resource      | Issue                                    |
+--------+---------------+------------------------------------------+
| S3     | mybucket      | Public bucket                            |
| EC2    | sg-12345abcde | Security group with port 22 open to public |
| EBS    | vol-67890fghij| Unencrypted volume                       |
| IAM    | alice         | User without MFA                         |
+--------+---------------+------------------------------------------+
```

## Requirements

- Python 3.9+
- AWS credentials configured (via AWS CLI or environment variables)

## Development

To set up AWS Sentinel for development:

1. Clone the repository:

``` bash
git clone https://github.com/yourusername/aws-sentinel.git cd aws-sentinel
```

2. Create a virtual environment:

``` bash
python -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate`
```

3. Install development dependencies:

``` bash
pip install -r requirements.txt
```

4. Run tests:

``` bash
python unittest test_aws_sentinel.py
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
