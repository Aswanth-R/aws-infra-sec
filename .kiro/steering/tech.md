# AWS Sentinel Technical Stack

## Language & Runtime
- **Python 3.9+** - Minimum required version
- Modern Python features and type hints encouraged

## Core Dependencies
- **boto3** (>=1.20.0) - AWS SDK for Python
- **click** (>=8.0.0) - Command-line interface framework
- **prettytable** (>=2.0.0) - Table formatting for output
- **colorama** (>=0.4.4) - Cross-platform colored terminal text

## Development Dependencies
- **moto** - AWS service mocking for tests
- **pytest** - Testing framework (though unittest is currently used)

## Build System
- **setuptools** - Package building and distribution
- **pip** - Package installation (primary)
- **uv** - Alternative fast Python package manager (supported)

## Common Commands

### Development Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install in development mode
pip install -e '.[dev]'
```

### Testing
```bash
# Run all tests
python -m unittest discover tests

# Run specific test
python -m unittest tests.test_aws_sentinel.TestAWSSentinel.test_check_public_buckets
```

### Installation
```bash
# Install from PyPI
pip install aws-sentinel

# Install with uv
uv pip install aws-sentinel
```

### CLI Usage
```bash
# Basic scan
aws-sentinel scan

# Scan with specific profile/region
aws-sentinel scan --profile production --region us-west-2

# Export results
aws-sentinel scan --output json > report.json
```

## Architecture Patterns
- **Modular design**: Core logic separated from CLI interface
- **Client injection**: AWS clients passed to functions for testability
- **Error handling**: Graceful handling of AWS API errors
- **Mocking**: Use moto for AWS service testing