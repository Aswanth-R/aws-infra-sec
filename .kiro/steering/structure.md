# AWS Sentinel Project Structure

## Root Directory
```
aws-sentinel/
├── aws_sentinel/          # Main package directory
├── tests/                 # Test suite
├── .kiro/                 # Kiro IDE configuration
├── .git/                  # Git repository
├── .idea/                 # IDE configuration
├── .idx/                  # IDX environment config
├── .venv/                 # Virtual environment
├── README.md              # Project documentation
├── setup.py               # Package configuration
├── requirements.txt       # Dependencies
└── .gitignore            # Git ignore rules
```

## Package Structure (`aws_sentinel/`)
- **`__init__.py`** - Package initialization, version info, and main exports
- **`cli.py`** - Click-based command-line interface and main entry point
- **`core.py`** - Core security check functions (business logic)
- **`utils.py`** - Utility functions for formatting and data processing
- **`ascii_art.py`** - Visual branding and banner display

## Test Structure (`tests/`)
- **`__init__.py`** - Test package initialization
- **`test_aws_sentinel.py`** - Comprehensive test suite using unittest and moto

## Key Architectural Principles

### Separation of Concerns
- **CLI layer** (`cli.py`) handles user interaction and command parsing
- **Core layer** (`core.py`) contains pure business logic for security checks
- **Utils layer** (`utils.py`) provides shared formatting and helper functions

### Function Design Patterns
- Security check functions accept AWS client objects as parameters
- Functions return simple data structures (lists of resource identifiers)
- Error handling is implemented at the function level with graceful degradation

### Entry Points
- Main CLI entry point: `aws_sentinel.cli:main`
- Console script: `aws-sentinel` command
- Package can be imported: `from aws_sentinel import check_public_buckets`

### Testing Strategy
- Use `@mock_aws` decorator from moto for AWS service mocking
- Each security check has dedicated test methods
- Colorful logging with colorama for test output visibility
- Tests create realistic AWS resources and verify detection logic

### Code Organization Rules
- Keep AWS client creation in CLI layer
- Core functions should be stateless and testable
- Utility functions should be reusable across modules
- ASCII art and branding separated into dedicated module