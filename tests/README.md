# Hanirizer Testing Suite

## Running Tests

### Install Test Dependencies

```bash
pip install -e ".[dev]"
```

### Run All Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_patterns.py -v

# Run specific test
pytest tests/test_patterns.py::TestPatternDetection::test_enable_password_detection -v
```

### Test Structure

```
tests/
├── __init__.py
├── test_patterns.py          # Pattern detection and sanitization tests
├── test_archive_handler.py   # Archive extraction and creation tests
└── README.md                  # This file
```

### Test Coverage

Current test coverage includes:

- **Pattern Detection**: Tests for all major secret types (passwords, SNMP, TACACS, RADIUS, etc.)
- **Archive Handling**: ZIP, TAR, 7z creation and extraction
- **Password Protection**: Encrypted archive handling
- **Error Handling**: Unsupported formats, missing tools

### Adding New Tests

1. Create test file in `tests/` directory
2. Name it `test_*.py`
3. Use pytest fixtures and assertions
4. Run tests to verify

Example:

```python
import pytest
from src.sanitizer import NetworkSanitizer

def test_my_feature():
    """Test description."""
    # Setup
    sanitizer = NetworkSanitizer()

    # Execute
    result = sanitizer.some_method()

    # Assert
    assert result == expected_value
```

### CI/CD Integration

Tests are designed to run in CI/CD pipelines:

```yaml
# .github/workflows/test.yml
- name: Run tests
  run: |
    pip install -e ".[dev]"
    pytest --cov=src --cov-report=xml
```

## Test Requirements

- Python ≥3.8
- pytest ≥7.0.0
- pytest-cov ≥4.0.0
- 7z (optional, some tests skip if not available)
- unrar (optional, some tests skip if not available)
