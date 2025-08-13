# Contributing to Network Configuration Sanitizer

Thank you for your interest in contributing to the Network Configuration Sanitizer! We welcome contributions from the community and are grateful for any help you can provide.

## Code of Conduct

Please note that this project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please be respectful and considerate in all interactions.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue on GitHub with:
- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Your environment (OS, Python version, etc.)
- Any relevant configuration files or logs

### Suggesting Enhancements

We welcome suggestions for new features! Please create an issue with:
- A clear description of the feature
- Use cases for the feature
- Any implementation ideas you might have

### Pull Requests

1. **Fork the repository** and create your branch from `main`:
   ```bash
   git checkout -b feature/amazing-feature
   ```

2. **Set up your development environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. **Make your changes**:
   - Follow the existing code style
   - Add/update tests as needed
   - Update documentation if required

4. **Run tests and linters**:
   ```bash
   # Run tests
   pytest tests/
   
   # Check code formatting
   black --check src/ tests/
   
   # Run linter
   flake8 src/ tests/
   
   # Type checking
   mypy src/
   ```

5. **Format your code**:
   ```bash
   black src/ tests/
   isort src/ tests/
   ```

6. **Write a good commit message**:
   - Use the present tense ("Add feature" not "Added feature")
   - Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
   - Limit the first line to 72 characters or less
   - Reference issues and pull requests liberally after the first line

7. **Push to your fork** and submit a pull request

### Adding New Vendor Support

To add support for a new network vendor:

1. Add vendor configuration to `src/config.py`:
   ```python
   VENDORS = {
       'newvendor': {
           'service_accounts': [...],
           'patterns': {...}
       }
   }
   ```

2. Add example configuration in `examples/newvendor-config.yaml`

3. Add tests in `tests/test_vendor_newvendor.py`

4. Update documentation

### Adding New Secret Patterns

To add new secret detection patterns:

1. Add pattern to `src/patterns.py`:
   ```python
   'new_secret': Pattern(
       name='new_secret',
       pattern=r'your-regex-here',
       replacement=r'your-replacement',
       flags=['IGNORECASE'],
       description='Description of the secret'
   )
   ```

2. Add test cases in `tests/test_patterns.py`

3. Document the pattern in the README

## Development Guidelines

### Code Style

- Follow PEP 8
- Use type hints where appropriate
- Maximum line length: 120 characters
- Use descriptive variable names
- Add docstrings to all functions and classes

### Testing

- Write tests for all new functionality
- Maintain test coverage above 90%
- Use pytest fixtures for common test data
- Mock external dependencies

### Documentation

- Update the README for user-facing changes
- Add docstrings following Google style
- Update example configurations
- Include inline comments for complex logic

## Release Process

1. Update version in `src/__init__.py`
2. Update CHANGELOG.md
3. Create a pull request with version bump
4. After merge, create a GitHub release
5. Package will be automatically published to PyPI

## Getting Help

If you need help with your contribution:
- Check existing issues and pull requests
- Ask questions in GitHub Discussions
- Reach out to maintainers

## Recognition

Contributors will be recognized in:
- The project README
- Release notes
- The AUTHORS file

Thank you for contributing!