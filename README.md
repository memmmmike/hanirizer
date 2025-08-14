# Hanirizer - Network Configuration Sanitizer

A robust Python tool for sanitizing sensitive information in network device configuration files while preserving functionality and readability.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)

## Features

- **Multi-vendor support**: Cisco IOS/IOS-XE, Palo Alto Networks, Juniper, Arista, and more
- **Intelligent sanitization**: Preserves service accounts while replacing personal credentials
- **Universal archive support**: Process ZIP, 7Z, RAR, TAR, TAR.GZ, TAR.BZ2, TAR.XZ, and more
- **Password-protected archives**: Automatic handling of encrypted archives with password prompts
- **Configurable patterns**: Define custom regex patterns for your environment
- **Safe operation**: Automatic backups before modification
- **Dry-run mode**: Preview changes without modifying files
- **Extensible**: Easy to add new device types and secret patterns
- **CLI and library usage**: Use as a command-line tool or Python library
- **Comprehensive logging**: Detailed audit trail of all changes
- **Parallel processing**: Multi-threaded execution for large deployments

## Quick Start

### System Requirements

**Python**: 3.8 or higher

**Optional dependencies for archive support**:
- **7-Zip archives (.7z)**: 
  - Linux/Ubuntu: `sudo apt-get install p7zip-full`
  - macOS: `brew install p7zip`
  - Windows: `choco install 7zip` or download from [7-zip.org](https://www.7-zip.org/)
- **RAR archives (.rar)**:
  - Linux/Ubuntu: `sudo apt-get install unrar`
  - macOS: `brew install --cask rar`
  - Windows: `choco install unrar` or download WinRAR

Note: ZIP and TAR archives work out of the box with Python's standard library.

### Installation

```bash
# Install from PyPI (when published)
pip install hanirizer

# Or install from source
git clone https://github.com/memmmmike/hanirizer.git
cd hanirizer
pip install -e .
```

### Basic Usage

```bash
# Sanitize a single file
netsan sanitize router-config.txt

# Sanitize directory with dry-run
netsan sanitize --dry-run /path/to/configs/

# Sanitize any archive format (ZIP, 7Z, RAR, TAR.GZ, etc.)
netsan sanitize-archive configs.zip
netsan sanitize-archive configs.7z
netsan sanitize-archive configs.tar.gz

# Handle password-protected archives
netsan sanitize-archive encrypted.zip --password mypassword
netsan sanitize-archive encrypted.7z  # Will prompt for password

# Create encrypted output archive
netsan sanitize-archive configs.zip --output-format 7z --output-password newsecret

# Sanitize ZIP with custom output directory
netsan sanitize-archive configs.zip --output /path/to/output

# Sanitize and create different archive format
netsan sanitize-archive configs.rar --output-format tar.gz

# Use custom configuration
netsan sanitize --config my-config.json /path/to/configs/

# Restore from backup
netsan restore /path/to/configs/
```

## Configuration

Create a `config.json` file to customize the sanitization:

```json
{
  "service_accounts": [
    "admin",
    "monitoring",
    "backup"
  ],
  "personal_accounts": [
    "john.doe",
    "jane.smith"
  ],
  "patterns": {
    "custom_secret": {
      "pattern": "my-secret-pattern (\\S+)",
      "replacement": "REDACTED_SECRET"
    }
  },
  "backup": {
    "enabled": true,
    "directory": ".backups",
    "retention_days": 30
  }
}
```

## Supported Secret Types

The sanitizer automatically detects and replaces:

- Enable passwords and secrets
- User credentials (passwords, secrets, hashes)
- TACACS+/RADIUS keys
- SNMP community strings
- Routing protocol passwords (OSPF, EIGRP, BGP)
- VPN pre-shared keys
- SSH keys and certificates
- API tokens and keys
- Database connection strings
- And many more...

## Archive File Processing

The sanitizer provides comprehensive support for all major archive formats:

### Supported Archive Formats
- **ZIP** - Standard ZIP files with optional password protection
- **7Z** - 7-Zip archives with strong encryption support
- **RAR** - RAR archives (requires unrar)
- **TAR** - Uncompressed tar archives
- **TAR.GZ/TGZ** - Gzip compressed tar archives
- **TAR.BZ2/TBZ2** - Bzip2 compressed tar archives
- **TAR.XZ/TXZ** - XZ compressed tar archives
- **GZ** - Single file gzip compression
- **BZ2** - Single file bzip2 compression
- **XZ** - Single file XZ compression

### Password Protection
The tool handles password-protected archives seamlessly:
- Provide password via `--password` flag
- Interactive password prompt for encrypted archives
- Create password-protected output with `--output-password`
- Supports encryption for ZIP and 7Z output formats

### Archive Processing Examples

```bash
# Process password-protected RAR archive
netsan sanitize-archive secure_configs.rar --password "SecretPass123"

# Convert between archive formats
netsan sanitize-archive configs.tar.gz --output-format 7z

# Create encrypted output
netsan sanitize-archive configs.zip --output-format 7z --output-password "NewSecret"

# Process nested archives
netsan sanitize-archive backup.tar.gz  # Automatically handles configs inside

# Batch process with custom config
netsan sanitize-archive *.7z --config company-config.json
```

### System Requirements for Archive Support
- **7Z archives**: Install `p7zip-full` package
- **RAR archives**: Install `unrar` package
- **Python packages**: `pyminizip` for encrypted ZIP creation

## ZIP File Processing

The sanitizer provides comprehensive ZIP file support with two processing modes:

### In-Memory Processing (Default)
Processes files directly within the ZIP without extracting to disk:
- **Faster**: No disk I/O overhead
- **Secure**: No temporary files on disk
- **Efficient**: Lower memory footprint

### Extraction-Based Processing
Traditional extract-process-recompress workflow:
- **Compatible**: Works with backup/restore features
- **Debuggable**: Can inspect intermediate files

### ZIP Processing Examples

```bash
# Process ZIP to folder (default)
netsan sanitize-zip network_configs.zip

# Process ZIP to new ZIP file
netsan sanitize-zip network_configs.zip --output-format zip

# Use extraction method instead of in-memory
netsan sanitize-zip network_configs.zip --extract

# Specify custom output location
netsan sanitize-zip configs.zip --output /sanitized/configs/

# Use custom configuration with ZIP
netsan sanitize-zip configs.zip --config impulse-config.json
```

### Important Notes

- When processing already-sanitized files, the tool intelligently avoids double-sanitization
- All files are preserved - those without secrets are copied unchanged
- Output folder naming: `original_name_sanitized/` (avoids duplicate suffixes)
- Supports nested directory structures within ZIP files

## Advanced Usage

### Python Library

```python
from netsan import NetworkSanitizer, Config

# Load configuration
config = Config.from_file('config.json')

# Create sanitizer
sanitizer = NetworkSanitizer(config)

# Sanitize a file
result = sanitizer.sanitize_file('router-config.txt')
print(f"Modified: {result.modified}")
print(f"Changes: {result.changes}")

# Sanitize content directly
clean_content = sanitizer.sanitize_content(config_text)

# Process ZIP files
zip_results = sanitizer.sanitize_zip_file(
    'configs.zip',
    output_format='folder'  # or 'zip'
)
print(f"Processed: {zip_results['processed_files']} files")
print(f"Sanitized: {zip_results['sanitized_files']} files")
```

### Custom Patterns

Define custom patterns in your configuration:

```json
{
  "patterns": {
    "api_key": {
      "pattern": "api[_-]key[\\s=:]+([\\w\\-]+)",
      "replacement": "API_KEY_REDACTED",
      "flags": ["IGNORECASE"]
    },
    "internal_ip": {
      "pattern": "10\\.0\\.0\\.\\d+",
      "replacement": "10.0.0.XXX"
    }
  }
}
```

### Vendor-Specific Configurations

Use pre-built vendor configurations:

```bash
# Cisco IOS/IOS-XE
netsan sanitize --vendor cisco configs/

# Palo Alto Networks
netsan sanitize --vendor paloalto configs/

# Juniper
netsan sanitize --vendor juniper configs/
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/network-config-sanitizer.git
cd network-config-sanitizer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=netsan --cov-report=html

# Run linters
flake8 src/
black src/ tests/
mypy src/
```

### Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) first.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## CI/CD Integration

The tool is tested on multiple platforms and can be integrated into CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Install system dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y p7zip-full unrar  # For 7z and RAR support
    
- name: Sanitize configs
  run: |
    pip install network-config-sanitizer
    netsan sanitize --dry-run ./configs/
```

The tool works on:
- ✅ Linux (Ubuntu, Debian, CentOS, RHEL)
- ✅ macOS 
- ✅ Windows
- ✅ Docker containers
- ✅ GitHub Actions, GitLab CI, Jenkins

## Security Considerations

- Always review sanitized files before sharing
- Use strong replacement values in production
- Store configuration files securely
- Regularly update patterns for new secret formats
- Consider additional encryption for backup files

## Command-Line Reference

```bash
netsan sanitize [OPTIONS] PATH

Options:
  --config PATH           Configuration file path
  --vendor NAME          Use vendor-specific config (cisco|paloalto|juniper|arista)
  --output PATH          Output directory (default: in-place)
  --dry-run             Preview changes without modifying files
  --backup              Create backups before modifying
  --no-backup           Skip backup creation
  --recursive           Process directories recursively
  --pattern GLOB        File pattern to match (default: *.txt,*.conf,*.config)
  --verbose             Verbose output
  --quiet               Suppress non-error output
  --format FORMAT       Output format (text|json|csv)
  --stats               Show statistics after processing
  --parallel N          Number of parallel workers
  --help                Show this message and exit

netsan restore [OPTIONS] PATH

Options:
  --backup-dir PATH     Backup directory path
  --date DATE          Restore from specific date
  --list               List available backups
  --help               Show this message and exit

netsan validate [OPTIONS] CONFIG

Options:
  --help               Show this message and exit
```

## Examples

### Example 1: Basic Sanitization

```bash
# Sanitize all .conf files in a directory
netsan sanitize --pattern "*.conf" /etc/network/

# Output:
# ✓ Processed: router1.conf (12 secrets sanitized)
# ✓ Processed: switch1.conf (8 secrets sanitized)
# ✓ Processed: firewall1.conf (15 secrets sanitized)
# 
# Summary: 3 files processed, 35 total secrets sanitized
```

### Example 2: Using Custom Configuration

```bash
# Create custom config
cat > myconfig.json << EOF
{
  "service_accounts": ["svc_monitor", "svc_backup"],
  "personal_accounts": ["admin_john", "admin_jane"],
  "backup": {
    "enabled": true,
    "compression": true
  }
}
EOF

# Run with custom config
netsan sanitize --config myconfig.json --stats configs/
```

### Example 3: Dry Run with JSON Output

```bash
netsan sanitize --dry-run --format json configs/ > changes.json
```

## Troubleshooting

### Common Issues

**Issue**: Some secrets are not being detected
**Solution**: Add custom patterns to your configuration file

**Issue**: Service accounts are being replaced
**Solution**: Add them to the `service_accounts` list in configuration

**Issue**: Backup files consuming too much space
**Solution**: Enable compression and set retention policy

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the need for secure configuration sharing in network automation
- Thanks to all contributors and the open-source community
- Special thanks to the network engineering community for feedback

## Support

- **Documentation**: [Full documentation](https://network-config-sanitizer.readthedocs.io)
- **Issues**: [GitHub Issues](https://github.com/yourusername/network-config-sanitizer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/network-config-sanitizer/discussions)
- **Email**: support@example.com

## Roadmap

- [ ] GUI interface
- [ ] Cloud provider integration (AWS, Azure, GCP)
- [ ] Automated secret rotation
- [ ] Integration with vault systems
- [ ] AI-powered pattern detection
- [ ] Configuration compliance checking

---

Made with ❤️ by the network automation community