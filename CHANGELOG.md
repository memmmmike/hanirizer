# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-08-13

### Added
- **Universal Archive Support**: Complete support for multiple archive formats
  - ZIP, 7Z, RAR archives with password protection
  - TAR archives with various compressions (GZ, BZ2, XZ)
  - Single file compressed formats (GZ, BZ2, XZ)
- **Password-Protected Archive Handling**:
  - Automatic password prompts for encrypted archives
  - Command-line password input with `--password` flag
  - Create encrypted output archives with `--output-password`
- **Archive Format Conversion**: Convert between different archive formats during sanitization
- **New `sanitize-archive` CLI Command**: Universal command for all archive types
- **Enhanced Error Handling**: Better error messages for unsupported formats and wrong passwords

### Changed
- Archive handler now auto-detects format by both extension and magic bytes
- Improved temporary file management for archive extraction

## [1.1.0] - 2025-08-13

### Added
- **ZIP File Support**: Complete support for processing ZIP archives of configuration files
  - In-memory processing mode (default) - processes files without extracting to disk
  - Extraction-based processing mode - traditional extract-process workflow
  - New `sanitize-zip` CLI command for dedicated ZIP processing
  - Output format option: extract to folder (default) or create new ZIP
- **Intelligent Re-sanitization Prevention**: Detects already-sanitized content to avoid double-sanitization
- **Enhanced CLI Options**:
  - `--output-format` flag to choose between folder or ZIP output
  - `--in-memory/--extract` flag to select processing mode
- **Improved File Detection**: Better configuration file type detection for ZIP processing

### Fixed
- Fixed multiple `_SANITIZED` suffix issue when processing already-sanitized files
- Fixed naming convention to avoid `_sanitized_sanitized` in output paths
- Fixed MKA pre-shared key sanitization to prevent duplicate suffixes
- Fixed personal username replacement when using custom configuration

### Changed
- Default ZIP processing now extracts to folder instead of creating new ZIP
- Improved sanitization patterns for better accuracy
- Enhanced parallel processing for better performance

## [1.0.0] - 2025-08-12

### Added
- Initial release with core functionality
- Multi-vendor support (Cisco, Palo Alto, Juniper, Arista)
- Service account preservation
- Personal account replacement
- Backup and restore functionality
- Dry-run mode
- Custom pattern support
- Parallel processing
- Comprehensive logging
- CLI and library interfaces