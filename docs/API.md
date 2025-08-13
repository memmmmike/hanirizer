# API Documentation

## NetworkSanitizer Class

The main class for sanitizing network configuration files.

### Constructor

```python
NetworkSanitizer(config: Config)
```

Creates a new NetworkSanitizer instance with the specified configuration.

### Methods

#### sanitize_file(filepath: str) -> SanitizationResult

Sanitizes a single configuration file.

**Parameters:**
- `filepath` (str): Path to the file to sanitize

**Returns:**
- `SanitizationResult`: Object containing sanitization results

#### sanitize_directory(directory: str) -> List[SanitizationResult]

Sanitizes all matching files in a directory.

**Parameters:**
- `directory` (str): Path to directory to process

**Returns:**
- `List[SanitizationResult]`: List of results for each file

#### sanitize_zip_file(zip_path: str, output_dir: Optional[str] = None, in_memory: bool = True, output_format: str = 'folder') -> Dict[str, Any]

Sanitizes configuration files within a ZIP archive.

**Parameters:**
- `zip_path` (str): Path to ZIP file
- `output_dir` (str, optional): Output directory (default: same as input)
- `in_memory` (bool): If True, process entirely in memory without disk extraction
- `output_format` (str): 'folder' to extract to folder, 'zip' to create ZIP

**Returns:**
- `Dict[str, Any]`: Dictionary with processing results including:
  - `processed_files`: Number of files processed
  - `sanitized_files`: Number of files sanitized
  - `output_dir` or `output_zip`: Path to output
  - `errors`: List of any errors encountered

#### sanitize_content(content: str, filename: str = "unknown") -> str

Sanitizes configuration content directly and returns sanitized version.

**Parameters:**
- `content` (str): Configuration content to sanitize
- `filename` (str): Filename for context (optional)

**Returns:**
- `str`: Sanitized content

## Config Class

Configuration class for the sanitizer.

### Constructor

```python
Config(
    service_accounts: Set[str] = set(),
    personal_accounts: Set[str] = set(),
    patterns: Dict[str, Pattern] = dict(),
    backup: BackupConfig = BackupConfig(),
    file_patterns: List[str] = ["*.txt", "*.conf", "*.config", "*.cfg"],
    recursive: bool = True,
    preserve_structure: bool = True,
    verbose: bool = False,
    dry_run: bool = False,
    parallel_workers: int = 4
)
```

### Class Methods

#### from_file(filepath: str) -> Config

Loads configuration from a JSON or YAML file.

**Parameters:**
- `filepath` (str): Path to configuration file

**Returns:**
- `Config`: Configuration object

## ZipHandler Class

Handles ZIP file extraction, processing, and re-compression.

### Methods

#### process_zip_to_folder(zip_path: Path, sanitizer, output_dir: Optional[Path] = None) -> Dict[str, Any]

Process a ZIP file and extract sanitized files to a folder.

**Parameters:**
- `zip_path` (Path): Path to input ZIP file
- `sanitizer`: NetworkSanitizer instance
- `output_dir` (Path, optional): Directory for output

**Returns:**
- `Dict[str, Any]`: Processing results

#### process_zip_in_memory(zip_path: Path, sanitizer, output_dir: Optional[Path] = None) -> Dict[str, Any]

Process a ZIP file entirely in memory without extracting to disk.

**Parameters:**
- `zip_path` (Path): Path to input ZIP file
- `sanitizer`: NetworkSanitizer instance
- `output_dir` (Path, optional): Directory for output

**Returns:**
- `Dict[str, Any]`: Processing results

## CLI Commands

### sanitize

Sanitize network configuration files.

```bash
netsan sanitize [OPTIONS] PATH
```

**Options:**
- `--config, -c`: Configuration file path
- `--vendor, -v`: Use vendor-specific configuration
- `--output, -o`: Output directory
- `--dry-run`: Preview changes without modifying files
- `--backup/--no-backup`: Create backups before modifying
- `--recursive, -r`: Process directories recursively
- `--pattern, -p`: File pattern to match
- `--verbose, -v`: Verbose output
- `--quiet, -q`: Suppress non-error output
- `--stats`: Show statistics after processing
- `--parallel, -j`: Number of parallel workers

### sanitize-zip

Sanitize network configurations within a ZIP file.

```bash
netsan sanitize-zip [OPTIONS] ZIP_FILE
```

**Options:**
- `--output, -o`: Output directory for sanitized files
- `--config, -c`: Configuration file path
- `--vendor, -v`: Use vendor-specific configuration
- `--dry-run`: Preview changes without creating output
- `--verbose, -v`: Verbose output
- `--in-memory/--extract`: Process files in memory (default) or extract to disk first
- `--output-format`: Output as 'folder' (default) or 'zip'

### restore

Restore files from backup.

```bash
netsan restore [OPTIONS] PATH
```

**Options:**
- `--backup-dir`: Backup directory path
- `--date`: Restore from specific date (YYYYMMDD)
- `--list`: List available backups
- `--verbose, -v`: Verbose output