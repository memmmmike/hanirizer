"""Main sanitizer implementation."""

import re
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from .config import Config
from .backup import BackupManager
from .patterns import PatternManager
from .zip_handler import ZipHandler
from .archive_handler import ArchiveHandler

logger = logging.getLogger(__name__)


@dataclass
class SanitizationResult:
    """Result of sanitization operation."""

    filepath: Path
    modified: bool = False
    changes: List[str] = field(default_factory=list)
    error: Optional[str] = None
    backup_path: Optional[Path] = None
    duration: float = 0.0

    @property
    def change_count(self) -> int:
        return len(self.changes)


class NetworkSanitizer:
    """Main network configuration sanitizer."""

    def __init__(self, config: Config):
        """Initialize sanitizer with configuration."""
        self.config = config
        self.pattern_manager = PatternManager(config)
        self.backup_manager = (
            BackupManager(config.backup) if config.backup.enabled else None
        )
        self._personal_user_mapping: Dict[str, str] = {}
        self._stats = {
            "files_processed": 0,
            "files_modified": 0,
            "total_changes": 0,
            "errors": 0,
        }
        self._hash_cache: Dict[str, str] = {}  # Cache for consistent hashes

    def sanitize_file(self, filepath: Union[str, Path]) -> SanitizationResult:
        """Sanitize a single file."""
        start_time = time.time()
        filepath = Path(filepath) if isinstance(filepath, str) else filepath
        result = SanitizationResult(filepath=filepath)

        try:
            # Check if file exists
            if not filepath.exists():
                result.error = f"File not found: {filepath}"
                return result

            # Read file content
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Create backup if enabled
            if self.backup_manager and not self.config.dry_run:
                result.backup_path = self.backup_manager.create_backup(filepath)

            # Sanitize content
            sanitized_content, changes = self._sanitize_content(content, filepath.name)

            # Check if content was modified
            if sanitized_content != content:
                result.modified = True
                result.changes = changes

                # Write sanitized content if not dry-run
                if not self.config.dry_run:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(sanitized_content)

                    if self.config.verbose:
                        logger.info(f"Sanitized {filepath}: {len(changes)} changes")

            result.duration = time.time() - start_time

        except Exception as e:
            result.error = str(e)
            logger.error(f"Error sanitizing {filepath}: {e}")

        return result

    def sanitize_directory(
        self, directory: Union[str, Path]
    ) -> List[SanitizationResult]:
        """Sanitize all matching files in a directory."""
        directory = Path(directory) if isinstance(directory, str) else directory
        results: List[SanitizationResult] = []

        if not directory.exists():
            logger.error(f"Directory not found: {directory}")
            return results

        # Find all matching files
        files = self._find_files(directory)

        if not files:
            logger.warning(f"No matching files found in {directory}")
            return results

        logger.info(f"Found {len(files)} files to process")

        # Process files in parallel if configured
        if self.config.parallel_workers > 1:
            results = self._process_parallel(files)
        else:
            results = self._process_sequential(files)

        # Update statistics
        self._update_stats(results)

        return results

    def sanitize_zip_file(
        self,
        zip_path: str,
        output_dir: Optional[str] = None,
        in_memory: bool = True,
        output_format: str = "folder",
    ) -> Dict[str, Any]:
        """Sanitize configurations within a ZIP file.

        Args:
            zip_path: Path to ZIP file
            output_dir: Output directory (default: same as input)
            in_memory: If True, process entirely in memory without disk extraction
            output_format: 'folder' to extract to folder, 'zip' to create ZIP

        Returns:
            Dictionary with processing results
        """
        zip_path = Path(zip_path)

        if not zip_path.exists():
            raise FileNotFoundError(f"ZIP file not found: {zip_path}")

        output_dir_path = Path(output_dir) if output_dir else None

        with ZipHandler(
            preserve_structure=self.config.preserve_structure,
            create_sanitized_zip=(output_format == "zip"),
        ) as zip_handler:
            if output_format == "folder":
                return zip_handler.process_zip_to_folder(
                    zip_path, self, output_dir_path
                )
            elif in_memory:
                return zip_handler.process_zip_in_memory(
                    zip_path, self, output_dir_path
                )
            else:
                return zip_handler.process_zip_file(zip_path, self, output_dir_path)

    def sanitize_content(self, content: str, filename: str = "unknown") -> str:
        """Sanitize content directly and return sanitized version."""
        sanitized, _ = self._sanitize_content(content, filename)
        return sanitized

    def sanitize_archive_file(
        self,
        archive_path: str,
        output_dir: Optional[str] = None,
        archive_format: str = "folder",
        password: Optional[str] = None,
        output_password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Sanitize configurations within any supported archive format.

        Args:
            archive_path: Path to archive file
            output_dir: Output directory (default: same as input)
            archive_format: Output format ('folder', 'zip', '7z', 'tar.gz')
            password: Password for input archive
            output_password: Password for output archive (if creating encrypted)

        Returns:
            Dictionary with processing results
        """
        archive_path = Path(archive_path)

        if not archive_path.exists():
            raise FileNotFoundError(f"Archive file not found: {archive_path}")

        results = {
            "input_archive": str(archive_path),
            "extracted_files": 0,
            "sanitized_files": 0,
            "output_path": None,
            "errors": [],
        }

        with ArchiveHandler(password=password) as archive_handler:
            try:
                # Extract archive
                extract_dir, extracted_files = archive_handler.extract_archive(
                    archive_path
                )
                results["extracted_files"] = len(extracted_files)

                # Sanitize extracted files
                sanitization_results = self.sanitize_directory(str(extract_dir))
                results["sanitized_files"] = sum(
                    1 for r in sanitization_results if r.modified
                )

                # Collect errors
                for result in sanitization_results:
                    if result.error:
                        results["errors"].append(
                            f"{result.filepath.name}: {result.error}"
                        )

                # Create output
                if output_dir:
                    output_base = Path(output_dir)
                else:
                    output_base = archive_path.parent

                if archive_format == "folder":
                    # Copy sanitized files to output folder
                    base_name = archive_path.stem
                    if base_name.endswith("_sanitized"):
                        base_name = base_name[:-11]
                    output_path = output_base / f"{base_name}_sanitized"

                    if output_path.exists():
                        shutil.rmtree(output_path)
                    shutil.copytree(extract_dir, output_path)
                    results["output_path"] = str(output_path)

                else:
                    # Create archive in specified format
                    base_name = archive_path.stem
                    if base_name.endswith("_sanitized"):
                        base_name = base_name[:-11]

                    if archive_format == "zip":
                        output_path = output_base / f"{base_name}_sanitized.zip"
                    elif archive_format == "7z":
                        output_path = output_base / f"{base_name}_sanitized.7z"
                    elif archive_format == "tar.gz":
                        output_path = output_base / f"{base_name}_sanitized.tar.gz"
                    else:
                        output_path = (
                            output_base / f"{base_name}_sanitized.{archive_format}"
                        )

                    archive_handler.create_archive(
                        extract_dir,
                        output_path,
                        archive_format=archive_format,
                        password=output_password,
                    )
                    results["output_path"] = str(output_path)

                logger.info(
                    f"Archive processing complete: {results['sanitized_files']}/{results['extracted_files']} files sanitized"
                )

            except Exception as e:
                error_msg = f"Failed to process archive {archive_path}: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)

        return results

    def _generate_consistent_hash(self, secret_type: str, value: str = "") -> str:
        """Generate a consistent hash for replacements like the original script."""
        # Create a unique key for this secret type
        cache_key = f"{secret_type}_{value}"

        # Return cached hash if available
        if cache_key in self._hash_cache:
            return self._hash_cache[cache_key]

        # Generate new hash
        import hashlib
        import sys

        base_string = f"{secret_type}_{value}_{len(self._hash_cache)}"
        # Python 3.8 doesn't support usedforsecurity parameter
        if sys.version_info >= (3, 9):
            hash_obj = hashlib.md5(base_string.encode(), usedforsecurity=False)
        else:
            hash_obj = hashlib.md5(base_string.encode())
        # Format like original: 12 character hex string in uppercase
        hash_value = hash_obj.hexdigest()[:12].upper()

        # Cache it
        self._hash_cache[cache_key] = hash_value
        return hash_value

    def _sanitize_content(self, content: str, filename: str) -> Tuple[str, List[str]]:
        """Internal method to sanitize content."""
        changes = []

        # Reset personal user mapping for each file
        self._personal_user_mapping = {}
        personal_user_counter = 1

        # Apply built-in patterns
        content, builtin_changes = self._apply_builtin_patterns(content)
        changes.extend(builtin_changes)

        # Apply custom patterns from configuration
        content, custom_changes = self._apply_custom_patterns(content)
        changes.extend(custom_changes)

        # Replace personal usernames
        for username in self.config.personal_accounts:
            if username in content:
                if username not in self._personal_user_mapping:
                    self._personal_user_mapping[username] = (
                        f"netadmin{personal_user_counter}"
                    )
                    personal_user_counter += 1

                replacement = self._personal_user_mapping[username]
                count = content.count(username)
                content = content.replace(username, replacement)

                if count > 0:
                    changes.append(
                        f"Username {username} -> {replacement} ({count} occurrences)"
                    )

        return content, changes

    def _apply_builtin_patterns(self, content: str) -> Tuple[str, List[str]]:
        """Apply built-in sanitization patterns."""
        changes = []

        # Enable secrets (Type 5, 7, 9)
        pattern = re.compile(
            r"(enable (?:secret|password) )(\d+)( \$?\S+)", re.IGNORECASE
        )
        matches = pattern.findall(content)
        if matches:
            # Generate consistent hash like original
            enable_hash = self._generate_consistent_hash("ENABLE")
            content = pattern.sub(rf"\1\2 $SANITIZED_ENABLE_{enable_hash}", content)
            changes.append(f"Enable secrets: {len(matches)} replaced")

        # Username secrets - Fixed to handle each line separately
        username_lines = []
        for line in content.split("\n"):
            if "username " in line:
                # Parse username line correctly
                username_match = re.match(
                    r"(\s*username )(\S+)( .*)?(secret|password)( )(\d+)( )(\S+)(.*)?",
                    line,
                )
                if username_match:
                    username = username_match.group(2)
                    # Generate consistent hash
                    if username in self.config.service_accounts:
                        secret_hash = self._generate_consistent_hash("SECRET")
                        new_line = f"{username_match.group(1)}{username}{username_match.group(3) or ''}{username_match.group(4)}{username_match.group(5)}{username_match.group(6)} $SANITIZED_SECRET_{secret_hash}"
                    else:
                        # Replace personal username and secret
                        if username in self.config.personal_accounts:
                            if username not in self._personal_user_mapping:
                                self._personal_user_mapping[username] = (
                                    f"netadmin{len(self._personal_user_mapping) + 1}"
                                )
                            username = self._personal_user_mapping[username]
                        secret_hash = self._generate_consistent_hash("SECRET")
                        new_line = f"{username_match.group(1)}{username}{username_match.group(3) or ''}{username_match.group(4)}{username_match.group(5)}{username_match.group(6)} $SANITIZED_SECRET_{secret_hash}"
                    username_lines.append((line, new_line))
                    line = new_line

        # Apply username changes
        for old_line, new_line in username_lines:
            content = content.replace(old_line, new_line)

        if username_lines:
            changes.append(f"User secrets: {len(username_lines)} replaced")

        # TACACS/RADIUS keys - Handle both server blocks and global commands
        for service in ["tacacs", "radius"]:
            key_hash = self._generate_consistent_hash(f"{service.upper()}_KEY")

            # Pattern for server command keys (e.g., "tacacs-server key secret")
            pattern1 = re.compile(rf"({service}-server key )(\S+)", re.IGNORECASE)
            # Pattern for server block keys (e.g., "tacacs server X\n key 7 secret")
            # Must be in a server block context, not generic "key" lines
            pattern2 = re.compile(
                rf"({service} server .+\n\s+key )(\d+)( )(\S+)",
                re.IGNORECASE | re.MULTILINE,
            )

            # Replace global server keys
            matches1 = pattern1.findall(content)
            if matches1:
                content = pattern1.sub(
                    rf"\1SANITIZED_{service.upper()}_{key_hash}", content
                )

            # Replace server block keys
            matches2 = pattern2.findall(content)
            if matches2:
                content = pattern2.sub(
                    rf"\1\2 SANITIZED_{service.upper()}_{key_hash}", content
                )

            total_replaced = len(matches1) + len(matches2)
            if total_replaced > 0:
                changes.append(f"{service.upper()} keys: {total_replaced} replaced")

        # SNMP community strings
        pattern = re.compile(r"(snmp-server community )(\S+)(\s+\S+)?")
        snmp_hash = self._generate_consistent_hash("SNMP")

        def replace_snmp(match):
            community = match.group(2)
            rest = match.group(3) or ""
            if community.lower() not in ["ro", "rw", "read-only", "read-write"]:
                return f"{match.group(1)}SANITIZED_SNMP_{snmp_hash}{rest}"
            return match.group(0)

        matches = pattern.findall(content)
        if matches:
            content = pattern.sub(replace_snmp, content)
            changes.append(f"SNMP communities: {len(matches)} checked")

        # Pre-shared keys - Handle various formats
        psk_hash = self._generate_consistent_hash("PSK")

        # MKA pre-shared keys
        mka_pattern = re.compile(r"(mka pre-shared-key key-chain )(\S+)")
        mka_matches = mka_pattern.findall(content)
        if mka_matches:
            content = mka_pattern.sub(r"\1MAC_KEY_SANITIZED", content)
            changes.append(f"MKA pre-shared keys: {len(mka_matches)} replaced")

        # Crypto ISAKMP keys
        isakmp_pattern = re.compile(r"(crypto isakmp key )(\S+)( .*)")
        isakmp_matches = isakmp_pattern.findall(content)
        if isakmp_matches:
            content = isakmp_pattern.sub(rf"\1SANITIZED_PSK_{psk_hash}\3", content)
            changes.append(f"ISAKMP keys: {len(isakmp_matches)} replaced")

        # Standalone pre-shared-key lines
        psk_pattern = re.compile(r"^(\s*pre-shared-key )(\S+)", re.MULTILINE)
        psk_matches = psk_pattern.findall(content)
        if psk_matches:
            content = psk_pattern.sub(rf"\1SANITIZED_PSK_{psk_hash}", content)
            changes.append(f"Pre-shared keys: {len(psk_matches)} replaced")

        # BGP/OSPF/EIGRP passwords
        routing_patterns = [
            (
                r"(neighbor \S+ password )(\d+)( )(\S+)",
                r"\g<1>7 REDACTED_BGP_PASS",
            ),
            (
                r"(.*message-digest-key \d+ md5 )(\d+)( )(\S+)",
                r"\g<1>7 REDACTED_OSPF_KEY",
            ),
            (
                r"(authentication mode md5.*key-string )(\d+)( )(\S+)",
                r"\g<1>7 REDACTED_AUTH_KEY",
            ),
        ]

        for pattern_str, replacement in routing_patterns:
            pattern = re.compile(pattern_str)
            matches = pattern.findall(content)
            if matches:
                content = pattern.sub(replacement, content)
                protocol = (
                    "BGP"
                    if "neighbor" in pattern_str
                    else "OSPF" if "message-digest" in pattern_str else "AUTH"
                )
                changes.append(f"{protocol} passwords: {len(matches)} replaced")

        return content, changes

    def _apply_custom_patterns(self, content: str) -> Tuple[str, List[str]]:
        """Apply custom patterns from configuration."""
        changes = []

        for pattern_name, pattern_obj in self.config.patterns.items():
            flags = 0
            for flag_name in pattern_obj.flags:
                if hasattr(re, flag_name):
                    flags |= getattr(re, flag_name)

            regex = re.compile(pattern_obj.pattern, flags)
            matches = regex.findall(content)

            if matches:
                content = regex.sub(pattern_obj.replacement, content)
                changes.append(
                    f"Custom pattern '{pattern_name}': {len(matches)} replaced"
                )

        return content, changes

    def _find_files(self, directory: Path) -> List[Path]:
        """Find all files matching configured patterns."""
        files = []

        for pattern in self.config.file_patterns:
            if self.config.recursive:
                files.extend(directory.rglob(pattern))
            else:
                files.extend(directory.glob(pattern))

        # Remove duplicates and sort
        files = sorted(set(files))

        return files

    def _process_sequential(self, files: List[Path]) -> List[SanitizationResult]:
        """Process files sequentially."""
        results = []

        for i, filepath in enumerate(files, 1):
            if self.config.verbose:
                print(f"Processing [{i}/{len(files)}]: {filepath.name}")

            result = self.sanitize_file(filepath)
            results.append(result)

        return results

    def _process_parallel(self, files: List[Path]) -> List[SanitizationResult]:
        """Process files in parallel."""
        results = []

        with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
            future_to_file = {
                executor.submit(self.sanitize_file, filepath): filepath
                for filepath in files
            }

            for i, future in enumerate(as_completed(future_to_file), 1):
                filepath = future_to_file[future]

                try:
                    result = future.result()
                    results.append(result)

                    if self.config.verbose:
                        status = "✓" if result.modified else "○"
                        print(f"[{i}/{len(files)}] {status} {filepath.name}")

                except Exception as e:
                    logger.error(f"Error processing {filepath}: {e}")
                    results.append(SanitizationResult(filepath=filepath, error=str(e)))

        return results

    def _update_stats(self, results: List[SanitizationResult]):
        """Update processing statistics."""
        self._stats["files_processed"] = len(results)
        self._stats["files_modified"] = sum(1 for r in results if r.modified)
        self._stats["total_changes"] = sum(r.change_count for r in results)
        self._stats["errors"] = sum(1 for r in results if r.error)

    def get_stats(self) -> Dict[str, int]:
        """Get processing statistics."""
        return self._stats.copy()

    def print_summary(self, results: List[SanitizationResult]):
        """Print processing summary."""
        print("\n" + "=" * 60)
        print("SANITIZATION SUMMARY")
        print("=" * 60)

        stats = self.get_stats()
        print(f"Files processed: {stats['files_processed']}")
        print(f"Files modified: {stats['files_modified']}")
        print(f"Total changes: {stats['total_changes']}")

        if stats["errors"] > 0:
            print(f"Errors: {stats['errors']}")

        if self.config.dry_run:
            print("\n*** DRY RUN MODE - No files were actually modified ***")

        # Show top changed files
        if results:
            sorted_results = sorted(results, key=lambda r: r.change_count, reverse=True)
            top_changed = sorted_results[:5]

            if any(r.modified for r in top_changed):
                print("\nTop modified files:")
                for result in top_changed:
                    if result.modified:
                        print(
                            f"  - {result.filepath.name}: {result.change_count} changes"
                        )

        print("=" * 60)
