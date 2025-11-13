"""Main sanitizer implementation."""

import re
import logging
import shutil
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime

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

                    # Add timestamp to avoid overwriting existing folders
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = output_base / f"{base_name}_sanitized_{timestamp}"

                    shutil.copytree(extract_dir, output_path)
                    results["output_path"] = str(output_path)

                    # Generate and save security report in output folder
                    security_report = self.generate_security_report(
                        sanitization_results, archive_path.name, output_path
                    )
                    self.save_security_report(
                        security_report, output_path, formats=["json", "txt", "md"]
                    )

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

        base_string = f"{secret_type}_{value}_{len(self._hash_cache)}"
        try:
            # Python 3.9+ supports usedforsecurity parameter
            hash_obj = hashlib.md5(base_string.encode(), usedforsecurity=False)
        except TypeError:
            # Python 3.8 doesn't support usedforsecurity parameter
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
            content = pattern.sub(rf"\1\2 <removed-enable-secret>", content)
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
                    # Replace personal username and secret
                    if username in self.config.service_accounts:
                        new_line = f"{username_match.group(1)}{username}{username_match.group(3) or ''}{username_match.group(4)}{username_match.group(5)}{username_match.group(6)} <removed-user-secret>"
                    else:
                        # Replace personal username and secret
                        if username in self.config.personal_accounts:
                            if username not in self._personal_user_mapping:
                                self._personal_user_mapping[username] = (
                                    f"netadmin{len(self._personal_user_mapping) + 1}"
                                )
                            username = self._personal_user_mapping[username]
                        new_line = f"{username_match.group(1)}{username}{username_match.group(3) or ''}{username_match.group(4)}{username_match.group(5)}{username_match.group(6)} <removed-user-secret>"
                    username_lines.append((line, new_line))
                    line = new_line

        # Apply username changes
        for old_line, new_line in username_lines:
            content = content.replace(old_line, new_line)

        if username_lines:
            changes.append(f"User secrets: {len(username_lines)} replaced")

        # TACACS/RADIUS keys - Handle both server blocks and global commands
        for service in ["tacacs", "radius"]:
            service_upper = service.upper()
            # Pattern for server command keys (e.g., "tacacs-server key secret")
            pattern1 = re.compile(rf"({service}-server key )(\S+)", re.IGNORECASE)
            # Pattern for server block keys (e.g., "tacacs server X\n address...\n key 7 secret")
            # This pattern allows any number of lines between "server" and "key"
            pattern2 = re.compile(
                rf"({service} server [^\n]+(?:\n[ \t]+(?!{service} server)[^\n]+)*?\n[ \t]+key )(\d+)( )(\S+)",
                re.IGNORECASE | re.MULTILINE,
            )

            # Replace global server keys
            matches1 = pattern1.findall(content)
            if matches1:
                content = pattern1.sub(rf"\1<removed-{service}-key>", content)

            # Replace server block keys
            matches2 = pattern2.findall(content)
            if matches2:
                content = pattern2.sub(rf"\1\2 <removed-{service}-key>", content)

            total_replaced = len(matches1) + len(matches2)
            if total_replaced > 0:
                changes.append(f"{service_upper} keys: {total_replaced} replaced")

        # SNMP community strings
        pattern = re.compile(r"(snmp-server community )(\S+)(\s+\S+)?")

        def replace_snmp(match):
            community = match.group(2)
            rest = match.group(3) or ""
            if community.lower() not in ["ro", "rw", "read-only", "read-write"]:
                return f"{match.group(1)}<removed-snmp-community>{rest}"
            return match.group(0)

        matches = pattern.findall(content)
        if matches:
            content = pattern.sub(replace_snmp, content)
            changes.append(f"SNMP communities: {len(matches)} checked")

        # Pre-shared keys - Handle various formats

        # MKA pre-shared keys
        mka_pattern = re.compile(r"(mka pre-shared-key key-chain )(\S+)")
        mka_matches = mka_pattern.findall(content)
        if mka_matches:
            content = mka_pattern.sub(r"\1<removed-mka-key>", content)
            changes.append(f"MKA pre-shared keys: {len(mka_matches)} replaced")

        # Crypto ISAKMP keys
        isakmp_pattern = re.compile(r"(crypto isakmp key )(\S+)( .*)")
        isakmp_matches = isakmp_pattern.findall(content)
        if isakmp_matches:
            content = isakmp_pattern.sub(r"\1<removed-isakmp-key>\3", content)
            changes.append(f"ISAKMP keys: {len(isakmp_matches)} replaced")

        # Standalone pre-shared-key lines
        psk_pattern = re.compile(r"^(\s*pre-shared-key )(\S+)", re.MULTILINE)
        psk_matches = psk_pattern.findall(content)
        if psk_matches:
            content = psk_pattern.sub(r"\1<removed-psk>", content)
            changes.append(f"Pre-shared keys: {len(psk_matches)} replaced")

        # NTP authentication keys
        ntp_pattern = re.compile(r"(ntp authentication-key \d+ md5 )(\d+)?(\s*)(\S+)")
        ntp_matches = ntp_pattern.findall(content)
        if ntp_matches:
            content = ntp_pattern.sub(r"\1<removed-ntp-key>", content)
            changes.append(f"NTP keys: {len(ntp_matches)} replaced")

        # BGP/OSPF/EIGRP passwords
        routing_patterns = [
            (
                r"(neighbor \S+ password )(\d+)( )(\S+)",
                r"\g<1><removed-bgp-password>",
            ),
            (
                r"(.*message-digest-key \d+ md5 )(\d+)( )(\S+)",
                r"\g<1><removed-ospf-key>",
            ),
            (
                r"(authentication mode md5.*key-string )(\d+)( )(\S+)",
                r"\g<1><removed-auth-key>",
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
        """Find all files matching configured patterns (case-insensitive)."""
        files = []

        for pattern in self.config.file_patterns:
            if self.config.recursive:
                # Get all files matching pattern (case-sensitive first)
                matched = list(directory.rglob(pattern))
                files.extend(matched)

                # Also match case-insensitive variants for common extensions
                if pattern.startswith("*."):
                    ext = pattern[2:]  # Remove "*."
                    # Try uppercase, lowercase, and title case variants
                    for variant in [ext.upper(), ext.lower(), ext.title()]:
                        if variant != ext:
                            files.extend(directory.rglob(f"*.{variant}"))
            else:
                matched = list(directory.glob(pattern))
                files.extend(matched)

                # Also match case-insensitive variants for common extensions
                if pattern.startswith("*."):
                    ext = pattern[2:]  # Remove "*."
                    for variant in [ext.upper(), ext.lower(), ext.title()]:
                        if variant != ext:
                            files.extend(directory.glob(f"*.{variant}"))

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

    def generate_security_report(
        self,
        sanitization_results: List[SanitizationResult],
        archive_name: str,
        output_path: Path,
    ) -> Dict[str, Any]:
        """Generate comprehensive security report of sanitization.

        Args:
            sanitization_results: List of sanitization results
            archive_name: Name of the original archive
            output_path: Path where sanitized output was saved

        Returns:
            Dictionary containing the security report data
        """
        timestamp = datetime.now()

        # Aggregate statistics by secret type
        secret_stats = {}
        total_secrets = 0
        files_with_secrets = 0
        file_details = []

        for result in sanitization_results:
            if result.modified and result.changes:
                files_with_secrets += 1
                file_info = {
                    "filename": result.filepath.name,
                    "changes": result.change_count,
                    "secrets_by_type": {},
                }

                for change in result.changes:
                    # Parse change string to extract secret type and count
                    # Format: "Secret Type: N replaced" or "Secret Type: N checked"
                    if isinstance(change, str):
                        # Extract the secret type (everything before the colon)
                        if ":" in change:
                            secret_type = change.split(":")[0].strip()
                            # Extract the count
                            count_match = re.search(r'(\d+)\s+(?:replaced|checked)', change)
                            count = int(count_match.group(1)) if count_match else 1
                        else:
                            secret_type = "unknown"
                            count = 1
                    else:
                        # Fallback for unexpected format
                        secret_type = "unknown"
                        count = 1

                    if secret_type not in secret_stats:
                        secret_stats[secret_type] = {
                            "count": 0,
                            "files": set(),
                        }

                    secret_stats[secret_type]["count"] += count
                    secret_stats[secret_type]["files"].add(result.filepath.name)
                    total_secrets += count

                    # Track per-file stats
                    if secret_type not in file_info["secrets_by_type"]:
                        file_info["secrets_by_type"][secret_type] = 0
                    file_info["secrets_by_type"][secret_type] += count

                file_details.append(file_info)

        # Convert sets to counts for JSON serialization
        secret_summary = {}
        for secret_type, data in secret_stats.items():
            secret_summary[secret_type] = {
                "total_count": data["count"],
                "affected_files": len(data["files"]),
            }

        # Build report
        report = {
            "report_metadata": {
                "generated_at": timestamp.isoformat(),
                "generated_by": "Hanirizer Network Config Sanitizer",
                "report_version": "1.0",
            },
            "archive_info": {
                "original_archive": archive_name,
                "sanitized_output": str(output_path),
                "total_files_extracted": len(sanitization_results),
                "total_files_sanitized": files_with_secrets,
            },
            "security_summary": {
                "total_secrets_found": total_secrets,
                "files_containing_secrets": files_with_secrets,
                "secret_types_detected": len(secret_stats),
            },
            "secrets_by_type": secret_summary,
            "file_details": sorted(
                file_details, key=lambda x: x["changes"], reverse=True
            ),
        }

        return report

    def save_security_report(
        self,
        report: Dict[str, Any],
        output_dir: Path,
        formats: List[str] = ["json", "txt"],
    ):
        """Save security report in multiple formats.

        Args:
            report: Security report data
            output_dir: Directory to save reports
            formats: List of formats to generate (json, txt, md)
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON format
        if "json" in formats:
            json_path = output_dir / f"SECURITY_REPORT_{timestamp}.json"
            with open(json_path, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Security report (JSON) saved: {json_path}")

        # Save TXT format
        if "txt" in formats:
            txt_path = output_dir / f"SECURITY_REPORT_{timestamp}.txt"
            with open(txt_path, "w") as f:
                self._write_text_report(f, report)
            logger.info(f"Security report (TXT) saved: {txt_path}")

        # Save Markdown format
        if "md" in formats:
            md_path = output_dir / f"SECURITY_REPORT_{timestamp}.md"
            with open(md_path, "w") as f:
                self._write_markdown_report(f, report)
            logger.info(f"Security report (MD) saved: {md_path}")

    def _write_text_report(self, f, report: Dict[str, Any]):
        """Write security report in plain text format."""
        f.write("=" * 80 + "\n")
        f.write("NETWORK CONFIGURATION SANITIZATION SECURITY REPORT\n")
        f.write("=" * 80 + "\n\n")

        # Metadata
        f.write(f"Generated: {report['report_metadata']['generated_at']}\n")
        f.write(f"Tool: {report['report_metadata']['generated_by']}\n\n")

        # Archive info
        f.write("-" * 80 + "\n")
        f.write("ARCHIVE INFORMATION\n")
        f.write("-" * 80 + "\n")
        f.write(f"Original Archive: {report['archive_info']['original_archive']}\n")
        f.write(f"Sanitized Output: {report['archive_info']['sanitized_output']}\n")
        f.write(f"Total Files: {report['archive_info']['total_files_extracted']}\n")
        f.write(f"Files Sanitized: {report['archive_info']['total_files_sanitized']}\n\n")

        # Security summary
        f.write("-" * 80 + "\n")
        f.write("SECURITY SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Secrets Found: {report['security_summary']['total_secrets_found']}\n")
        f.write(f"Files With Secrets: {report['security_summary']['files_containing_secrets']}\n")
        f.write(f"Secret Types: {report['security_summary']['secret_types_detected']}\n\n")

        # Secrets by type
        if report["secrets_by_type"]:
            f.write("-" * 80 + "\n")
            f.write("SECRETS BY TYPE\n")
            f.write("-" * 80 + "\n")
            for secret_type, data in sorted(
                report["secrets_by_type"].items(),
                key=lambda x: x[1]["total_count"],
                reverse=True,
            ):
                f.write(f"\n{secret_type}:\n")
                f.write(f"  Count: {data['total_count']}\n")
                f.write(f"  Affected Files: {data['affected_files']}\n")

        # All modified files
        if report["file_details"]:
            f.write("\n" + "-" * 80 + "\n")
            f.write("MODIFIED FILES\n")
            f.write("-" * 80 + "\n")
            for idx, file_info in enumerate(report["file_details"], 1):
                f.write(f"\n{idx}. {file_info['filename']}\n")
                f.write(f"   Total Changes: {file_info['changes']}\n")
                if file_info["secrets_by_type"]:
                    f.write("   Secrets Found:\n")
                    for stype, count in sorted(
                        file_info["secrets_by_type"].items(),
                        key=lambda x: x[1],
                        reverse=True,
                    ):
                        f.write(f"     - {stype}: {count}\n")

        f.write("\n" + "=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")

    def _write_markdown_report(self, f, report: Dict[str, Any]):
        """Write security report in Markdown format."""
        f.write("# Network Configuration Sanitization Security Report\n\n")

        # Metadata
        f.write("## Report Metadata\n\n")
        f.write(f"- **Generated:** {report['report_metadata']['generated_at']}\n")
        f.write(f"- **Tool:** {report['report_metadata']['generated_by']}\n")
        f.write(f"- **Version:** {report['report_metadata']['report_version']}\n\n")

        # Archive info
        f.write("## Archive Information\n\n")
        f.write(f"- **Original Archive:** `{report['archive_info']['original_archive']}`\n")
        f.write(f"- **Sanitized Output:** `{report['archive_info']['sanitized_output']}`\n")
        f.write(f"- **Total Files Extracted:** {report['archive_info']['total_files_extracted']}\n")
        f.write(f"- **Files Sanitized:** {report['archive_info']['total_files_sanitized']}\n\n")

        # Security summary
        f.write("## Security Summary\n\n")
        f.write(f"- **Total Secrets Found:** {report['security_summary']['total_secrets_found']}\n")
        f.write(f"- **Files Containing Secrets:** {report['security_summary']['files_containing_secrets']}\n")
        f.write(f"- **Secret Types Detected:** {report['security_summary']['secret_types_detected']}\n\n")

        # Secrets by type
        if report["secrets_by_type"]:
            f.write("## Secrets by Type\n\n")
            f.write("| Secret Type | Total Count | Affected Files |\n")
            f.write("|-------------|-------------|----------------|\n")
            for secret_type, data in sorted(
                report["secrets_by_type"].items(),
                key=lambda x: x[1]["total_count"],
                reverse=True,
            ):
                f.write(f"| {secret_type} | {data['total_count']} | {data['affected_files']} |\n")
            f.write("\n")

        # All modified files
        if report["file_details"]:
            f.write("## Modified Files\n\n")
            for idx, file_info in enumerate(report["file_details"], 1):
                f.write(f"### {idx}. {file_info['filename']}\n\n")
                f.write(f"**Total Changes:** {file_info['changes']}\n\n")
                if file_info["secrets_by_type"]:
                    f.write("**Secrets Found:**\n\n")
                    for stype, count in sorted(
                        file_info["secrets_by_type"].items(),
                        key=lambda x: x[1],
                        reverse=True,
                    ):
                        f.write(f"- `{stype}`: {count}\n")
                    f.write("\n")

        f.write("---\n\n")
        f.write("*Report generated by Hanirizer Network Config Sanitizer*\n")
