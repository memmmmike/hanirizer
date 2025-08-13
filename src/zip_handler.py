"""ZIP file handling for network configuration sanitizer."""

import zipfile
import tempfile
import shutil
import os
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)


class ZipHandler:
    """Handles ZIP file extraction, processing, and re-compression."""

    def __init__(self, preserve_structure: bool = True, create_sanitized_zip: bool = True):
        """Initialize ZIP handler.

        Args:
            preserve_structure: Whether to preserve directory structure in ZIP
            create_sanitized_zip: Whether to create a new ZIP with sanitized files
        """
        self.preserve_structure = preserve_structure
        self.should_create_zip = create_sanitized_zip
        self.temp_dirs: List[Path] = []

    def is_zip_file(self, filepath: Path) -> bool:
        """Check if file is a ZIP archive."""
        try:
            with zipfile.ZipFile(filepath, "r"):
                return True
        except (zipfile.BadZipFile, FileNotFoundError):
            return False

    def extract_zip(self, zip_path: Path, extract_to: Optional[Path] = None) -> Tuple[Path, List[Path]]:
        """Extract ZIP file to temporary directory.

        Args:
            zip_path: Path to ZIP file
            extract_to: Directory to extract to (if None, creates temp dir)

        Returns:
            Tuple of (extraction_directory, list_of_extracted_files)
        """
        if extract_to is None:
            extract_dir = Path(tempfile.mkdtemp(prefix="netsan_extract_"))
            self.temp_dirs.append(extract_dir)
        else:
            extract_dir = extract_to
            extract_dir.mkdir(parents=True, exist_ok=True)

        extracted_files = []

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                # Get list of files in ZIP
                file_list = zip_ref.namelist()

                # Filter for config files
                config_files = [f for f in file_list if self._is_config_file(f)]

                logger.info(f"Extracting {len(config_files)} config files from {zip_path.name}")

                # Extract only config files
                for file_info in zip_ref.infolist():
                    if file_info.filename in config_files and not file_info.is_dir():
                        try:
                            # Extract file
                            zip_ref.extract(file_info, extract_dir)
                            extracted_path = extract_dir / file_info.filename
                            extracted_files.append(extracted_path)

                            # Fix permissions if needed
                            if hasattr(os, "chmod"):
                                os.chmod(extracted_path, 0o644)

                        except Exception as e:
                            logger.warning(f"Failed to extract {file_info.filename}: {e}")

        except Exception as e:
            logger.error(f"Failed to extract ZIP file {zip_path}: {e}")
            raise

        logger.info(f"Extracted {len(extracted_files)} files to {extract_dir}")
        return extract_dir, extracted_files

    def create_sanitized_zip(
        self, source_dir: Path, output_path: Path, original_zip_path: Optional[Path] = None
    ) -> Path:
        """Create a new ZIP file with sanitized configurations.

        Args:
            source_dir: Directory containing sanitized files
            output_path: Path for the new ZIP file
            original_zip_path: Original ZIP path for reference

        Returns:
            Path to created ZIP file
        """
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Generate output filename if directory provided
        if output_path.is_dir():
            if original_zip_path:
                base_name = original_zip_path.stem + "_sanitized.zip"
            else:
                base_name = "sanitized_configs.zip"
            output_path = output_path / base_name

        created_files = []

        try:
            with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zip_ref:
                # Walk through source directory
                for file_path in source_dir.rglob("*"):
                    if file_path.is_file() and self._is_config_file(str(file_path)):
                        # Calculate relative path for ZIP archive
                        if self.preserve_structure:
                            archive_path = file_path.relative_to(source_dir)
                        else:
                            archive_path = file_path.name

                        # Add file to ZIP
                        zip_ref.write(file_path, archive_path)
                        created_files.append(str(archive_path))

                        logger.debug(f"Added {file_path.name} to ZIP as {archive_path}")

            logger.info(f"Created sanitized ZIP: {output_path} ({len(created_files)} files)")
            return output_path

        except Exception as e:
            logger.error(f"Failed to create ZIP file {output_path}: {e}")
            raise

    def process_zip_file(self, zip_path: Path, sanitizer, output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Process a ZIP file end-to-end: extract, sanitize, re-zip.

        Args:
            zip_path: Path to input ZIP file
            sanitizer: NetworkSanitizer instance
            output_dir: Directory for output (default: same as input)

        Returns:
            Dictionary with processing results
        """
        if output_dir is None:
            output_dir = zip_path.parent

        results = {
            "input_zip": str(zip_path),
            "extracted_files": 0,
            "sanitized_files": 0,
            "output_zip": None,
            "temp_dir": None,
            "errors": [],
        }

        try:
            # Extract ZIP file
            extract_dir, extracted_files = self.extract_zip(zip_path)
            results["extracted_files"] = len(extracted_files)
            results["temp_dir"] = str(extract_dir)

            if not extracted_files:
                logger.warning(f"No config files found in {zip_path}")
                return results

            # Sanitize extracted files
            sanitization_results = sanitizer.sanitize_directory(str(extract_dir))

            # Count successful sanitizations
            results["sanitized_files"] = sum(1 for r in sanitization_results if r.modified)

            # Collect any errors
            for result in sanitization_results:
                if result.error:
                    results["errors"].append(f"{result.filepath.name}: {result.error}")

            # Create sanitized ZIP if requested
            if self.should_create_zip:
                sanitized_zip_path = self.create_sanitized_zip(extract_dir, output_dir, zip_path)
                results["output_zip"] = str(sanitized_zip_path)

            logger.info(
                f"ZIP processing complete: {results['sanitized_files']}/{results['extracted_files']} files sanitized"
            )

        except Exception as e:
            error_msg = f"Failed to process ZIP file {zip_path}: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)

        return results

    def process_zip_to_folder(self, zip_path: Path, sanitizer, output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Process a ZIP file and extract sanitized files to a folder.

        Args:
            zip_path: Path to input ZIP file
            sanitizer: NetworkSanitizer instance
            output_dir: Directory for output (default: same as input)

        Returns:
            Dictionary with processing results
        """
        if output_dir is None:
            # Remove any existing _sanitized suffix to avoid duplication
            base_name = zip_path.stem
            if base_name.endswith("_sanitized"):
                base_name = base_name[:-11]  # Remove '_sanitized'
            output_dir = zip_path.parent / f"{base_name}_sanitized"
        else:
            output_dir = Path(output_dir)

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        results = {
            "input_zip": str(zip_path),
            "processed_files": 0,
            "sanitized_files": 0,
            "output_dir": str(output_dir),
            "errors": [],
        }

        try:
            with zipfile.ZipFile(zip_path, "r") as input_zip:
                for file_info in input_zip.infolist():
                    if file_info.is_dir():
                        # Create directories
                        dir_path = output_dir / file_info.filename
                        dir_path.mkdir(parents=True, exist_ok=True)
                        continue

                    filename = file_info.filename

                    # Read file content from ZIP
                    try:
                        file_content = input_zip.read(file_info).decode("utf-8", errors="ignore")
                    except Exception as e:
                        logger.warning(f"Failed to read {filename}: {e}")
                        # Copy original file if can't read as text
                        output_path = output_dir / filename
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        output_path.write_bytes(input_zip.read(file_info))
                        continue

                    results["processed_files"] += 1

                    # Check if this is a config file that should be sanitized
                    if self._is_config_file(filename):
                        try:
                            # Sanitize content in memory
                            sanitized_content = sanitizer.sanitize_content(file_content, filename)

                            # Check if content was modified
                            if sanitized_content != file_content:
                                results["sanitized_files"] += 1
                                logger.debug(f"Sanitized {filename}")

                            # Write sanitized content to output folder
                            output_path = output_dir / filename
                            output_path.parent.mkdir(parents=True, exist_ok=True)
                            output_path.write_text(sanitized_content, encoding="utf-8")

                        except Exception as e:
                            error_msg = f"Failed to sanitize {filename}: {e}"
                            logger.error(error_msg)
                            results["errors"].append(error_msg)
                            # Write original content on error
                            output_path = output_dir / filename
                            output_path.parent.mkdir(parents=True, exist_ok=True)
                            output_path.write_text(file_content, encoding="utf-8")
                    else:
                        # Copy non-config files as-is
                        output_path = output_dir / filename
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        output_path.write_text(file_content, encoding="utf-8")

            logger.info(
                f"ZIP extraction complete: {results['sanitized_files']}/{results['processed_files']} files sanitized to {output_dir}"
            )

        except Exception as e:
            error_msg = f"Failed to process ZIP file to folder {zip_path}: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)

        return results

    def process_zip_in_memory(self, zip_path: Path, sanitizer, output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Process a ZIP file entirely in memory without extracting to disk.

        Args:
            zip_path: Path to input ZIP file
            sanitizer: NetworkSanitizer instance
            output_dir: Directory for output (default: same as input)

        Returns:
            Dictionary with processing results
        """
        if output_dir is None:
            output_dir = zip_path.parent

        results = {
            "input_zip": str(zip_path),
            "processed_files": 0,
            "sanitized_files": 0,
            "output_zip": None,
            "errors": [],
        }

        try:
            # Generate output filename
            if output_dir.is_dir():
                output_path = output_dir / f"{zip_path.stem}_sanitized.zip"
            else:
                output_path = output_dir

            with zipfile.ZipFile(zip_path, "r") as input_zip:
                with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as output_zip:

                    for file_info in input_zip.infolist():
                        if file_info.is_dir():
                            # Copy directories as-is
                            output_zip.writestr(file_info, "")
                            continue

                        filename = file_info.filename

                        # Read file content from ZIP
                        try:
                            file_content = input_zip.read(file_info).decode("utf-8", errors="ignore")
                        except Exception as e:
                            logger.warning(f"Failed to read {filename}: {e}")
                            # Copy original file if can't read as text
                            output_zip.writestr(file_info, input_zip.read(file_info))
                            continue

                        results["processed_files"] += 1

                        # Check if this is a config file that should be sanitized
                        if self._is_config_file(filename):
                            try:
                                # Sanitize content in memory
                                sanitized_content = sanitizer.sanitize_content(file_content, filename)

                                # Check if content was modified
                                if sanitized_content != file_content:
                                    results["sanitized_files"] += 1
                                    logger.debug(f"Sanitized {filename} in memory")

                                # Write sanitized content to output ZIP
                                output_zip.writestr(file_info, sanitized_content.encode("utf-8"))

                            except Exception as e:
                                error_msg = f"Failed to sanitize {filename}: {e}"
                                logger.error(error_msg)
                                results["errors"].append(error_msg)
                                # Write original content on error
                                output_zip.writestr(file_info, file_content.encode("utf-8"))
                        else:
                            # Copy non-config files as-is
                            output_zip.writestr(file_info, file_content.encode("utf-8"))

            results["output_zip"] = str(output_path)
            logger.info(
                f"In-memory ZIP processing complete: {results['sanitized_files']}/{results['processed_files']} files sanitized"
            )

        except Exception as e:
            error_msg = f"Failed to process ZIP file in memory {zip_path}: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)

        return results

    def _is_config_file(self, filename: str) -> bool:
        """Check if filename appears to be a network configuration file."""
        config_extensions = {".txt", ".conf", ".config", ".cfg", ".Config", ".ios", ".nx", ".eos", ".xml"}

        config_patterns = ["running", "startup", "config", "conf", "show run", "show config", "cfg"]

        filename_lower = filename.lower()

        # Check extensions
        if any(filename.endswith(ext) for ext in config_extensions):
            return True

        # Check patterns in filename
        if any(pattern in filename_lower for pattern in config_patterns):
            return True

        # Skip common non-config files
        skip_patterns = [
            ".log",
            ".txt.gz",
            ".zip",
            ".tar",
            ".pdf",
            ".doc",
            ".jpg",
            ".png",
            ".gif",
            ".bin",
            ".exe",
            ".dll",
        ]

        if any(pattern in filename_lower for pattern in skip_patterns):
            return False

        return False

    def cleanup(self):
        """Clean up temporary directories."""
        for temp_dir in self.temp_dirs:
            try:
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_dir}: {e}")

        self.temp_dirs.clear()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()

    def get_zip_info(self, zip_path: Path) -> Dict[str, Any]:
        """Get information about ZIP file contents.

        Args:
            zip_path: Path to ZIP file

        Returns:
            Dictionary with ZIP file information
        """
        info = {
            "total_files": 0,
            "config_files": 0,
            "file_list": [],
            "config_file_list": [],
            "size_mb": 0,
            "compressed_size_mb": 0,
        }

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                file_list = zip_ref.infolist()

                total_size = 0
                compressed_size = 0

                for file_info in file_list:
                    if not file_info.is_dir():
                        info["total_files"] += 1
                        info["file_list"].append(file_info.filename)

                        total_size += file_info.file_size
                        compressed_size += file_info.compress_size

                        if self._is_config_file(file_info.filename):
                            info["config_files"] += 1
                            info["config_file_list"].append(file_info.filename)

                info["size_mb"] = round(total_size / (1024 * 1024), 2)
                info["compressed_size_mb"] = round(compressed_size / (1024 * 1024), 2)

        except Exception as e:
            logger.error(f"Failed to get ZIP info for {zip_path}: {e}")
            info["error"] = str(e)

        return info
