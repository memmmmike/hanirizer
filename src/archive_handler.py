"""Universal archive handler for multiple compressed file formats with password support."""

import zipfile
import tarfile
import tempfile
import shutil
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Union
import logging
import getpass

logger = logging.getLogger(__name__)


class ArchiveHandler:
    """Handles various archive formats including password-protected archives."""

    # Supported archive extensions
    ARCHIVE_EXTENSIONS = {
        ".zip": "zip",
        ".7z": "7zip",
        ".rar": "rar",
        ".tar": "tar",
        ".tar.gz": "tar",
        ".tgz": "tar",
        ".tar.bz2": "tar",
        ".tbz2": "tar",
        ".tar.xz": "tar",
        ".txz": "tar",
        ".gz": "gzip",
        ".bz2": "bzip2",
        ".xz": "xz",
    }

    def __init__(self, preserve_structure: bool = True, password: Optional[str] = None):
        """Initialize archive handler.

        Args:
            preserve_structure: Whether to preserve directory structure
            password: Password for encrypted archives (will prompt if needed and not provided)
        """
        self.preserve_structure = preserve_structure
        self.password = password
        self.temp_dirs: List[Path] = []
        self._7z_available = self._check_7z_available()
        self._rar_available = self._check_rar_available()

    def _check_7z_available(self) -> bool:
        """Check if 7z command is available."""
        try:
            subprocess.run(["7z"], capture_output=True, check=False)
            return True
        except FileNotFoundError:
            return False

    def _check_rar_available(self) -> bool:
        """Check if unrar command is available."""
        try:
            subprocess.run(["unrar"], capture_output=True, check=False)
            return True
        except FileNotFoundError:
            return False

    def identify_archive_type(self, filepath: Path) -> Optional[str]:
        """Identify the type of archive based on extension and magic bytes."""
        # Check by extension first
        for ext, archive_type in self.ARCHIVE_EXTENSIONS.items():
            if filepath.name.lower().endswith(ext):
                return archive_type

        # Check by magic bytes if extension doesn't match
        try:
            with open(filepath, "rb") as f:
                magic = f.read(8)

                # ZIP files
                if magic[:2] == b"PK":
                    return "zip"
                # 7z files
                elif magic[:6] == b"7z\xbc\xaf\x27\x1c":
                    return "7zip"
                # RAR files
                elif magic[:4] == b"Rar!" or magic[:7] == b"Rar!\x1a\x07":
                    return "rar"
                # Tar files
                elif b"ustar" in f.read(512):
                    f.seek(0)
                    return "tar"
                # Gzip files
                elif magic[:2] == b"\x1f\x8b":
                    return "gzip"
                # Bzip2 files
                elif magic[:3] == b"BZh":
                    return "bzip2"
                # XZ files
                elif magic[:6] == b"\xfd7zXZ\x00":
                    return "xz"
        except Exception as e:
            logger.debug(f"Could not identify archive type by magic bytes: {e}")

        return None

    def is_archive_file(self, filepath: Path) -> bool:
        """Check if file is a supported archive."""
        return self.identify_archive_type(filepath) is not None

    def is_format_supported(self, format_name: str) -> bool:
        """Check if a specific archive format is supported."""
        format_name = format_name.lower()

        # Always supported formats (Python standard library)
        if format_name in [
            "zip",
            "tar",
            "tar.gz",
            "tar.bz2",
            "tar.xz",
            "tgz",
            "tbz2",
            "txz",
        ]:
            return True

        # 7z support depends on tool availability
        if format_name in ["7z", "7zip"]:
            return self._7z_available

        # RAR support depends on tool availability
        if format_name == "rar":
            return self._rar_available

        # Compressed file formats
        if format_name in ["gz", "gzip", "bz2", "bzip2", "xz"]:
            return True

        return False

    def extract_archive(
        self,
        archive_path: Path,
        extract_to: Optional[Path] = None,
        password: Optional[str] = None,
    ) -> Tuple[Path, List[Path]]:
        """Extract any supported archive format.

        Args:
            archive_path: Path to archive file
            extract_to: Directory to extract to (if None, creates temp dir)
            password: Password for encrypted archives

        Returns:
            Tuple of (extraction_directory, list_of_extracted_files)
        """
        archive_type = self.identify_archive_type(archive_path)

        if not archive_type:
            raise ValueError(f"Unsupported archive format: {archive_path}")

        # Use provided password or instance password
        pwd = password or self.password

        # Create extraction directory
        if extract_to is None:
            extract_dir = Path(tempfile.mkdtemp(prefix="archive_extract_"))
            self.temp_dirs.append(extract_dir)
        else:
            extract_dir = extract_to
            extract_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Extracting {archive_type} archive: {archive_path.name}")

        # Route to appropriate extraction method
        if archive_type == "zip":
            return self._extract_zip(archive_path, extract_dir, pwd)
        elif archive_type == "7zip":
            return self._extract_7z(archive_path, extract_dir, pwd)
        elif archive_type == "rar":
            return self._extract_rar(archive_path, extract_dir, pwd)
        elif archive_type == "tar":
            return self._extract_tar(archive_path, extract_dir)
        elif archive_type in ["gzip", "bzip2", "xz"]:
            return self._extract_compressed(archive_path, extract_dir, archive_type)
        else:
            raise ValueError(f"Extraction not implemented for {archive_type}")

    def _extract_zip(
        self, zip_path: Path, extract_dir: Path, password: Optional[str] = None
    ) -> Tuple[Path, List[Path]]:
        """Extract ZIP archive with optional password."""
        extracted_files = []

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                # Check if password is needed
                if (
                    zip_ref.namelist()
                    and zip_ref.getinfo(zip_ref.namelist()[0]).flag_bits & 0x1
                ):
                    if not password:
                        password = self._prompt_for_password(zip_path.name)

                    if password:
                        zip_ref.setpassword(password.encode("utf-8"))

                # Extract all files
                for file_info in zip_ref.infolist():
                    if not file_info.is_dir():
                        try:
                            zip_ref.extract(file_info, extract_dir)
                            extracted_path = extract_dir / file_info.filename
                            extracted_files.append(extracted_path)

                            # Fix permissions if needed
                            if hasattr(os, "chmod"):
                                os.chmod(extracted_path, 0o644)
                        except Exception as e:
                            logger.warning(
                                f"Failed to extract {file_info.filename}: {e}"
                            )

        except zipfile.BadZipFile as e:
            raise ValueError(f"Invalid ZIP file: {e}")
        except RuntimeError as e:
            if "Bad password" in str(e):
                raise ValueError("Incorrect password for encrypted ZIP file")
            raise

        logger.info(f"Extracted {len(extracted_files)} files from ZIP")
        return extract_dir, extracted_files

    def _extract_7z(
        self, archive_path: Path, extract_dir: Path, password: Optional[str] = None
    ) -> Tuple[Path, List[Path]]:
        """Extract 7z archive using 7z command."""
        if not self._7z_available:
            logger.warning(
                "7z command not available. Install p7zip-full (Linux/Mac) or 7-Zip (Windows) for 7z support."
            )
            raise RuntimeError(
                "7z support not available. Please install: Linux/Mac: 'sudo apt-get install p7zip-full' or 'brew install p7zip', Windows: 'choco install 7zip'"
            )

        # Build 7z command
        cmd = ["7z", "x", "-y", f"-o{extract_dir}", str(archive_path)]

        # Add password if provided
        if password:
            cmd.append(f"-p{password}")
        elif self._is_password_protected_7z(archive_path):
            password = self._prompt_for_password(archive_path.name)
            if password:
                cmd.append(f"-p{password}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Get list of extracted files
            extracted_files = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    extracted_files.append(Path(root) / file)

            logger.info(f"Extracted {len(extracted_files)} files from 7z archive")
            return extract_dir, extracted_files

        except subprocess.CalledProcessError as e:
            if "Wrong password" in e.stderr:
                raise ValueError("Incorrect password for encrypted 7z file")
            raise RuntimeError(f"Failed to extract 7z archive: {e.stderr}")

    def _extract_rar(
        self, archive_path: Path, extract_dir: Path, password: Optional[str] = None
    ) -> Tuple[Path, List[Path]]:
        """Extract RAR archive using unrar command."""
        if not self._rar_available:
            logger.warning(
                "unrar command not available. Install unrar (Linux) or WinRAR (Windows) for RAR support."
            )
            raise RuntimeError(
                "RAR support not available. Please install: Linux: 'sudo apt-get install unrar', Mac: 'brew install --cask rar', Windows: 'choco install unrar'"
            )

        # Build unrar command
        cmd = ["unrar", "x", "-y", str(archive_path), str(extract_dir) + "/"]

        # Add password if provided
        if password:
            cmd.insert(2, f"-p{password}")
        elif self._is_password_protected_rar(archive_path):
            password = self._prompt_for_password(archive_path.name)
            if password:
                cmd.insert(2, f"-p{password}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Get list of extracted files
            extracted_files = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    extracted_files.append(Path(root) / file)

            logger.info(f"Extracted {len(extracted_files)} files from RAR archive")
            return extract_dir, extracted_files

        except subprocess.CalledProcessError as e:
            if "wrong password" in e.stderr.lower():
                raise ValueError("Incorrect password for encrypted RAR file")
            raise RuntimeError(f"Failed to extract RAR archive: {e.stderr}")

    def _extract_tar(
        self, tar_path: Path, extract_dir: Path
    ) -> Tuple[Path, List[Path]]:
        """Extract tar archive (supports gz, bz2, xz compression)."""
        extracted_files = []

        try:
            with tarfile.open(tar_path, "r:*") as tar_ref:
                # Extract all files
                for member in tar_ref.getmembers():
                    if member.isfile():
                        tar_ref.extract(member, extract_dir)
                        extracted_files.append(extract_dir / member.name)

            logger.info(f"Extracted {len(extracted_files)} files from tar archive")
            return extract_dir, extracted_files

        except Exception as e:
            raise RuntimeError(f"Failed to extract tar archive: {e}")

    def _extract_compressed(
        self, file_path: Path, extract_dir: Path, compression_type: str
    ) -> Tuple[Path, List[Path]]:
        """Extract single compressed file (gz, bz2, xz)."""
        import gzip
        import bz2
        import lzma

        # Determine output filename
        output_name = file_path.stem
        output_path = extract_dir / output_name

        try:
            if compression_type == "gzip":
                with gzip.open(file_path, "rb") as f_in:
                    with open(output_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
            elif compression_type == "bzip2":
                with bz2.open(file_path, "rb") as f_in:
                    with open(output_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
            elif compression_type == "xz":
                with lzma.open(file_path, "rb") as f_in:
                    with open(output_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)

            logger.info(f"Extracted compressed file to {output_path}")
            return extract_dir, [output_path]

        except Exception as e:
            raise RuntimeError(f"Failed to extract compressed file: {e}")

    def _is_password_protected_7z(self, archive_path: Path) -> bool:
        """Check if 7z archive is password protected."""
        if not self._7z_available:
            return False

        try:
            result = subprocess.run(
                ["7z", "l", str(archive_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            return "Enter password" in result.stderr
        except:
            return False

    def _is_password_protected_rar(self, archive_path: Path) -> bool:
        """Check if RAR archive is password protected."""
        if not self._rar_available:
            return False

        try:
            result = subprocess.run(
                ["unrar", "l", str(archive_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            return "encrypted" in result.stdout.lower()
        except:
            return False

    def _prompt_for_password(self, archive_name: str) -> Optional[str]:
        """Prompt user for archive password."""
        try:
            password = getpass.getpass(f"Enter password for {archive_name}: ")
            return password if password else None
        except (KeyboardInterrupt, EOFError):
            logger.info("Password prompt cancelled")
            return None

    def create_archive(
        self,
        source_dir: Path,
        output_path: Path,
        archive_format: str = "zip",
        password: Optional[str] = None,
    ) -> Path:
        """Create an archive from a directory.

        Args:
            source_dir: Directory to archive
            output_path: Output archive path
            archive_format: Format to create ('zip', '7z', 'tar', 'tar.gz', etc.)
            password: Optional password for encryption

        Returns:
            Path to created archive
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if archive_format == "zip":
            return self._create_zip(source_dir, output_path, password)
        elif archive_format == "7z":
            return self._create_7z(source_dir, output_path, password)
        elif archive_format.startswith("tar"):
            return self._create_tar(source_dir, output_path, archive_format)
        else:
            raise ValueError(
                f"Unsupported archive format for creation: {archive_format}"
            )

    def _create_zip(
        self, source_dir: Path, output_path: Path, password: Optional[str] = None
    ) -> Path:
        """Create a ZIP archive with optional encryption."""
        if password:
            try:
                import pyminizip
            except ImportError:
                logger.warning(
                    "pyminizip not installed. Creating unencrypted ZIP instead."
                )
                password = None

        if password:
            # Use pyminizip for password-protected ZIPs
            files_to_compress = []
            for file_path in source_dir.rglob("*"):
                if file_path.is_file():
                    files_to_compress.append(str(file_path))

            pyminizip.compress_multiple(
                files_to_compress,
                [str(source_dir)],
                str(output_path),
                password,
                5,  # Compression level
            )
        else:
            # Use standard zipfile for non-encrypted ZIPs
            with zipfile.ZipFile(
                output_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6
            ) as zip_ref:
                for file_path in source_dir.rglob("*"):
                    if file_path.is_file():
                        archive_path = file_path.relative_to(source_dir)
                        zip_ref.write(file_path, archive_path)

        logger.info(f"Created ZIP archive: {output_path}")
        return output_path

    def _create_7z(
        self, source_dir: Path, output_path: Path, password: Optional[str] = None
    ) -> Path:
        """Create a 7z archive with optional encryption."""
        if not self._7z_available:
            logger.warning("7z command not available. Cannot create 7z archives.")
            raise RuntimeError(
                "7z support not available. Please install: Linux/Mac: 'sudo apt-get install p7zip-full' or 'brew install p7zip', Windows: 'choco install 7zip'"
            )

        cmd = ["7z", "a", "-t7z", str(output_path), f"{source_dir}/*"]

        if password:
            cmd.append(f"-p{password}")
            cmd.append("-mhe=on")  # Encrypt headers as well

        try:
            subprocess.run(cmd, capture_output=True, check=True)
            logger.info(f"Created 7z archive: {output_path}")
            return output_path
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create 7z archive: {e.stderr}")

    def _create_tar(
        self, source_dir: Path, output_path: Path, format_type: str
    ) -> Path:
        """Create a tar archive with optional compression."""
        compression = ""
        if format_type == "tar.gz" or format_type == "tgz":
            compression = "gz"
        elif format_type == "tar.bz2" or format_type == "tbz2":
            compression = "bz2"
        elif format_type == "tar.xz" or format_type == "txz":
            compression = "xz"

        mode = f"w:{compression}" if compression else "w"

        with tarfile.open(output_path, mode) as tar_ref:
            for file_path in source_dir.rglob("*"):
                if file_path.is_file():
                    archive_path = file_path.relative_to(source_dir)
                    tar_ref.add(file_path, archive_path)

        logger.info(f"Created tar archive: {output_path}")
        return output_path

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

    def get_archive_info(self, archive_path: Path) -> Dict[str, Any]:
        """Get information about archive contents."""
        archive_type = self.identify_archive_type(archive_path)

        if not archive_type:
            return {"error": "Unsupported archive format"}

        info = {
            "type": archive_type,
            "size_mb": round(archive_path.stat().st_size / (1024 * 1024), 2),
            "encrypted": False,
            "files": [],
        }

        try:
            if archive_type == "zip":
                with zipfile.ZipFile(archive_path, "r") as zip_ref:
                    for file_info in zip_ref.infolist():
                        if not file_info.is_dir():
                            info["files"].append(file_info.filename)
                    # Check if encrypted
                    if (
                        zip_ref.namelist()
                        and zip_ref.getinfo(zip_ref.namelist()[0]).flag_bits & 0x1
                    ):
                        info["encrypted"] = True

            elif archive_type == "7z" and self._7z_available:
                info["encrypted"] = self._is_password_protected_7z(archive_path)
                # Get file list
                result = subprocess.run(
                    ["7z", "l", "-slt", str(archive_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                for line in result.stdout.split("\n"):
                    if line.startswith("Path = "):
                        filename = line[7:]
                        if filename and filename != str(archive_path):
                            info["files"].append(filename)

            elif archive_type == "rar" and self._rar_available:
                info["encrypted"] = self._is_password_protected_rar(archive_path)
                # Get file list
                result = subprocess.run(
                    ["unrar", "lb", str(archive_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                info["files"] = [f for f in result.stdout.split("\n") if f]

            elif archive_type == "tar":
                with tarfile.open(archive_path, "r:*") as tar_ref:
                    for member in tar_ref.getmembers():
                        if member.isfile():
                            info["files"].append(member.name)

        except Exception as e:
            info["error"] = str(e)

        info["file_count"] = len(info["files"])
        return info
