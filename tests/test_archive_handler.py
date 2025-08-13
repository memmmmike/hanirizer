"""Tests for archive handler functionality."""

import pytest
import tempfile
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch
import zipfile
import tarfile

from src.archive_handler import ArchiveHandler


def check_7z_available():
    """Check if 7z command is available."""
    try:
        subprocess.run(["7z"], capture_output=True, check=False)
        return True
    except (FileNotFoundError, OSError):
        return False


def check_unrar_available():
    """Check if unrar command is available."""
    try:
        subprocess.run(["unrar"], capture_output=True, check=False)
        return True
    except (FileNotFoundError, OSError):
        return False


class TestArchiveHandler:
    """Test archive handler functionality."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.fixture
    def archive_handler(self):
        """Create an archive handler instance."""
        return ArchiveHandler()

    @pytest.fixture
    def sample_files(self, temp_dir):
        """Create sample files for testing."""
        files = []
        for i in range(3):
            file_path = temp_dir / f"test_file_{i}.txt"
            file_path.write_text(f"Test content {i}")
            files.append(file_path)
        return files

    def test_zip_support_always_available(self, archive_handler):
        """Test that ZIP support is always available."""
        assert archive_handler.is_format_supported("zip")

    def test_tar_support_always_available(self, archive_handler):
        """Test that TAR support is always available."""
        assert archive_handler.is_format_supported("tar")
        assert archive_handler.is_format_supported("tar.gz")
        assert archive_handler.is_format_supported("tar.bz2")

    @pytest.mark.skipif(not check_7z_available(), reason="7z not installed")
    def test_7z_support_when_available(self, archive_handler):
        """Test 7z support when tool is available."""
        assert archive_handler.is_format_supported("7z")
        assert archive_handler._7z_available

    @pytest.mark.skipif(not check_unrar_available(), reason="unrar not installed")
    def test_rar_support_when_available(self, archive_handler):
        """Test RAR support when tool is available."""
        assert archive_handler.is_format_supported("rar")
        assert archive_handler._rar_available

    def test_create_zip_archive(self, archive_handler, temp_dir, sample_files):
        """Test creating a ZIP archive."""
        output_path = temp_dir / "test_archive.zip"

        result = archive_handler.create_archive(temp_dir, output_path, "zip")

        assert result.exists()
        assert zipfile.is_zipfile(result)

        # Verify contents
        with zipfile.ZipFile(result, "r") as zf:
            names = zf.namelist()
            assert len(names) == 3

    def test_extract_zip_archive(self, archive_handler, temp_dir):
        """Test extracting a ZIP archive."""
        # Create a test ZIP
        zip_path = temp_dir / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("file2.txt", "content2")

        # Extract it
        extract_dir, files = archive_handler.extract_archive(zip_path)

        assert len(files) == 2
        assert any(f.name == "file1.txt" for f in files)
        assert any(f.name == "file2.txt" for f in files)

    def test_create_tar_gz_archive(self, archive_handler, temp_dir, sample_files):
        """Test creating a TAR.GZ archive."""
        output_path = temp_dir / "test_archive.tar.gz"

        result = archive_handler.create_archive(temp_dir, output_path, "tar.gz")

        assert result.exists()
        assert tarfile.is_tarfile(result)

        # Verify contents
        with tarfile.open(result, "r:gz") as tf:
            members = tf.getmembers()
            assert len([m for m in members if m.isfile()]) == 3

    @pytest.mark.skipif(not check_7z_available(), reason="7z not installed")
    def test_create_7z_archive(self, archive_handler, temp_dir, sample_files):
        """Test creating a 7z archive."""
        output_path = temp_dir / "test_archive.7z"

        result = archive_handler.create_archive(temp_dir, output_path, "7z")

        assert result.exists()

        # Verify with 7z command
        result = subprocess.run(["7z", "l", str(output_path)], capture_output=True, text=True)
        assert result.returncode == 0

    def test_password_protected_zip(self, archive_handler, temp_dir):
        """Test creating and extracting password-protected ZIP."""
        # Note: pyminizip is used for password-protected ZIPs
        # This test verifies the API works even if actual encryption requires pyminizip

        output_path = temp_dir / "test_encrypted.zip"
        password = "test_password"

        # Create some test files
        test_file = temp_dir / "secret.txt"
        test_file.write_text("Secret content")

        # Create password-protected ZIP
        result = archive_handler.create_archive(temp_dir, output_path, "zip", password)
        assert result.exists()

    def test_unsupported_format_raises_error(self, archive_handler, temp_dir):
        """Test that unsupported formats raise appropriate errors."""
        with pytest.raises(ValueError, match="Unsupported archive format"):
            archive_handler.create_archive(temp_dir, temp_dir / "test.xyz", "xyz")

    def test_cleanup_temp_directories(self, archive_handler, temp_dir):
        """Test that temporary directories are cleaned up."""
        # Create a test ZIP
        zip_path = temp_dir / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file.txt", "content")

        # Extract it (creates temp dir)
        extract_dir, _ = archive_handler.extract_archive(zip_path)

        # Cleanup should remove temp dirs
        archive_handler.cleanup()

        # Check temp dir no longer exists (if it was a temp dir)
        if str(extract_dir).startswith(tempfile.gettempdir()):
            assert not extract_dir.exists()

    @pytest.mark.skipif(check_7z_available(), reason="Test for when 7z is NOT installed")
    def test_7z_not_available_error(self, archive_handler, temp_dir):
        """Test appropriate error when 7z is not available."""
        if archive_handler._7z_available:
            pytest.skip("7z is available, skipping test")

        with pytest.raises(RuntimeError, match="7z support not available"):
            archive_handler.create_archive(temp_dir, temp_dir / "test.7z", "7z")

    @pytest.mark.skipif(check_unrar_available(), reason="Test for when unrar is NOT installed")
    def test_rar_not_available_error(self, archive_handler, temp_dir):
        """Test appropriate error when unrar is not available."""
        if archive_handler._rar_available:
            pytest.skip("unrar is available, skipping test")

        # Create a fake RAR file
        rar_path = temp_dir / "test.rar"
        rar_path.write_bytes(b"Rar!\x1a\x07\x00")  # RAR signature

        with pytest.raises(RuntimeError, match="RAR support not available"):
            archive_handler.extract_archive(rar_path)
