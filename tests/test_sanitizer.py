"""Tests for the network sanitizer."""

import pytest
import tempfile
from pathlib import Path
import json

from src.sanitizer import NetworkSanitizer, SanitizationResult
from src.config import Config
from src.patterns import PatternManager


class TestNetworkSanitizer:
    """Test the NetworkSanitizer class."""

    @pytest.fixture
    def config(self):
        """Create test configuration."""
        config = Config()
        config.service_accounts = {"admin", "service"}
        config.personal_accounts = {"john.doe", "jane.smith"}
        config.dry_run = False
        config.backup.enabled = False
        return config

    @pytest.fixture
    def sanitizer(self, config):
        """Create test sanitizer."""
        return NetworkSanitizer(config)

    def test_sanitize_enable_secret(self, sanitizer):
        """Test sanitization of enable secrets."""
        content = "enable secret 5 $1$xyz$abcdef123456"
        result = sanitizer.sanitize_content(content)
        assert "$REDACTED_ENABLE_SECRET" in result
        assert "$1$xyz$abcdef123456" not in result

    def test_sanitize_username_password(self, sanitizer):
        """Test sanitization of username passwords."""
        content = """
        username admin secret 5 $1$abc$def123
        username john.doe password 7 1234567890ABCDEF
        """
        result = sanitizer.sanitize_content(content)
        assert "$REDACTED_" in result
        assert "$1$abc$def123" not in result
        assert "1234567890ABCDEF" not in result

    def test_preserve_service_accounts(self, sanitizer):
        """Test that service account usernames are preserved."""
        content = "username admin secret 5 $1$abc$def123"
        result = sanitizer.sanitize_content(content)
        assert "username admin" in result
        assert "$REDACTED_" in result

    def test_replace_personal_accounts(self, sanitizer):
        """Test that personal account usernames are replaced."""
        content = """
        username john.doe secret 5 $1$abc$def123
        Last configuration change by john.doe
        """
        result = sanitizer.sanitize_content(content)
        assert "john.doe" not in result
        assert "netadmin1" in result

    def test_sanitize_tacacs_key(self, sanitizer):
        """Test sanitization of TACACS keys."""
        content = """
        tacacs server SERVER1
         key 7 1234567890ABCDEF
        tacacs-server key MySecretKey
        """
        result = sanitizer.sanitize_content(content)
        assert "REDACTED_TACACS" in result
        assert "1234567890ABCDEF" not in result
        assert "MySecretKey" not in result

    def test_sanitize_snmp_community(self, sanitizer):
        """Test sanitization of SNMP community strings."""
        content = """
        snmp-server community public RO
        snmp-server community MySecret RW
        """
        result = sanitizer.sanitize_content(content)
        assert "REDACTED_COMMUNITY" in result
        assert "MySecret" not in result

    def test_sanitize_routing_passwords(self, sanitizer):
        """Test sanitization of routing protocol passwords."""
        content = """
        router ospf 1
         area 0 authentication message-digest
         network 10.0.0.0 0.0.0.255 area 0
        !
        interface GigabitEthernet0/0
         ip ospf message-digest-key 1 md5 7 1234567890
        !
        router bgp 65001
         neighbor 10.0.0.1 password 7 ABCDEF123456
        """
        result = sanitizer.sanitize_content(content)
        assert "REDACTED_OSPF" in result or "REDACTED_BGP" in result
        assert "1234567890" not in result
        assert "ABCDEF123456" not in result

    def test_sanitize_preshared_key(self, sanitizer):
        """Test sanitization of pre-shared keys."""
        content = """
        crypto isakmp key MyVPNKey address 10.0.0.1
        pre-shared-key SuperSecretKey
        """
        result = sanitizer.sanitize_content(content)
        assert "REDACTED" in result
        assert "MyVPNKey" not in result
        assert "SuperSecretKey" not in result

    def test_sanitize_file_creation(self, sanitizer, tmp_path):
        """Test file sanitization with file creation."""
        # Create test file
        test_file = tmp_path / "test_config.txt"
        test_file.write_text("enable secret 5 $1$xyz$abcdef123456")

        # Sanitize file
        result = sanitizer.sanitize_file(str(test_file))

        # Check result
        assert result.modified
        assert len(result.changes) > 0
        assert result.error is None

        # Check file content
        sanitized_content = test_file.read_text()
        assert "$REDACTED_ENABLE_SECRET" in sanitized_content
        assert "$1$xyz$abcdef123456" not in sanitized_content

    def test_dry_run_mode(self, config, tmp_path):
        """Test dry-run mode doesn't modify files."""
        config.dry_run = True
        sanitizer = NetworkSanitizer(config)

        # Create test file
        test_file = tmp_path / "test_config.txt"
        original_content = "enable secret 5 $1$xyz$abcdef123456"
        test_file.write_text(original_content)

        # Sanitize file in dry-run mode
        result = sanitizer.sanitize_file(str(test_file))

        # Check result
        assert result.modified

        # Check file wasn't modified
        assert test_file.read_text() == original_content

    def test_sanitize_directory(self, sanitizer, tmp_path):
        """Test directory sanitization."""
        # Create test files
        (tmp_path / "config1.txt").write_text("enable secret 5 $1$secret1")
        (tmp_path / "config2.txt").write_text("enable secret 5 $1$secret2")
        (tmp_path / "other.log").write_text("enable secret 5 $1$secret3")

        # Sanitize directory
        results = sanitizer.sanitize_directory(str(tmp_path))

        # Check results
        assert len(results) == 2  # Only .txt files by default
        assert all(r.modified for r in results)
        assert all(r.error is None for r in results)

    def test_parallel_processing(self, config, tmp_path):
        """Test parallel file processing."""
        config.parallel_workers = 2
        sanitizer = NetworkSanitizer(config)

        # Create multiple test files
        for i in range(5):
            (tmp_path / f"config{i}.txt").write_text(f"enable secret 5 $1$secret{i}")

        # Sanitize directory with parallel processing
        results = sanitizer.sanitize_directory(str(tmp_path))

        # Check results
        assert len(results) == 5
        assert all(r.modified for r in results)

    def test_error_handling(self, sanitizer):
        """Test error handling for non-existent files."""
        result = sanitizer.sanitize_file("/nonexistent/file.txt")
        assert result.error is not None
        assert not result.modified

    def test_statistics(self, sanitizer, tmp_path):
        """Test statistics gathering."""
        # Create test files
        (tmp_path / "config1.txt").write_text("enable secret 5 $1$secret1")
        (tmp_path / "config2.txt").write_text("no secrets here")

        # Sanitize directory
        results = sanitizer.sanitize_directory(str(tmp_path))

        # Check statistics
        stats = sanitizer.get_stats()
        assert stats["files_processed"] == 2
        assert stats["files_modified"] == 1
        assert stats["errors"] == 0


class TestPatternManager:
    """Test the PatternManager class."""

    def test_default_patterns(self):
        """Test that default patterns are loaded."""
        pm = PatternManager()
        assert len(pm.patterns) > 0
        assert "enable_secret" in pm.patterns
        assert "username_secret" in pm.patterns

    def test_pattern_compilation(self):
        """Test pattern compilation."""
        pm = PatternManager()
        for name, pattern in pm.patterns.items():
            assert name in pm.compiled_patterns
            assert pm.compiled_patterns[name] is not None

    def test_detect_secrets(self):
        """Test secret detection without replacement."""
        pm = PatternManager()
        content = """
        enable secret 5 $1$xyz$abcdef123456
        username admin password 7 1234567890
        snmp-server community MySecret RW
        """

        detections = pm.detect_secrets(content)
        assert len(detections) > 0
        assert any("enable" in key.lower() for key in detections)

    def test_pattern_validation(self):
        """Test pattern validation."""
        pm = PatternManager()

        # Valid pattern
        assert pm.validate_pattern(r"test \d+ pattern")

        # Invalid pattern
        assert not pm.validate_pattern(r"test [invalid")

    def test_custom_pattern(self):
        """Test adding custom patterns."""
        pm = PatternManager()
        from src.patterns import Pattern

        custom_pattern = Pattern(
            name="custom_test",
            pattern=r"custom-secret (\S+)",
            replacement=r"custom-secret REDACTED",
            flags=[],
            description="Test custom pattern",
        )

        pm.add_pattern(custom_pattern)
        assert "custom_test" in pm.patterns

        # Test application
        content = "custom-secret MySecretValue"
        result, changes = pm.apply_patterns(content, ["custom_test"])
        assert "REDACTED" in result
        assert "MySecretValue" not in result
