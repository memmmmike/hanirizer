"""Configuration management for network sanitizer."""

import json
import yaml
import os
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class BackupConfig:
    """Backup configuration settings."""

    enabled: bool = True
    directory: str = ".backups"
    retention_days: int = 30
    compression: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BackupConfig":
        return cls(**data)


@dataclass
class Pattern:
    """Secret pattern definition."""

    name: str
    pattern: str
    replacement: str
    flags: List[str] = field(default_factory=list)
    description: Optional[str] = None

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> "Pattern":
        return cls(name=name, **data)


@dataclass
class Config:
    """Main configuration for network sanitizer."""

    service_accounts: Set[str] = field(default_factory=set)
    personal_accounts: Set[str] = field(default_factory=set)
    patterns: Dict[str, Pattern] = field(default_factory=dict)
    backup: BackupConfig = field(default_factory=BackupConfig)
    file_patterns: List[str] = field(
        default_factory=lambda: ["*.txt", "*.conf", "*.config", "*.cfg"]
    )
    recursive: bool = True
    preserve_structure: bool = True
    verbose: bool = False
    dry_run: bool = False
    parallel_workers: int = 4

    @classmethod
    def from_file(cls, filepath: str) -> "Config":
        """Load configuration from JSON or YAML file."""
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        with open(filepath, "r") as f:
            if filepath.suffix in [".yaml", ".yml"]:
                data = yaml.safe_load(f)
            else:
                data = json.load(f)

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create configuration from dictionary."""
        config = cls()

        # Load service accounts
        if "service_accounts" in data:
            config.service_accounts = set(data["service_accounts"])

        # Load personal accounts
        if "personal_accounts" in data:
            config.personal_accounts = set(data["personal_accounts"])

        # Load patterns
        if "patterns" in data:
            config.patterns = {
                name: Pattern.from_dict(name, pattern_data)
                for name, pattern_data in data["patterns"].items()
            }

        # Load backup config
        if "backup" in data:
            config.backup = BackupConfig.from_dict(data["backup"])

        # Load other settings
        for key in [
            "file_patterns",
            "recursive",
            "preserve_structure",
            "verbose",
            "dry_run",
            "parallel_workers",
        ]:
            if key in data:
                setattr(config, key, data[key])

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "service_accounts": list(self.service_accounts),
            "personal_accounts": list(self.personal_accounts),
            "patterns": {
                name: {
                    "pattern": pattern.pattern,
                    "replacement": pattern.replacement,
                    "flags": pattern.flags,
                    "description": pattern.description,
                }
                for name, pattern in self.patterns.items()
            },
            "backup": {
                "enabled": self.backup.enabled,
                "directory": self.backup.directory,
                "retention_days": self.backup.retention_days,
                "compression": self.backup.compression,
            },
            "file_patterns": self.file_patterns,
            "recursive": self.recursive,
            "preserve_structure": self.preserve_structure,
            "verbose": self.verbose,
            "dry_run": self.dry_run,
            "parallel_workers": self.parallel_workers,
        }

    def save(self, filepath: str):
        """Save configuration to file."""
        filepath = Path(filepath)
        data = self.to_dict()

        with open(filepath, "w") as f:
            if filepath.suffix in [".yaml", ".yml"]:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            else:
                json.dump(data, f, indent=2)

        logger.info(f"Configuration saved to {filepath}")

    def merge(self, other: "Config"):
        """Merge another configuration into this one."""
        self.service_accounts.update(other.service_accounts)
        self.personal_accounts.update(other.personal_accounts)
        self.patterns.update(other.patterns)

        # Merge backup config
        if other.backup:
            for key, value in vars(other.backup).items():
                if value is not None:
                    setattr(self.backup, key, value)


class VendorConfig:
    """Pre-defined vendor-specific configurations."""

    VENDORS = {
        "cisco": {
            "service_accounts": [
                "admin",
                "cisco",
                "enable",
                "operator",
                "monitor",
                "rancid",
                "netconf",
                "restconf",
            ],
            "patterns": {
                "enable_secret": {
                    "pattern": r"enable secret \d+ (\S+)",
                    "replacement": "enable secret 5 $REDACTED_ENABLE_SECRET",
                },
                "username_secret": {
                    "pattern": r"username (\S+) .*secret \d+ (\S+)",
                    "replacement": r"username \1 secret 5 $REDACTED_SECRET",
                },
                "tacacs_key": {
                    "pattern": r"tacacs.*key \d+ (\S+)",
                    "replacement": "key 7 REDACTED_TACACS_KEY",
                },
                "radius_key": {
                    "pattern": r"radius.*key \d+ (\S+)",
                    "replacement": "key 7 REDACTED_RADIUS_KEY",
                },
                "ospf_auth": {
                    "pattern": r"message-digest-key \d+ md5 \d+ (\S+)",
                    "replacement": "message-digest-key 1 md5 7 REDACTED_OSPF_KEY",
                },
                "bgp_password": {
                    "pattern": r"neighbor (\S+) password \d+ (\S+)",
                    "replacement": r"neighbor \1 password 7 REDACTED_BGP_PASS",
                },
                "snmp_community": {
                    "pattern": r"snmp-server community (\S+)",
                    "replacement": "snmp-server community REDACTED_COMMUNITY",
                },
            },
        },
        "paloalto": {
            "service_accounts": ["admin", "panorama", "api", "monitor", "operator"],
            "patterns": {
                "phash": {
                    "pattern": r"<phash>[^<]+</phash>",
                    "replacement": "<phash>$REDACTED_HASH</phash>",
                },
                "private_key": {
                    "pattern": r"<private-key>[^<]+</private-key>",
                    "replacement": "<private-key>REDACTED_PRIVATE_KEY</private-key>",
                },
                "api_key": {
                    "pattern": r"<api-key>[^<]+</api-key>",
                    "replacement": "<api-key>REDACTED_API_KEY</api-key>",
                },
                "shared_key": {
                    "pattern": r"<key>[^<]+</key>",
                    "replacement": "<key>REDACTED_KEY</key>",
                },
            },
        },
        "juniper": {
            "service_accounts": [
                "root",
                "admin",
                "operator",
                "read-only",
                "super-user",
            ],
            "patterns": {
                "encrypted_password": {
                    "pattern": r'encrypted-password "([^"]+)"',
                    "replacement": 'encrypted-password "$REDACTED_PASSWORD"',
                },
                "authentication_key": {
                    "pattern": r'authentication-key "([^"]+)"',
                    "replacement": 'authentication-key "$REDACTED_AUTH_KEY"',
                },
                "preshared_key": {
                    "pattern": r'pre-shared-key (ascii-text|hexadecimal) "([^"]+)"',
                    "replacement": r'pre-shared-key \1 "$REDACTED_PSK"',
                },
            },
        },
        "arista": {
            "service_accounts": ["admin", "cvpadmin", "ansible", "arista"],
            "patterns": {
                "username_secret": {
                    "pattern": r"username (\S+) secret (sha512 )?\S+",
                    "replacement": r"username \1 secret sha512 $REDACTED_SECRET",
                },
                "enable_password": {
                    "pattern": r"enable password (sha512 )?\S+",
                    "replacement": "enable password sha512 $REDACTED_ENABLE",
                },
                "tacacs_key": {
                    "pattern": r"key \d+ (\S+)",
                    "replacement": "key 7 REDACTED_KEY",
                },
            },
        },
    }

    @classmethod
    def get_vendor_config(cls, vendor: str) -> Config:
        """Get pre-defined configuration for a specific vendor."""
        vendor = vendor.lower()

        if vendor not in cls.VENDORS:
            raise ValueError(
                f"Unknown vendor: {vendor}. Available: {', '.join(cls.VENDORS.keys())}"
            )

        vendor_data = cls.VENDORS[vendor]

        config = Config()
        config.service_accounts = set(vendor_data.get("service_accounts", []))

        # Convert pattern dictionaries to Pattern objects
        if "patterns" in vendor_data:
            config.patterns = {
                name: Pattern(
                    name=name,
                    pattern=pattern_data["pattern"],
                    replacement=pattern_data["replacement"],
                    flags=pattern_data.get("flags", []),
                    description=pattern_data.get("description"),
                )
                for name, pattern_data in vendor_data["patterns"].items()
            }

        return config

    @classmethod
    def list_vendors(cls) -> List[str]:
        """Get list of available vendor configurations."""
        return list(cls.VENDORS.keys())
