"""Pattern management for secret detection and replacement."""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import hashlib
import logging

logger = logging.getLogger(__name__)


@dataclass
class Pattern:
    """Represents a sanitization pattern."""

    name: str
    pattern: str
    replacement: str
    flags: List[str]
    description: Optional[str] = None

    def compile(self) -> re.Pattern:
        """Compile the pattern with specified flags."""
        regex_flags = 0
        for flag_name in self.flags:
            if hasattr(re, flag_name.upper()):
                regex_flags |= getattr(re, flag_name.upper())
        return re.compile(self.pattern, regex_flags)


class PatternManager:
    """Manages patterns for secret detection and sanitization."""

    # Default patterns for common network device secrets
    DEFAULT_PATTERNS = {
        "enable_secret": Pattern(
            name="enable_secret",
            pattern=r"(enable (?:secret|password) )(\d+)( \S+)",
            replacement=r"\1\2 $REDACTED_ENABLE",
            flags=["IGNORECASE"],
            description="Cisco enable secrets and passwords",
        ),
        "username_secret": Pattern(
            name="username_secret",
            pattern=r"(username \S+ .*(?:secret|password) )(\d+)( \S+)",
            replacement=r"\1\2 $REDACTED_SECRET",
            flags=[],
            description="Username passwords and secrets",
        ),
        "tacacs_key": Pattern(
            name="tacacs_key",
            pattern=r"(tacacs.*key )(\d+)?(\s*)(\S+)",
            replacement=r"\1\2\3REDACTED_TACACS",
            flags=["IGNORECASE"],
            description="TACACS+ server keys",
        ),
        "radius_key": Pattern(
            name="radius_key",
            pattern=r"(radius.*key )(\d+)?(\s*)(\S+)",
            replacement=r"\1\2\3REDACTED_RADIUS",
            flags=["IGNORECASE"],
            description="RADIUS server keys",
        ),
        "snmp_community": Pattern(
            name="snmp_community",
            pattern=r"(snmp-server community )(\S+)",
            replacement=r"\1REDACTED_COMMUNITY",
            flags=[],
            description="SNMP community strings",
        ),
        "ospf_auth": Pattern(
            name="ospf_auth",
            pattern=r"(message-digest-key \d+ md5 )(\d+)?(\s*)(\S+)",
            replacement=r"\1\2\3REDACTED_OSPF",
            flags=[],
            description="OSPF MD5 authentication keys",
        ),
        "bgp_password": Pattern(
            name="bgp_password",
            pattern=r"(neighbor \S+ password )(\d+)?(\s*)(\S+)",
            replacement=r"\1\2\3REDACTED_BGP",
            flags=[],
            description="BGP neighbor passwords",
        ),
        "preshared_key": Pattern(
            name="preshared_key",
            pattern=r"(pre-?shared-key )(\S+)",
            replacement=r"\1REDACTED_PSK",
            flags=["IGNORECASE"],
            description="VPN pre-shared keys",
        ),
        "key_string": Pattern(
            name="key_string",
            pattern=r"(key-string )(\d+)?(\s*)([0-9A-Fa-f]+)",
            replacement=r"\1\2\3REDACTED_KEY",
            flags=[],
            description="Encrypted key strings",
        ),
        "wpa_passphrase": Pattern(
            name="wpa_passphrase",
            pattern=r"(wpa-passphrase )(\S+)",
            replacement=r"\1REDACTED_WPA",
            flags=["IGNORECASE"],
            description="WPA/WPA2 passphrases",
        ),
        "api_key": Pattern(
            name="api_key",
            pattern=r'(api[_-]?key["\s=:]+)([a-zA-Z0-9\-_]+)',
            replacement=r"\1REDACTED_API_KEY",
            flags=["IGNORECASE"],
            description="API keys in various formats",
        ),
        "private_key_block": Pattern(
            name="private_key_block",
            pattern=r"(-----BEGIN [A-Z ]+PRIVATE KEY-----)[\s\S]+?(-----END [A-Z ]+PRIVATE KEY-----)",
            replacement=r"\1\n[REDACTED_PRIVATE_KEY]\n\2",
            flags=["MULTILINE"],
            description="Private key blocks (RSA, DSA, EC, etc.)",
        ),
        "certificate": Pattern(
            name="certificate",
            pattern=r"(-----BEGIN CERTIFICATE-----)[\s\S]+?(-----END CERTIFICATE-----)",
            replacement=r"\1\n[REDACTED_CERTIFICATE]\n\2",
            flags=["MULTILINE"],
            description="Certificate blocks",
        ),
        "xml_password": Pattern(
            name="xml_password",
            pattern=r"(<(?:password|secret|key|passphrase)>)[^<]+(</(?:password|secret|key|passphrase)>)",
            replacement=r"\1REDACTED\2",
            flags=["IGNORECASE"],
            description="Passwords in XML format",
        ),
        "json_secret": Pattern(
            name="json_secret",
            pattern=r'("(?:password|secret|key|token|api_key)"\s*:\s*")[^"]+(")',
            replacement=r"\1REDACTED\2",
            flags=["IGNORECASE"],
            description="Secrets in JSON format",
        ),
        "base64_potential": Pattern(
            name="base64_potential",
            pattern=r'(["\s])([A-Za-z0-9+/]{40,}={0,2})(["\s])',
            replacement=r"\1REDACTED_BASE64\3",
            flags=[],
            description="Potential base64 encoded secrets",
        ),
        "hex_key": Pattern(
            name="hex_key",
            pattern=r"((?:key|secret|password).*?)([0-9A-Fa-f]{32,})",
            replacement=r"\1REDACTED_HEX",
            flags=["IGNORECASE"],
            description="Hexadecimal keys and secrets",
        ),
        "ldap_password": Pattern(
            name="ldap_password",
            pattern=r"(ldap.*password )(\S+)",
            replacement=r"\1REDACTED_LDAP",
            flags=["IGNORECASE"],
            description="LDAP passwords",
        ),
        "database_url": Pattern(
            name="database_url",
            pattern=r"((?:mysql|postgresql|mongodb|redis)://[^:]+:)([^@]+)(@)",
            replacement=r"\1REDACTED\3",
            flags=["IGNORECASE"],
            description="Database connection URLs with passwords",
        ),
        "aws_secret": Pattern(
            name="aws_secret",
            pattern=r"(aws_secret_access_key\s*=\s*)(\S+)",
            replacement=r"\1REDACTED_AWS_SECRET",
            flags=["IGNORECASE"],
            description="AWS secret access keys",
        ),
    }

    def __init__(self, config=None):
        """Initialize pattern manager."""
        self.patterns = self.DEFAULT_PATTERNS.copy()

        # Add custom patterns from config
        if config and hasattr(config, "patterns"):
            self.patterns.update(config.patterns)

        # Compile all patterns
        self.compiled_patterns = {}
        for name, pattern in self.patterns.items():
            try:
                self.compiled_patterns[name] = pattern.compile()
            except Exception as e:
                logger.error(f"Failed to compile pattern '{name}': {e}")

    def add_pattern(self, pattern: Pattern):
        """Add a new pattern."""
        self.patterns[pattern.name] = pattern
        try:
            self.compiled_patterns[pattern.name] = pattern.compile()
        except Exception as e:
            logger.error(f"Failed to compile pattern '{pattern.name}': {e}")
            raise

    def remove_pattern(self, name: str):
        """Remove a pattern."""
        if name in self.patterns:
            del self.patterns[name]
            del self.compiled_patterns[name]

    def apply_patterns(
        self, content: str, pattern_names: Optional[List[str]] = None
    ) -> Tuple[str, List[str]]:
        """Apply patterns to content and return sanitized content with changes."""
        changes = []

        # Use specified patterns or all patterns
        patterns_to_apply = pattern_names if pattern_names else self.patterns.keys()

        for pattern_name in patterns_to_apply:
            if pattern_name not in self.compiled_patterns:
                continue

            pattern = self.patterns[pattern_name]
            regex = self.compiled_patterns[pattern_name]

            # Find all matches
            matches = regex.findall(content)

            if matches:
                # Apply replacement
                original_content = content
                content = regex.sub(pattern.replacement, content)

                # Record change if content was modified
                if content != original_content:
                    changes.append(
                        f"{pattern.description or pattern_name}: {len(matches)} replaced"
                    )

        return content, changes

    def detect_secrets(self, content: str) -> Dict[str, List[str]]:
        """Detect potential secrets in content without replacing them."""
        detections = {}

        for pattern_name, regex in self.compiled_patterns.items():
            matches = regex.findall(content)

            if matches:
                # Extract just the secret part from matches
                secrets = []
                for match in matches:
                    if isinstance(match, tuple):
                        # For patterns with groups, extract the secret group
                        secrets.append(match[-1] if match else "")
                    else:
                        secrets.append(match)

                if secrets:
                    detections[pattern_name] = secrets[
                        :10
                    ]  # Limit to first 10 for display

        return detections

    def validate_pattern(self, pattern_str: str) -> bool:
        """Validate a regex pattern."""
        try:
            re.compile(pattern_str)
            return True
        except re.error:
            return False

    def get_pattern_stats(self, content: str) -> Dict[str, int]:
        """Get statistics about pattern matches in content."""
        stats = {}

        for pattern_name, regex in self.compiled_patterns.items():
            matches = regex.findall(content)
            if matches:
                stats[pattern_name] = len(matches)

        return stats

    def generate_hash(self, secret_type: str, index: int = 0) -> str:
        """Generate consistent hash for replacement values."""
        base = f"{secret_type}_{index}"
        import sys

        # Python 3.8 doesn't support usedforsecurity parameter
        if sys.version_info >= (3, 9):
            return (
                hashlib.md5(base.encode(), usedforsecurity=False)
                .hexdigest()[:12]
                .upper()
            )
        else:
            return hashlib.md5(base.encode()).hexdigest()[:12].upper()

    def export_patterns(self) -> Dict[str, Dict]:
        """Export patterns as dictionary."""
        return {
            name: {
                "pattern": pattern.pattern,
                "replacement": pattern.replacement,
                "flags": pattern.flags,
                "description": pattern.description,
            }
            for name, pattern in self.patterns.items()
        }

    def import_patterns(self, patterns_dict: Dict[str, Dict]):
        """Import patterns from dictionary."""
        for name, pattern_data in patterns_dict.items():
            pattern = Pattern(
                name=name,
                pattern=pattern_data["pattern"],
                replacement=pattern_data["replacement"],
                flags=pattern_data.get("flags", []),
                description=pattern_data.get("description"),
            )
            self.add_pattern(pattern)
