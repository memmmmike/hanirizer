"""Hanirizer - Secure your network configs before sharing."""

__version__ = "1.2.0"
__author__ = "Network Automation Community"
__email__ = "support@example.com"

from .sanitizer import NetworkSanitizer
from .config import Config, VendorConfig
from .backup import BackupManager
from .patterns import PatternManager, Pattern
from .zip_handler import ZipHandler
from .cli import main as cli_main

__all__ = [
    "NetworkSanitizer",
    "Config",
    "VendorConfig",
    "BackupManager",
    "PatternManager",
    "Pattern",
    "ZipHandler",
    "cli_main",
]
