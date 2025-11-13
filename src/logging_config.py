"""Logging configuration for Hanirizer."""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime


def setup_logging(log_dir: Path = None, verbose: bool = False, log_to_file: bool = True):
    """Configure logging for the application.

    Args:
        log_dir: Directory to store log files (default: ./logs)
        verbose: Enable debug logging
        log_to_file: Whether to log to files
    """
    # Create log directory
    if log_to_file:
        if log_dir is None:
            log_dir = Path.cwd() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

    # Set log level
    log_level = logging.DEBUG if verbose else logging.INFO

    # Create formatters
    detailed_formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    simple_formatter = logging.Formatter(
        fmt="%(levelname)s: %(message)s"
    )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler (simple format)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO if not verbose else logging.DEBUG)
    console_handler.setFormatter(simple_formatter)
    root_logger.addHandler(console_handler)

    if log_to_file:
        # Main log file (all messages)
        main_log = log_dir / "hanirizer.log"
        main_handler = RotatingFileHandler(
            main_log,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
        main_handler.setLevel(logging.DEBUG)
        main_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(main_handler)

        # Error log file (errors only)
        error_log = log_dir / "hanirizer_errors.log"
        error_handler = RotatingFileHandler(
            error_log,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(error_handler)

        # Session log (current run only)
        session_log = log_dir / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        session_handler = logging.FileHandler(session_log, encoding="utf-8")
        session_handler.setLevel(logging.DEBUG)
        session_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(session_handler)

        logging.info(f"Logging to: {log_dir}")
        logging.debug(f"Session log: {session_log}")

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class SensitiveDataFilter(logging.Filter):
    """Filter to redact sensitive data from logs."""

    # Patterns that might contain secrets
    REDACT_PATTERNS = [
        "password",
        "secret",
        "key",
        "token",
        "credential",
    ]

    def filter(self, record):
        """Filter log record to redact sensitive data."""
        if hasattr(record, "msg"):
            msg = str(record.msg).lower()
            # Don't log if message contains sensitive keywords
            for pattern in self.REDACT_PATTERNS:
                if pattern in msg and "=" in msg:
                    # Redact values but keep structure
                    record.msg = self._redact_values(str(record.msg))
        return True

    def _redact_values(self, message: str) -> str:
        """Redact values after = signs in message."""
        parts = message.split(" ")
        redacted_parts = []
        for part in parts:
            if "=" in part:
                key, _ = part.split("=", 1)
                redacted_parts.append(f"{key}=<redacted>")
            else:
                redacted_parts.append(part)
        return " ".join(redacted_parts)
