"""Version checking and update notifications."""

import requests
import logging
from typing import Optional, Tuple
from packaging import version

from . import __version__

logger = logging.getLogger(__name__)

PYPI_API_URL = "https://pypi.org/pypi/hanirizer/json"
GITHUB_API_URL = "https://api.github.com/repos/memmmmike/hanirizer/releases/latest"


def check_pypi_version() -> Optional[str]:
    """Check latest version on PyPI.

    Returns:
        Latest version string, or None if check fails
    """
    try:
        response = requests.get(PYPI_API_URL, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data["info"]["version"]
    except Exception as e:
        logger.debug(f"Failed to check PyPI version: {e}")
    return None


def check_github_version() -> Optional[str]:
    """Check latest version on GitHub releases.

    Returns:
        Latest version string, or None if check fails
    """
    try:
        response = requests.get(GITHUB_API_URL, timeout=3)
        if response.status_code == 200:
            data = response.json()
            tag_name = data.get("tag_name", "")
            # Remove 'v' prefix if present
            return tag_name.lstrip("v")
    except Exception as e:
        logger.debug(f"Failed to check GitHub version: {e}")
    return None


def compare_versions(current: str, latest: str) -> Tuple[bool, str]:
    """Compare current version with latest version.

    Args:
        current: Current installed version
        latest: Latest available version

    Returns:
        Tuple of (is_outdated, message)
    """
    try:
        current_ver = version.parse(current)
        latest_ver = version.parse(latest)

        if latest_ver > current_ver:
            return True, f"New version available: {latest} (current: {current})"
        elif latest_ver < current_ver:
            return False, f"You're ahead of the latest release ({current} > {latest})"
        else:
            return False, f"You're on the latest version ({current})"
    except Exception as e:
        logger.debug(f"Version comparison failed: {e}")
        return False, "Could not compare versions"


def check_for_updates(silent: bool = False) -> Optional[dict]:
    """Check for available updates.

    Args:
        silent: If True, don't log anything

    Returns:
        Dictionary with update information, or None if no update check possible
    """
    # Try PyPI first, fall back to GitHub
    latest_version = check_pypi_version()
    source = "PyPI"

    if not latest_version:
        latest_version = check_github_version()
        source = "GitHub"

    if not latest_version:
        if not silent:
            logger.debug("Could not check for updates")
        return None

    is_outdated, message = compare_versions(__version__, latest_version)

    result = {
        "current_version": __version__,
        "latest_version": latest_version,
        "is_outdated": is_outdated,
        "message": message,
        "source": source,
    }

    if not silent:
        if is_outdated:
            logger.info(f"⚠️  {message}")
            logger.info(f"   Update with: pip install --upgrade hanirizer")
        else:
            logger.debug(message)

    return result


def get_update_command() -> str:
    """Get the command to update Hanirizer.

    Returns:
        Update command string
    """
    return "pip install --upgrade hanirizer"
