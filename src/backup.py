"""Backup and restore functionality."""

import os
import shutil
import gzip
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class BackupManager:
    """Manages backup and restore operations."""

    def __init__(self, config):
        """Initialize backup manager with configuration."""
        self.enabled = config.enabled
        self.backup_dir = Path(config.directory)
        self.retention_days = config.retention_days
        self.compression = config.compression

        # Create backup directory if it doesn't exist
        if self.enabled:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            self._metadata_file = self.backup_dir / "backup_metadata.json"
            self._load_metadata()

    def _load_metadata(self):
        """Load backup metadata."""
        if self._metadata_file.exists():
            with open(self._metadata_file, "r") as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {"backups": {}}

    def _save_metadata(self):
        """Save backup metadata."""
        with open(self._metadata_file, "w") as f:
            json.dump(self.metadata, f, indent=2, default=str)

    def create_backup(self, filepath: Path) -> Optional[Path]:
        """Create a backup of a file."""
        if not self.enabled:
            return None

        try:
            # Generate backup filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_hash = self._calculate_hash(filepath)[:8]

            if self.compression:
                backup_name = (
                    f"{filepath.stem}_{timestamp}_{file_hash}.{filepath.suffix}.gz"
                )
            else:
                backup_name = (
                    f"{filepath.stem}_{timestamp}_{file_hash}{filepath.suffix}"
                )

            backup_path = self.backup_dir / backup_name

            # Create backup
            if self.compression:
                with open(filepath, "rb") as f_in:
                    with gzip.open(backup_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(filepath, backup_path)

            # Update metadata
            self.metadata["backups"][str(backup_path)] = {
                "original_path": str(filepath),
                "timestamp": timestamp,
                "file_hash": file_hash,
                "compressed": self.compression,
                "size": backup_path.stat().st_size,
            }
            self._save_metadata()

            logger.debug(f"Created backup: {backup_path}")
            return backup_path

        except Exception as e:
            logger.error(f"Failed to create backup for {filepath}: {e}")
            return None

    def restore_file(
        self, original_path: Path, backup_date: Optional[str] = None
    ) -> bool:
        """Restore a file from backup."""
        try:
            # Find matching backup
            backup_path = self._find_backup(original_path, backup_date)

            if not backup_path:
                logger.error(f"No backup found for {original_path}")
                return False

            # Restore file
            backup_info = self.metadata["backups"][str(backup_path)]

            if backup_info["compressed"]:
                with gzip.open(backup_path, "rb") as f_in:
                    with open(original_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(backup_path, original_path)

            logger.info(f"Restored {original_path} from {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore {original_path}: {e}")
            return False

    def restore_directory(self, directory: Path) -> Dict[str, bool]:
        """Restore all files in a directory from backups."""
        results = {}

        for backup_path, info in self.metadata["backups"].items():
            original_path = Path(info["original_path"])

            try:
                is_relative = (
                    original_path.parent == directory
                    or original_path.is_relative_to(directory)
                )
            except AttributeError:
                # Python < 3.9 doesn't have is_relative_to
                try:
                    original_path.relative_to(directory)
                    is_relative = True
                except ValueError:
                    is_relative = original_path.parent == directory

            if is_relative:
                results[str(original_path)] = self.restore_file(original_path)

        return results

    def list_backups(self, filepath: Optional[Path] = None) -> List[Dict[str, Any]]:
        """List available backups."""
        backups = []

        for backup_path, info in self.metadata["backups"].items():
            if filepath is None or Path(info["original_path"]) == filepath:
                backup_info = info.copy()
                backup_info["backup_path"] = backup_path
                backups.append(backup_info)

        # Sort by timestamp
        backups.sort(key=lambda x: x["timestamp"], reverse=True)

        return backups

    def cleanup_old_backups(self):
        """Remove backups older than retention period."""
        if self.retention_days <= 0:
            return

        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        removed_count = 0

        for backup_path, info in list(self.metadata["backups"].items()):
            backup_date = datetime.strptime(info["timestamp"], "%Y%m%d_%H%M%S")

            if backup_date < cutoff_date:
                try:
                    Path(backup_path).unlink()
                    del self.metadata["backups"][backup_path]
                    removed_count += 1
                except Exception as e:
                    logger.error(f"Failed to remove old backup {backup_path}: {e}")

        if removed_count > 0:
            self._save_metadata()
            logger.info(f"Removed {removed_count} old backups")

    def _find_backup(
        self, original_path: Path, backup_date: Optional[str] = None
    ) -> Optional[Path]:
        """Find a backup for a given file."""
        matching_backups = []

        for backup_path, info in self.metadata["backups"].items():
            if Path(info["original_path"]) == original_path:
                if backup_date is None or info["timestamp"].startswith(backup_date):
                    matching_backups.append((backup_path, info["timestamp"]))

        if matching_backups:
            # Return most recent matching backup
            matching_backups.sort(key=lambda x: x[1], reverse=True)
            return Path(matching_backups[0][0])

        return None

    def _calculate_hash(self, filepath: Path) -> str:
        """Calculate file hash for identification."""
        hasher = hashlib.md5()

        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        return hasher.hexdigest()

    def get_backup_stats(self) -> Dict[str, Any]:
        """Get backup statistics."""
        if not self.metadata["backups"]:
            return {
                "total_backups": 0,
                "total_size": 0,
                "oldest_backup": None,
                "newest_backup": None,
            }

        total_size = sum(info["size"] for info in self.metadata["backups"].values())
        timestamps = [info["timestamp"] for info in self.metadata["backups"].values()]

        return {
            "total_backups": len(self.metadata["backups"]),
            "total_size": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "oldest_backup": min(timestamps),
            "newest_backup": max(timestamps),
            "compression_enabled": self.compression,
            "retention_days": self.retention_days,
        }
