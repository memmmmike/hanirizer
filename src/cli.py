"""Command-line interface for network configuration sanitizer."""

import click
import json
import sys
import logging
from pathlib import Path
import time

from . import __version__
from .sanitizer import NetworkSanitizer
from .config import Config, VendorConfig
from .backup import BackupManager
from .zip_handler import ZipHandler
from .archive_handler import ArchiveHandler
from .logging_config import setup_logging

logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version=__version__)
def cli():
    """Network Configuration Sanitizer - Secure your network configs before sharing."""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.option(
    "--vendor",
    "-v",
    type=click.Choice(["cisco", "paloalto", "juniper", "arista"]),
    help="Use vendor-specific configuration",
)
@click.option(
    "--output", "-o", type=click.Path(), help="Output directory (default: in-place)"
)
@click.option("--dry-run", is_flag=True, help="Preview changes without modifying files")
@click.option(
    "--backup/--no-backup", default=True, help="Create backups before modifying"
)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    default=True,
    help="Process directories recursively",
)
@click.option(
    "--pattern", "-p", multiple=True, help="File pattern to match (e.g., *.conf)"
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output")
@click.option(
    "--format",
    type=click.Choice(["text", "json", "csv"]),
    default="text",
    help="Output format",
)
@click.option("--stats", is_flag=True, help="Show statistics after processing")
@click.option(
    "--parallel", "-j", type=int, default=4, help="Number of parallel workers"
)
@click.option(
    "--zip-output", is_flag=True, help="Create ZIP file with sanitized configs"
)
def sanitize(
    path,
    config,
    vendor,
    output,
    dry_run,
    backup,
    recursive,
    pattern,
    verbose,
    quiet,
    format,
    stats,
    parallel,
    zip_output,
):
    """Sanitize network configuration files."""

    # Load configuration
    if config:
        cfg = Config.from_file(config)
    elif vendor:
        cfg = VendorConfig.get_vendor_config(vendor)
    else:
        cfg = Config()

    # Apply command-line options
    cfg.dry_run = dry_run
    cfg.backup.enabled = backup
    cfg.recursive = recursive
    cfg.verbose = verbose and not quiet
    cfg.parallel_workers = parallel

    if pattern:
        cfg.file_patterns = list(pattern)

    # Configure logging level
    if quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create sanitizer
    sanitizer = NetworkSanitizer(cfg)

    # Process path
    path = Path(path)
    start_time = time.time()

    # Check if input is a ZIP file
    if path.is_file() and path.suffix.lower() == ".zip":
        if not quiet:
            click.echo(f"Processing ZIP file: {path.name}")

        # Use ZIP handler to inspect the file first
        with ZipHandler() as zip_handler:
            if zip_handler.is_zip_file(path):
                zip_info = zip_handler.get_zip_info(path)
                if not quiet:
                    click.echo(
                        f"Found {zip_info['config_files']} config files in ZIP ({zip_info['size_mb']} MB)"
                    )

                # Process ZIP file
                zip_results = sanitizer.sanitize_zip_file(str(path), output)

                # Convert ZIP results to standard results format for output
                results = []
                if zip_results.get("output_zip"):
                    click.echo(
                        f"Created sanitized ZIP: {Path(zip_results['output_zip']).name}"
                    )

                # Create a summary result
                summary_result = type(
                    "ZipResult",
                    (),
                    {
                        "filepath": path,
                        "modified": zip_results["sanitized_files"] > 0,
                        "changes": [
                            f"ZIP: {zip_results['sanitized_files']}/{zip_results['extracted_files']} files sanitized"
                        ],
                        "change_count": zip_results["sanitized_files"],
                        "error": (
                            zip_results["errors"][0] if zip_results["errors"] else None
                        ),
                    },
                )()
                results = [summary_result]
            else:
                click.echo("Error: File is not a valid ZIP archive", err=True)
                sys.exit(1)

    elif path.is_file():
        results = [sanitizer.sanitize_file(path)]
    else:
        results = sanitizer.sanitize_directory(path)

        # Create ZIP output if requested
        if zip_output and not dry_run:
            output_dir = Path(output) if output else path.parent
            zip_output_path = output_dir / f"{path.name}_sanitized.zip"

            with ZipHandler() as zip_handler:
                created_zip = zip_handler.create_sanitized_zip(path, zip_output_path)
                if not quiet:
                    click.echo(f"Created ZIP: {created_zip.name}")

    duration = time.time() - start_time

    # Output results
    if format == "json":
        output_json(results, stats)
    elif format == "csv":
        output_csv(results)
    else:
        output_text(results, cfg.dry_run, stats, duration)

    # Print summary if requested
    if stats and format == "text":
        sanitizer.print_summary(results)

    # Exit with appropriate code
    error_count = sum(1 for r in results if r.error)
    sys.exit(1 if error_count > 0 else 0)


@cli.command()
@click.argument("path", type=click.Path())
@click.option("--backup-dir", type=click.Path(), help="Backup directory path")
@click.option("--date", help="Restore from specific date (YYYYMMDD)")
@click.option("--list", "list_only", is_flag=True, help="List available backups")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def restore(path, backup_dir, date, list_only, verbose):
    """Restore files from backup."""

    # Configure logging
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create backup manager
    backup_config = type(
        "BackupConfig",
        (),
        {
            "enabled": True,
            "directory": backup_dir or ".backups",
            "retention_days": 30,
            "compression": True,
        },
    )()

    manager = BackupManager(backup_config)
    path = Path(path)

    if list_only:
        # List available backups
        backups = manager.list_backups(path if path.is_file() else None)

        if not backups:
            click.echo("No backups found")
            return

        click.echo(f"Available backups ({len(backups)} total):")
        for backup in backups:
            size_mb = backup["size"] / (1024 * 1024)
            click.echo(
                f"  {backup['timestamp']} - {backup['original_path']} ({size_mb:.2f} MB)"
            )
    else:
        # Restore files
        if path.is_file():
            success = manager.restore_file(path, date)
            if success:
                click.echo(f"✓ Restored {path}")
            else:
                click.echo(f"✗ Failed to restore {path}", err=True)
                sys.exit(1)
        else:
            results = manager.restore_directory(path)
            success_count = sum(1 for r in results.values() if r)

            click.echo(f"Restored {success_count}/{len(results)} files")

            for filepath, success in results.items():
                if verbose:
                    status = "✓" if success else "✗"
                    click.echo(f"  {status} {filepath}")


@cli.command()
@click.argument("config_file", type=click.Path())
def validate(config_file):
    """Validate a configuration file."""

    try:
        config = Config.from_file(config_file)
        click.echo("✓ Configuration is valid")
        click.echo(f"  Service accounts: {len(config.service_accounts)}")
        click.echo(f"  Personal accounts: {len(config.personal_accounts)}")
        click.echo(f"  Custom patterns: {len(config.patterns)}")

        # Validate patterns
        from .patterns import PatternManager

        pm = PatternManager()

        for name, pattern in config.patterns.items():
            if pm.validate_pattern(pattern.pattern):
                click.echo(f"  ✓ Pattern '{name}' is valid")
            else:
                click.echo(f"  ✗ Pattern '{name}' is invalid", err=True)
                sys.exit(1)

    except Exception as e:
        click.echo(f"✗ Configuration is invalid: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--vendor",
    type=click.Choice(["cisco", "paloalto", "juniper", "arista"]),
    help="Generate vendor-specific config",
)
@click.option(
    "--format",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Output format",
)
def generate_config(output, vendor, format):
    """Generate a sample configuration file."""

    if vendor:
        config = VendorConfig.get_vendor_config(vendor)
    else:
        # Generate default config
        config = Config()
        config.service_accounts = {"admin", "service", "monitor", "backup"}
        config.personal_accounts = {"john.doe", "jane.smith"}

    # Convert to dictionary
    config_dict = config.to_dict()

    # Add example custom pattern
    if "patterns" not in config_dict:
        config_dict["patterns"] = {}

    config_dict["patterns"]["custom_example"] = {
        "pattern": r"my-secret-pattern (\S+)",
        "replacement": "my-secret-pattern REDACTED",
        "flags": ["IGNORECASE"],
        "description": "Example custom pattern",
    }

    # Output configuration
    if output:
        with open(output, "w") as f:
            if format == "yaml":
                import yaml

                yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
            else:
                json.dump(config_dict, f, indent=2)
        click.echo(f"Configuration written to {output}")
    else:
        if format == "yaml":
            import yaml

            click.echo(
                yaml.dump(config_dict, default_flow_style=False, sort_keys=False)
            )
        else:
            click.echo(json.dumps(config_dict, indent=2))


@cli.command()
@click.argument("archive_file", type=click.Path(exists=True))
@click.option(
    "--output", "-o", type=click.Path(), help="Output directory for sanitized files"
)
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.option(
    "--vendor",
    "-v",
    type=click.Choice(["cisco", "paloalto", "juniper", "arista"]),
    help="Use vendor-specific configuration",
)
@click.option("--dry-run", is_flag=True, help="Preview changes without creating output")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--in-memory/--extract",
    default=True,
    help="Process files in memory (default) or extract to disk first",
)
@click.option(
    "--output-format",
    type=click.Choice(["folder", "zip", "7z", "tar.gz"]),
    default="folder",
    help="Output format: folder (default), zip, 7z, or tar.gz",
)
@click.option(
    "--password", "-p", help="Password for encrypted archives (will prompt if needed)"
)
@click.option(
    "--output-password",
    help="Password for output archive (if creating encrypted archive)",
)
def sanitize_archive(
    archive_file,
    output,
    config,
    vendor,
    dry_run,
    verbose,
    in_memory,
    output_format,
    password,
    output_password,
):
    """Sanitize network configurations within any supported archive format.

    Supports: ZIP, 7Z, RAR, TAR, TAR.GZ, TAR.BZ2, TAR.XZ, GZ, BZ2, XZ
    Handles password-protected archives automatically."""

    # Load configuration
    if config:
        cfg = Config.from_file(config)
    elif vendor:
        cfg = VendorConfig.get_vendor_config(vendor)
    else:
        cfg = Config()

    cfg.dry_run = dry_run
    cfg.verbose = verbose

    # Setup file logging
    log_dir = Path.cwd() / "logs"
    setup_logging(log_dir=log_dir, verbose=verbose, log_to_file=True)

    logger.info(f"Starting sanitization of {archive_file}")
    logger.info(f"Hanirizer version: {__version__}")

    archive_path = Path(archive_file)

    # Inspect archive file first using ArchiveHandler
    with ArchiveHandler(password=password) as archive_handler:
        if not archive_handler.is_archive_file(archive_path):
            click.echo("Error: File is not a supported archive format", err=True)
            sys.exit(1)

        archive_info = archive_handler.get_archive_info(archive_path, password=password)
        click.echo(f"Archive file: {archive_path.name}")
        click.echo(f"Archive type: {archive_info['type']}")
        if archive_info.get("encrypted"):
            click.echo("Encrypted: Yes")
        click.echo(f"Total files: {archive_info['file_count']}")
        click.echo(f"Size: {archive_info['size_mb']} MB")

        # If encrypted and no password provided, warn but continue
        # (extraction will prompt for password)
        if archive_info.get("encrypted") and not password and archive_info["file_count"] == 0:
            click.echo("\n⚠️  Archive is encrypted. File count may be inaccurate without password.")
            click.echo("   Continuing anyway - you will be prompted for password during extraction.")
            # Don't return early - let extraction prompt for password

        if verbose:
            click.echo("\nFiles found in archive:")
            for file_name in archive_info["files"][:10]:  # Show first 10
                click.echo(f"  - {file_name}")
            if len(archive_info["files"]) > 10:
                click.echo(f"  ... and {len(archive_info['files']) - 10} more")

    if dry_run:
        click.echo(
            f"\n*** DRY RUN - Would process {archive_info['file_count']} files ***"
        )
        return

    # Process archive file
    sanitizer = NetworkSanitizer(cfg)

    if verbose:
        click.echo(f"Processing archive with output format: {output_format}")

    results = sanitizer.sanitize_archive_file(
        str(archive_path),
        output,
        archive_format=output_format,
        password=password,
        output_password=output_password,
    )

    # Display results
    click.echo("\n" + "=" * 60)
    click.echo("SANITIZATION COMPLETE")
    click.echo("=" * 60)

    click.echo(f"Input:  {archive_path.name}")
    if "output_path" in results:
        click.echo(f"Output: {Path(results['output_path']).name}")

    click.echo(f"\nFiles extracted: {results.get('extracted_files', 0)}")
    click.echo(f"Files sanitized: {results['sanitized_files']}")

    # Show error summary
    error_count = len(results.get("errors", []))
    if error_count > 0:
        click.echo(f"Files with errors: {error_count}", err=True)

    # Show reports generated
    if "output_path" in results:
        click.echo(f"\nOutput location: {results['output_path']}")
        click.echo("Security reports: SECURITY_REPORT_*.{json,txt,md}")

    if results.get("errors"):
        click.echo("\n" + "=" * 60)
        click.echo("ERRORS ENCOUNTERED")
        click.echo("=" * 60)
        for error in results["errors"]:
            click.echo(f"  - {error}", err=True)
            logger.error(f"File error: {error}")

    click.echo("=" * 60)

    # Log completion
    logger.info(f"Sanitization complete: {results['sanitized_files']} files sanitized, {error_count} errors")

    # Exit with error code if there were errors
    if error_count > 0:
        sys.exit(1)


@cli.command()
def list_vendors():
    """List available vendor configurations."""

    vendors = VendorConfig.list_vendors()
    click.echo("Available vendor configurations:")

    for vendor in vendors:
        config = VendorConfig.get_vendor_config(vendor)
        click.echo(f"\n{vendor.upper()}:")
        click.echo(f"  Service accounts: {len(config.service_accounts)}")
        click.echo(f"  Patterns: {len(config.patterns)}")

        if config.patterns:
            click.echo("  Pattern types:")
            for pattern_name in list(config.patterns.keys())[:5]:
                click.echo(f"    - {pattern_name}")
            if len(config.patterns) > 5:
                click.echo(f"    ... and {len(config.patterns) - 5} more")


@cli.command()
def check_update():
    """Check for available updates."""
    from .version_check import check_for_updates

    click.echo(f"Current version: {__version__}")
    click.echo("Checking for updates...")

    result = check_for_updates(silent=True)

    if result is None:
        click.echo("❌ Could not check for updates (no internet connection?)")
        return

    click.echo(f"Latest version: {result['latest_version']} (from {result['source']})")

    if result['is_outdated']:
        click.echo(f"\n⚠️  {result['message']}")
        click.echo(f"\nTo update, run:")
        click.echo(f"  pip install --upgrade hanirizer")
    else:
        click.echo(f"\n✓ {result['message']}")


def output_text(results, dry_run, show_stats, duration):
    """Output results in text format."""
    modified_count = sum(1 for r in results if r.modified)
    error_count = sum(1 for r in results if r.error)

    for result in results:
        if result.error:
            click.echo(f"✗ Error: {result.filepath.name} - {result.error}", err=True)
        elif result.modified:
            click.echo(
                f"✓ Modified: {result.filepath.name} ({result.change_count} changes)"
            )
        else:
            if show_stats:
                click.echo(f"○ No changes: {result.filepath.name}")

    if show_stats:
        click.echo(f"\nProcessing time: {duration:.2f} seconds")
        click.echo(f"Files processed: {len(results)}")
        click.echo(f"Files modified: {modified_count}")
        click.echo(f"Errors: {error_count}")

    if dry_run:
        click.echo("\n*** DRY RUN - No files were modified ***")


def output_json(results, show_stats):
    """Output results in JSON format."""
    output = {
        "results": [
            {
                "file": str(r.filepath),
                "modified": r.modified,
                "changes": r.changes,
                "change_count": r.change_count,
                "error": r.error,
                "backup": str(r.backup_path) if r.backup_path else None,
                "duration": r.duration,
            }
            for r in results
        ]
    }

    if show_stats:
        output["stats"] = {
            "total_files": len(results),
            "modified_files": sum(1 for r in results if r.modified),
            "total_changes": sum(r.change_count for r in results),
            "errors": sum(1 for r in results if r.error),
        }

    click.echo(json.dumps(output, indent=2))


def output_csv(results):
    """Output results in CSV format."""
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(["File", "Modified", "Changes", "Error", "Backup", "Duration"])

    # Write data
    for result in results:
        writer.writerow(
            [
                result.filepath.name,
                "Yes" if result.modified else "No",
                result.change_count,
                result.error or "",
                str(result.backup_path) if result.backup_path else "",
                f"{result.duration:.3f}",
            ]
        )

    click.echo(output.getvalue())


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
