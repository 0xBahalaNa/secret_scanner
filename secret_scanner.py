"""
secret_scanner.py

This script scans a directory for sensitive information such as:
- AWS credentials
- API keys
- Database credentials

Usage:
    python secret_scanner.py [directory] [--exit-zero]

If no directory is provided, defaults to test_configs/.
"""

import argparse
import sys
from pathlib import Path

# argparse replaces manual sys.argv parsing. It handles --help automatically,
# validates inputs, and makes adding new flags (like --exit-zero) straightforward.
parser = argparse.ArgumentParser(
    description="Scan a directory for secrets, credentials, and sensitive patterns."
)

# positional argument with a default — the directory to scan.
# nargs="?" means "zero or one argument," so it's optional.
parser.add_argument(
    "directory",
    nargs="?",
    default="test_configs",
    help="Path to the directory to scan (default: test_configs/)",
)

# --exit-zero: always exit 0, even when findings exist.
# Useful for informational/audit runs in CI where you want visibility
# without blocking the pipeline (e.g., during initial secret triage).
parser.add_argument(
    "--exit-zero",
    action="store_true",
    help="Always exit with code 0, even if alerts are found (informational mode)",
)

args = parser.parse_args()
folder = Path(args.directory)

# Validate that the path exists and is a directory before scanning.
# Without this check, rglob() on a nonexistent path would raise FileNotFoundError,
# producing a traceback instead of a clear, actionable error message.
if not folder.exists():
    print(f"[ERROR] Path does not exist: {folder}")
    sys.exit(1)

if not folder.is_dir():
    print(f"[ERROR] Path is not a directory: {folder}")
    sys.exit(1)

# Prints a header to let the user know which directory is being scanned.
print(f"Scanning folder: {folder}")

# Counter to track the total number of alerts found across all files in directory.
issues = 0

# A set to store filenames that triggered at least one alert (avoids duplicates).
files_with_issues = set()

skipped_files = 0

# Track unique directories encountered during recursion.
directories_scanned = set()

# Iterates recursively through every file inside directory and its subdirectories.
# is_file() filters out directories — without this, open() would fail on directories
# and they'd be silently skipped, giving a misleading skipped_files count.
for item in folder.rglob("*"):
    if not item.is_file():
        continue

    # Record the parent directory so we can report how deep the scan went.
    directories_scanned.add(item.parent)

    # Build the display path relative to the scan root (e.g., "nested/test.json"
    # instead of just "test.json") so findings in subdirectories are identifiable.
    relative_path = item.relative_to(folder)

    # Opens the file in read mode and loads the entire content into a string.
    try:
        with open(item, "r") as f:
            contents = f.read()
    except UnicodeDecodeError:
        print(f"[SKIP] {relative_path}: The file type is not compatible.")
        skipped_files += 1
        continue
    except PermissionError:
        print(f"[SKIP] {relative_path}: You do not have the necessary permissions for this file.")
        skipped_files += 1
        continue

    # Converts the contents to lowercase for case-insensitive searching
    contents_lower = contents.casefold()

    # Track whether an alert was triggered for a file.
    found_issue = False

    # Check for AWS access key pattern ("AKIA...").
    if "AKIA" in contents:
        print(f'[ALERT] {relative_path}: Found potential AWS key (AKIA...).')
        issues += 1             # Increment total alert count.
        found_issue = True      # Mark that this file has an issue.

    # Check for the word "password" (case-insensitive).
    if "password" in contents_lower:
        print(f'[ALERT] {relative_path}: Found potential "password" pattern.')
        issues += 1
        found_issue = True

    # Check for the word "secret" (case-insensitive).
    if "secret" in contents_lower:
        print(f'[ALERT] {relative_path}: Found potential "secret" pattern.')
        issues += 1
        found_issue = True

    # If any alert was found in a file, record the relative path in the set.
    if found_issue:
        files_with_issues.add(str(relative_path))

# Print summary of the scan results, total number of alerts, and unique affected files.
print("\n--- Scan Summary ---")
print(f"Directories scanned: {len(directories_scanned)}")
print(f"Total alerts: {issues}")
print(f"Files with issues: {len(files_with_issues)}")
print(f"Skipped files: {skipped_files}")

# List the relative paths of affected files so the user knows exactly where to look.
if files_with_issues:
    print("Affected files:")
    for fname in sorted(files_with_issues):
        print(f" - {fname}")

# Exit with a non-zero code when secrets are found so CI/CD pipelines fail.
# Without this, a pipeline step using this scanner would always "pass," meaning
# the scanner enforces nothing — a finding for SA-11 and CM-3.
# --exit-zero overrides this for informational/audit-only runs.
if issues > 0 and not args.exit_zero:
    sys.exit(1)
else:
    sys.exit(0)