"""
secret_scanner.py

This script loads a JSON file and checks for sensitive information such as:
- AWS credentials
- API keys
- Database credentials
"""

# Importing the Path class from the pathlib module
from pathlib import Path

# Variable to define the directory containing the files that need to be scanned.
folder = Path("test_configs")

# Prints a header to let the user know which directory is being scanned.
print(f"Scanning folder: {folder}")

# Counter to track the total number of alerts found across all files in directory.
issues = 0

# A set to store filenames that triggered at least one alert (avoids duplicates).
files_with_issues = set()

skipped_files = 0

# Iterates through every file inside directory. 
for item in folder.iterdir():
    # Opens the file in read mode and loads the entire content into a string.
    try:
        with open(item, "r") as f:
            contents = f.read()
    except UnicodeDecodeError:
        print(f"[SKIP] {item.name}: The file type is not compatible.")
        skipped_files += 1
        continue
    except PermissionError:
        print(f"[SKIP] {item.name}: You do not have the necessary permissions for this file.")
        skipped_files += 1
        continue

    # Converts the contents to lowercase for case-insensitive searching
    contents_lower = contents.casefold()

    # Track whether an alert was triggered for a file.
    found_issue = False

    # Check for AWS access key pattern ("AKIA...").
    if "AKIA" in contents:
        print(f'[ALERT] {item.name}: Found potential AWS key (AKIA...).')
        issues += 1             # Increment total alert count.
        found_issue = True      # Mark that this file has an issue.

    # Check for the word "password" (case-insensitive).
    if "password" in contents_lower:
        print(f'[ALERT] {item.name}: Found potential "password" pattern.')
        issues += 1
        found_issue = True

    # Check for the word "secret" (case-insensitive).
    if "secret" in contents_lower:
        print(f'[ALERT] {item.name}: Found potential "secret" pattern.')
        issues += 1
        found_issue = True

    # If any alert was found in a file, record the filename in the set.
    if found_issue:
        files_with_issues.add(item.name)

# Print summary of the scan results, total number of alerts, and unique affected files.
print("\n--- Scan Summary ---")
print(f"Total alerts: {issues}")
print(f"Files with issues: {len(files_with_issues)}")
print(f"Skipped files: {skipped_files}")

# List the filenames of affected files. 
if files_with_issues:
    print("Affected files:")
    for fname in sorted(files_with_issues):
        print(f" - {fname}")