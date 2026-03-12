"""
secret_scanner.py

This script scans a directory for sensitive information such as:
- AWS credentials (Access Key IDs, Secret Keys, Session Tokens)
- API keys and generic secrets
- Database credentials and connection strings
- Private key files (PEM headers)
- JWT tokens

Detection uses compiled regex patterns instead of simple substring matching.
This reduces false positives (a comment mentioning 'password' won't trigger)
and catches more secret types with precise pattern matching.

Usage:
    python secret_scanner.py [directory] [--exit-zero] [--patterns FILE]

If no directory is provided, defaults to test_configs/.
"""

import argparse
import json
import re
import sys
from pathlib import Path


def load_default_patterns():
    """Return the built-in detection patterns as a dict of {name: compiled regex}.

    Each pattern targets a specific secret type. Using re.compile() pre-compiles
    the regex into an internal representation once, so it doesn't need to be
    re-parsed for every line of every file. This is a performance best practice
    when the same pattern is reused many times (see: docs.python.org/3/library/re.html).

    Pattern design philosophy: require an assignment context (= or :) where possible.
    This means 'password' in a comment won't trigger, but 'password = hunter2' will.
    This is the single biggest false-positive reduction vs. substring matching.
    """
    return {
        # Matches AWS Access Key IDs: literal "AKIA" followed by exactly 16
        # uppercase letters or digits. This is the documented AWS key format.
        "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),

        # Matches AWS Secret Access Keys: the key name (aws_secret_access_key
        # or secret_key) followed by an assignment operator and a 40-character
        # base64 string. The (?i) flag makes it case-insensitive inline.
        "AWS Secret Access Key": re.compile(
            r"(?i)(aws_secret_access_key|secret_key)\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}"
        ),

        # Matches AWS Session Tokens assigned to the standard variable name.
        # Session tokens are long base64 strings (typically 100+ chars), so we
        # require at least 16 characters after the assignment.
        "AWS Session Token": re.compile(
            r"(?i)aws_session_token\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{16,}"
        ),

        # Matches password assignments: the keyword (password, passwd, or pwd)
        # followed by = or : and a non-whitespace value. Requires an assignment
        # operator so that comments like "# never store passwords" don't trigger.
        # The optional ["'] before [=:] handles JSON keys like "password": "value"
        # where a closing quote sits between the keyword and the colon.
        "Password Assignment": re.compile(
            r"(?i)(password|passwd|pwd)[\"']?\s*[=:]\s*[\"']?\S+"
        ),

        # Matches secret assignments: similar logic to password — requires a value
        # after the assignment. Catches patterns like secret = "abc123" or
        # secret_key: some_value. Excludes bare mentions of "secret" in comments.
        # Same optional quote handling as password for JSON compatibility.
        "Secret Assignment": re.compile(
            r"(?i)(secret|secret_key)[\"']?\s*[=:]\s*[\"']?\S+"
        ),

        # Matches API key assignments using common variable naming conventions:
        # api_key, apikey, or api-key followed by an assignment and value.
        "API Key": re.compile(
            r"(?i)(api_key|apikey|api-key)\s*[=:]\s*[\"']?\S+"
        ),

        # Matches PEM-encoded private key headers. These should never appear in
        # config files or repos — a private key in source code is an immediate
        # IA-5(7) finding (no embedded unencrypted static authenticators).
        "Private Key Header": re.compile(
            r"-----BEGIN\s+(RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),

        # Matches JWT tokens. JWTs always start with "eyJ" (base64 for '{"')
        # followed by two dot-separated base64url segments. The minimum segment
        # length of 10 chars avoids matching short strings that happen to
        # start with "eyJ".
        "JWT Token": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),

        # Matches connection strings with embedded credentials, e.g.:
        # postgresql://admin:s3cret@db.example.com:5432/mydb
        # The pattern requires scheme://user:password@host format.
        "Connection String": re.compile(
            r"[\w+]+://[^/\s:]+:[^/\s@]+@[^/\s]+"
        ),
    }


def load_custom_patterns(patterns_file):
    """Load additional patterns from a JSON file and return as compiled regexes.

    The JSON file should be a flat dict of {"pattern_name": "regex_string"}.
    Example:
        {
            "Slack Token": "xox[baprs]-[0-9a-zA-Z-]{10,}",
            "GitHub PAT": "ghp_[A-Za-z0-9]{36}"
        }

    This uses json.load() to parse the file (PCC3e Ch 10: Files and Exceptions),
    then re.compile() on each value to turn the raw strings into pattern objects.

    Args:
        patterns_file: Path to the JSON patterns file.

    Returns:
        A dict of {name: compiled regex} for the custom patterns.

    Raises:
        SystemExit: If the file can't be read, isn't valid JSON, or contains
            invalid regex. A compliance tool must fail loudly — silent skipping
            would mean secrets go undetected (an IA-5(7) gap).
    """
    path = Path(patterns_file)

    if not path.exists():
        print(f"[ERROR] Patterns file does not exist: {path}")
        sys.exit(1)

    try:
        with open(path, "r") as f:
            raw_patterns = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in patterns file {path}: {e}")
        sys.exit(1)

    if not isinstance(raw_patterns, dict):
        print(f"[ERROR] Patterns file must contain a JSON object (dict), got {type(raw_patterns).__name__}")
        sys.exit(1)

    compiled = {}
    for name, regex_string in raw_patterns.items():
        try:
            compiled[name] = re.compile(regex_string)
        except re.error as e:
            # re.error is raised when a regex string has invalid syntax.
            # We fail hard here rather than skipping — a broken pattern means
            # a class of secrets would go undetected.
            print(f"[ERROR] Invalid regex for pattern '{name}': {e}")
            sys.exit(1)

    return compiled


# --- Argument parsing ---
# argparse replaces manual sys.argv parsing. It handles --help automatically,
# validates inputs, and makes adding new flags straightforward.
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

# --patterns: load additional detection patterns from a JSON file.
# This supports customization for different compliance contexts — e.g., a CJIS
# team might add ORI number patterns, while a PCI team adds card number patterns.
# Custom patterns are merged with (not replacing) the built-in defaults.
parser.add_argument(
    "--patterns",
    metavar="FILE",
    help="Path to a JSON file with additional detection patterns ({name: regex})",
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

# --- Build the pattern set ---
# Start with built-in patterns, then merge any custom patterns from --patterns.
# Using a dict means custom patterns with the same name as a built-in will
# override the built-in — this is intentional, allowing users to refine defaults.
patterns = load_default_patterns()

if args.patterns:
    custom = load_custom_patterns(args.patterns)
    print(f"Loaded {len(custom)} custom pattern(s) from {args.patterns}")
    patterns.update(custom)

print(f"Scanning folder: {folder}")
print(f"Active patterns: {len(patterns)}")

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

    # Track whether any alert was triggered for this file.
    found_issue = False

    # Read the file line-by-line using enumerate() so we can report exact
    # line numbers. enumerate(f, start=1) yields (line_number, line_text)
    # pairs — this is more Pythonic than maintaining a manual counter.
    # Line-level reporting satisfies AU-3 (Content of Audit Records):
    # analysts need to know exactly where a finding is, not just which file.
    try:
        with open(item, "r") as f:
            for line_number, line in enumerate(f, start=1):
                # Loop over every pattern and check if it matches this line.
                # This replaces the old three separate if-blocks. Adding a new
                # secret type now means adding one line to PATTERNS — the scan
                # loop doesn't change. This is the Open/Closed Principle in
                # practice: open for extension, closed for modification.
                for pattern_name, pattern_regex in patterns.items():
                    if pattern_regex.search(line):
                        print(
                            f"[ALERT] {relative_path}:{line_number} "
                            f"— {pattern_name}"
                        )
                        issues += 1
                        found_issue = True

    except UnicodeDecodeError:
        print(f"[SKIP] {relative_path}: The file type is not compatible.")
        skipped_files += 1
        continue
    except PermissionError:
        print(f"[SKIP] {relative_path}: You do not have the necessary permissions for this file.")
        skipped_files += 1
        continue

    # If any alert was found in this file, record the relative path in the set.
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
