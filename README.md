# Secret Scanner

A Python tool that scans directories for sensitive content such as AWS access keys, passwords, and secrets. Designed for use in CI/CD pipelines and GRC engineering workflows.

Maps to NIST 800-53 Rev 5 controls: **IA-5(7)**, **SC-12**, **SC-28**.
Maps to CJIS v6.0 controls: **SC-12**, **SC-13**, **SC-28**.

## Features

- Recursively scans all files in a target directory and its subdirectories
- Detects:
  - AWS key patterns (`AKIA`)
  - `"password"` (case-insensitive)
  - `"secret"` (case-insensitive)
- Gracefully skips binary files and permission-denied files
- Reports findings with relative paths for easy identification
- Returns a non-zero exit code when secrets are found (CI/CD integration)
- Supports `--exit-zero` for informational-only runs
- Prints a summary with total alerts, affected files, directories scanned, and skipped files

## Usage

Scan the default `test_configs/` directory:

```bash
python secret_scanner.py
```

Scan a specific directory:

```bash
python secret_scanner.py /path/to/configs
```

Run in informational mode (always exit 0, even if secrets are found):

```bash
python secret_scanner.py /path/to/configs --exit-zero
```

View all options:

```bash
python secret_scanner.py --help
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No secrets found, or `--exit-zero` was used |
| `1`  | Secrets detected (default behavior) |

In a CI/CD pipeline, the non-zero exit code will cause the step to fail, blocking merges that contain exposed secrets.

## Requirements

- Python 3.x (no third-party dependencies)

## License

MIT License
