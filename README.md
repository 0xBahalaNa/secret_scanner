# secret_scanner.py

A simple Python tool that scans all files in a folder for potentially sensitive content such as AWS access keys, passwords, or secrets. Alerts are printed as they’re found, followed by a summary report.

## Features
- Scans every file in a target directory  
- Detects:
  - AWS key pattern (`AKIA`)
  - `"password"` (case-insensitive)
  - `"secret"` (case-insensitive)
- Counts total alerts
- Tracks which files had issues (via a `set`)
- Prints a clean summary at the end

## Usage
1. `git clone` this repository
2. Place files inside the `test_configs` directory (there are test config files currently)
3. Run the script:

```
python secret_scanner.py
```

## Requirements 
- Python 3.x

## License
- MIT License 
