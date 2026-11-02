# GODREX01 NMAP Python — Windows Edition

A Windows-friendly, Python-only TCP port scanner that reads targets from a file and exports per-target and consolidated CSV reports.

## Important difference from Nmap

This edition **does not require `nmap.exe`**, but it is not the Nmap engine. It uses Python's built-in `socket` module to test TCP connections and labels common services by port number. It does not provide Nmap's service/version detection, OS fingerprinting, UDP scanning, NSE scripts, or XML output.

## Features

- Runs on Windows with Python; no separate Nmap executable.
- Reads targets from `targets.txt`, ignoring blank lines, comments, and duplicates.
- Supports comma-separated TCP ports and ranges.
- Uses bounded concurrency to scan ports more efficiently.
- Exports individual CSV reports and a consolidated CSV report.
- Includes target, resolved address, port, protocol, state, common service name, and connection time.

## Requirements

- Windows 10/11 (or another OS with Python socket support).
- Python 3.9 or newer recommended.
- No third-party Python packages.

`requirements.txt` is included for project consistency, but it contains no packages to install.

## Project structure

```text
GODREX01-NMAP-Python-Windows/
├── godrex01_nmap_python.py
├── targets.txt
├── requirements.txt
├── README.md
├── .gitignore
└── reports/
    └── .gitkeep
```

## Setup

1. Install Python from https://www.python.org/downloads/windows/ and enable **Add Python to PATH** during setup.
2. Extract the project ZIP.
3. Edit `targets.txt` and add only systems you own or have permission to test.
4. Open Command Prompt or PowerShell in the project folder.

Example `targets.txt`:

```text
# Authorized lab targets only
192.168.1.10
192.168.1.20
localhost
```

## Run

Default scan:

```powershell
python godrex01_nmap_python.py
```

Custom ports:

```powershell
python godrex01_nmap_python.py --ports 22,80,443,8000-8010
```

Custom output folder:

```powershell
python godrex01_nmap_python.py --output scan_reports
```

Set connection timeout and concurrency:

```powershell
python godrex01_nmap_python.py --timeout 1.5 --workers 100
```

Show all options:

```powershell
python godrex01_nmap_python.py --help
```

## Reports

The default `reports/` directory contains:

- One CSV file per target.
- `GODREX01_NMAP_Python_Report.csv`, a combined report.

The CSV files use UTF-8 with a BOM for better compatibility with Excel.

## Limitations

- TCP connect checks only; UDP ports are not scanned.
- A closed or filtered port is omitted from the open-port results.
- A service name is inferred from the port number, not verified through protocol negotiation. For example, port 443 is commonly HTTPS, but the script does not verify TLS or identify the application version.
- Firewalls, routing, host availability, and timeout settings affect results.
- This is not a replacement for full Nmap functionality.

## Authorized use

Only scan hosts and networks for which you have explicit authorization. Scanning may trigger security monitoring or violate acceptable-use rules if performed without permission.

## License

Add a license file before publicly distributing or reusing the project under specific license terms.

**GODREX01 NMAP Python — Windows Edition**
