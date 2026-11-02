#!/usr/bin/env python3
"""
GODREX01 NMAP Python - Windows-friendly Python TCP port scanner.

This edition does not require the Nmap executable. It uses Python sockets
to test TCP connections and identify common services by port number.
It is not the Nmap engine and does not perform Nmap-style version detection.
Use only against systems you own or have explicit permission to assess.
"""

import argparse
import concurrent.futures
import csv
import hashlib
import ipaddress
import socket
import sys
import time
from pathlib import Path

DEFAULT_TARGETS_FILE = "targets.txt"
DEFAULT_OUTPUT_DIR = "reports"
DEFAULT_PORTS = (
    "21-23,25,53,80,110,143,443,445,993,995,"
    "3306,3389,5432,8080,8443"
)
CSV_FIELDS = ["Target", "Address", "Port", "Protocol", "State", "Service", "Response Time (ms)"]


def parse_args():
    parser = argparse.ArgumentParser(
        prog="godrex01_nmap_python",
        description="GODREX01 NMAP Python - Python-only TCP port scanner (no Nmap executable).",
    )
    parser.add_argument("-i", "--input", default=DEFAULT_TARGETS_FILE,
                        help="Target list file (default: targets.txt)")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_DIR,
                        help="Output directory (default: reports)")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS,
                        help="TCP ports/ranges, e.g. 22,80,443,8000-8010")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout per port in seconds (default: 1.0)")
    parser.add_argument("--workers", type=int, default=100,
                        help="Maximum concurrent TCP connection attempts (default: 100)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")
    if not 1 <= args.workers <= 1000:
        parser.error("--workers must be between 1 and 1000.")
    return args


def parse_ports(spec):
    """Parse a comma-separated list of ports and port ranges."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            pieces = part.split("-", 1)
            if len(pieces) != 2:
                raise ValueError(f"Invalid port range: {part}")
            start, end = map(int, pieces)
            if start > end:
                raise ValueError(f"Invalid port range: {part}")
            if start < 1 or end > 65535:
                raise ValueError(f"Ports must be between 1 and 65535: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port must be between 1 and 65535: {port}")
            ports.add(port)
    if not ports:
        raise ValueError("No valid ports were supplied.")
    return sorted(ports)


def read_targets(filename):
    """Read target lines, ignoring comments and duplicates."""
    path = Path(filename)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    targets, seen = [], set()
    with path.open("r", encoding="utf-8-sig") as file:
        for line in file:
            target = line.split("#", 1)[0].strip()
            if target and target not in seen:
                targets.append(target)
                seen.add(target)
    if not targets:
        raise ValueError(f"No targets found in {path}")
    return targets


def safe_filename(value):
    slug = "".join(c if c.isalnum() or c in ".-_" else "_" for c in value)
    slug = slug.strip("._-")[:55] or "target"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"{slug}_{digest}"


def resolve_target(target):
    """Resolve hostname/IP and return a printable address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve {target}: {exc}") from exc


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(target, address, port, timeout):
    """Perform a TCP connect check for one port."""
    started = time.perf_counter()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            elapsed = (time.perf_counter() - started) * 1000
            return {
                "Target": target,
                "Address": address,
                "Port": port,
                "Protocol": "tcp",
                "State": "open",
                "Service": service_name(port),
                "Response Time (ms)": f"{elapsed:.2f}",
            }
    except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError):
        return None


def write_csv(path, rows):
    try:
        with path.open("w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] CSV report saved: {path}")
        return True
    except OSError as exc:
        print(f"[!] Could not write {path}: {exc}")
        return False


def scan_target(target, ports, timeout, workers):
    try:
        address = resolve_target(target)
    except ValueError as exc:
        print(f"[!] {exc}")
        return None

    print(f"[*] Scanning {target} ({address}) across {len(ports)} TCP ports...")
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, target, address, port, timeout): port
            for port in ports
        }
        try:
            for future in concurrent.futures.as_completed(futures):
                row = future.result()
                if row:
                    rows.append(row)
                    print(f"    [+] {row['Port']}/tcp open - {row['Service']}")
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            raise

    rows.sort(key=lambda row: int(row["Port"]))
    if not rows:
        rows.append({
            "Target": target,
            "Address": address,
            "Port": "",
            "Protocol": "tcp",
            "State": "No open TCP ports found",
            "Service": "",
            "Response Time (ms)": "",
        })
    return rows


def main():
    args = parse_args()
    print("=" * 60)
    print("              GODREX01 NMAP PYTHON")
    print("     Python-only TCP scanner for Windows")
    print("       Authorized Security Testing Only")
    print("=" * 60)

    try:
        targets = read_targets(args.input)
        ports = parse_ports(args.ports)
    except (OSError, ValueError) as exc:
        print(f"[!] {exc}")
        return 1

    output_dir = Path(args.output)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"[!] Cannot create output directory: {exc}")
        return 1

    print(f"[*] Targets: {len(targets)} | TCP ports: {len(ports)}")
    print(f"[*] Timeout: {args.timeout}s | Workers: {args.workers}")
    print(f"[*] Output: {output_dir.resolve()}")

    all_rows, failed = [], 0
    interrupted = False
    try:
        for index, target in enumerate(targets, start=1):
            print(f"\n[{index}/{len(targets)}] {target}")
            rows = scan_target(target, ports, args.timeout, args.workers)
            if rows is None:
                failed += 1
                continue
            all_rows.extend(rows)
            write_csv(output_dir / f"{safe_filename(target)}.csv", rows)
    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] Interrupted. Saving results collected so far...")

    master = output_dir / "GODREX01_NMAP_REPORT.csv"
    saved = write_csv(master, all_rows)
    open_count = sum(row["State"] == "open" for row in all_rows)

    print("\n" + "=" * 60)
    print("                 GODREX01 SUMMARY")
    print("=" * 60)
    print(f"Targets loaded: {len(targets)}")
    print(f"Targets failed: {failed}")
    print(f"Open TCP ports: {open_count}")
    print(f"Output folder:  {output_dir.resolve()}")
    print("=" * 60)
    return 130 if interrupted else (0 if failed == 0 and saved else 1)


if __name__ == "__main__":
    sys.exit(main())
