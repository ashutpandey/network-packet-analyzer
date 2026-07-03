#!/usr/bin/env python3
"""
Basic Network Port Scanner
---------------------------
A simple CLI-based TCP port scanner using Python sockets.

Features:
  - Resolves hostnames to IP addresses (DNS resolution)
  - Multithreaded scanning for speed
  - Detects open ports
  - Attempts basic service banner grabbing on open ports

Intended for diagnosing your own systems/networks or systems you have
explicit permission to test. Do not scan hosts you don't own or lack
authorization to test.

Usage:
    python3 port_scanner.py <target> [-p PORTS] [-t THREADS] [--timeout SECONDS]

Examples:
    python3 port_scanner.py example.com
    python3 port_scanner.py 192.168.1.1 -p 1-1024
    python3 port_scanner.py scanme.nmap.org -p 22,80,443,8080 -t 200
"""

import argparse
import socket
import sys
import threading
import queue
import time
from datetime import datetime


# A tiny map of well-known ports -> service name, used as a fallback
# label when a banner can't be grabbed.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def parse_ports(port_str):
    """Parse a port spec like '80', '1-1024', or '22,80,443,8000-8010'."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def resolve_target(target):
    """Resolve a hostname to an IP address. Returns (ip, hostname_or_None)."""
    try:
        ip = socket.gethostbyname(target)
        return ip, target if ip != target else None
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)


def grab_banner(sock):
    """Try to read a service banner from an already-connected socket."""
    try:
        sock.settimeout(1.0)
        banner = sock.recv(1024)
        if banner:
            return banner.decode(errors="replace").strip().split("\n")[0][:80]
    except (socket.timeout, ConnectionResetError, OSError):
        pass
    return ""


def probe_http(sock):
    """Send a minimal HTTP request to encourage a banner/response on web ports."""
    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        sock.settimeout(1.0)
        data = sock.recv(1024)
        if data:
            first_line = data.decode(errors="replace").split("\r\n")[0]
            return first_line.strip()[:80]
    except (socket.timeout, ConnectionResetError, OSError):
        pass
    return ""


def scan_port(ip, port, timeout, results, lock, print_live):
    """Attempt to connect to a single port; record and optionally print result."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(sock)
                if not banner and port in (80, 8080, 443, 8443):
                    banner = probe_http(sock)
                service = COMMON_PORTS.get(port, "unknown")
                with lock:
                    results[port] = {"service": service, "banner": banner}
                    if print_live:
                        label = banner if banner else service
                        print(f"[+] Port {port:<5} OPEN   ({label})")
    except (socket.timeout, OSError):
        pass


def worker(ip, timeout, results, lock, print_live, work_queue):
    while True:
        try:
            port = work_queue.get_nowait()
        except queue.Empty:
            return
        scan_port(ip, port, timeout, results, lock, print_live)
        work_queue.task_done()


def run_scan(target, ports, threads, timeout, quiet=False):
    ip, hostname = resolve_target(target)

    print("=" * 60)
    print(f"Target:      {target}" + (f"  ({ip})" if hostname else ""))
    print(f"Ports:       {ports[0]}-{ports[-1]}  ({len(ports)} total)")
    print(f"Threads:     {threads}")
    print(f"Started at:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    results = {}
    lock = threading.Lock()
    work_queue = queue.Queue()
    for port in ports:
        work_queue.put(port)

    start = time.time()
    thread_list = []
    for _ in range(min(threads, len(ports)) or 1):
        t = threading.Thread(
            target=worker,
            args=(ip, timeout, results, lock, not quiet, work_queue),
            daemon=True,
        )
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    elapsed = time.time() - start

    print("-" * 60)
    if results:
        print(f"Open ports on {ip}:")
        for port in sorted(results):
            info = results[port]
            label = info["banner"] if info["banner"] else info["service"]
            print(f"  {port:<6} {info['service']:<12} {label}")
    else:
        print("No open ports found.")
    print(f"\nScan completed in {elapsed:.2f} seconds.")
    print("=" * 60)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Basic multithreaded TCP port scanner.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan, e.g. '80', '1-1024', '22,80,443,8000-8010'"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of concurrent threads"
    )
    parser.add_argument(
        "--timeout", type=float, default=0.5,
        help="Per-connection timeout in seconds"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress live output; only show the final summary"
    )
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"[!] Invalid port specification: {args.ports}")
        sys.exit(1)

    if not ports:
        print("[!] No valid ports to scan.")
        sys.exit(1)

    try:
        run_scan(args.target, ports, args.threads, args.timeout, args.quiet)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
