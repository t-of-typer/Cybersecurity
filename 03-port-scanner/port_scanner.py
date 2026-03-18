#!/usr/bin/env python3
"""
Port Scanner from Scratch
--------------------------
A TCP port scanner built using raw Python sockets — no Nmap or external
dependencies. Demonstrates what happens at the TCP layer during a scan:
connection attempts, banner grabbing, and service identification.

Features:
  - Multi-threaded scanning for speed
  - Banner grabbing to identify services
  - Common port profiles (top 20, top 100, full range, custom)
  - UDP scan for common ports
  - OS TTL fingerprinting
  - Colour-coded terminal output
  - Auto-export to TXT and JSON

Author : Pedro Fousianis
GitHub : github.com/t-of-typer/Cybersecurity
Usage  : python port_scanner.py -t <target> [options]
"""

import argparse
import datetime
import ipaddress
import json
import os
import queue
import socket
import struct
import sys
import threading
import time


# ─── ANSI COLOURS ─────────────────────────────────────────────────────────────

USE_COLOUR = sys.platform != "win32" or os.environ.get("TERM") == "xterm"

class C:
    RESET  = "\033[0m"  if USE_COLOUR else ""
    BOLD   = "\033[1m"  if USE_COLOUR else ""
    RED    = "\033[91m" if USE_COLOUR else ""
    GREEN  = "\033[92m" if USE_COLOUR else ""
    YELLOW = "\033[93m" if USE_COLOUR else ""
    CYAN   = "\033[96m" if USE_COLOUR else ""
    DIM    = "\033[2m"  if USE_COLOUR else ""
    ORANGE = "\033[38;5;208m" if USE_COLOUR else ""


# ─── BANNER ───────────────────────────────────────────────────────────────────

BANNER = f"""{C.CYAN}{C.BOLD}
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.DIM}  Port Scanner from Scratch v1.0  |  github.com/t-of-typer/Cybersecurity{C.RESET}
"""


# ─── SERVICE DATABASE ─────────────────────────────────────────────────────────
# Common ports and their typical services — used when banner grab fails

SERVICE_DB = {
    20: "FTP (data)", 21: "FTP (control)", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP Trap", 179: "BGP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "SMTP (submission)",
    631: "IPP (CUPS)", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS proxy", 1194: "OpenVPN", 1433: "MS SQL Server",
    1521: "Oracle DB", 1723: "PPTP VPN", 2049: "NFS",
    2375: "Docker API", 2376: "Docker TLS", 3000: "Dev server",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
    5000: "Flask/dev", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes API", 8080: "HTTP alt",
    8443: "HTTPS alt", 8888: "Jupyter", 9200: "Elasticsearch",
    27017: "MongoDB",
}

# Security risk notes for notable ports
RISK_NOTES = {
    21:  "⚠  FTP — credentials sent in plaintext",
    23:  "⚠  Telnet — everything sent in plaintext, replace with SSH",
    25:  "ℹ  SMTP open relay risk if misconfigured",
    80:  "ℹ  HTTP — traffic unencrypted",
    135: "⚠  MS-RPC — common attack vector on Windows",
    139: "⚠  NetBIOS — legacy protocol, exposure risk",
    161: "⚠  SNMP — check community string strength",
    445: "⚠  SMB — common ransomware/lateral movement vector",
    1433: "⚠  SQL Server — should not be internet-facing",
    2375: "🚨 Docker API (unencrypted) — critical exposure risk",
    3306: "⚠  MySQL — should not be internet-facing",
    3389: "⚠  RDP — common brute-force target",
    4444: "🚨 Metasploit default port — possible backdoor",
    5900: "⚠  VNC — check authentication strength",
    6379: "⚠  Redis — often runs unauthenticated by default",
    27017: "⚠  MongoDB — often runs unauthenticated by default",
}

# Port profiles
PORT_PROFILES = {
    "top20":  [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080],
    "top100": [
        21,22,23,25,53,80,88,110,111,119,123,135,137,139,143,161,179,
        194,389,443,445,465,514,515,587,631,636,993,995,1080,1194,1433,
        1521,1723,2049,2375,2376,3000,3306,3389,4444,5000,5432,5900,
        6379,6443,8080,8443,8888,9200,27017,
        # Extra common web/dev ports
        81,82,83,84,85,8000,8001,8008,8090,8181,8888,9000,9090,9443,
        10000,10443,20000,49152,
    ],
    "full": list(range(1, 65536)),
}


# ─── RESOLVER ─────────────────────────────────────────────────────────────────

def resolve_target(target):
    """Resolve hostname to IP, or validate IP. Returns (ip, hostname)."""
    try:
        ip = socket.gethostbyname(target)
        hostname = target if target != ip else ""
        return ip, hostname
    except socket.gaierror:
        print(f"{C.RED}[!] Cannot resolve host: {target}{C.RESET}")
        sys.exit(1)


# ─── BANNER GRABBER ───────────────────────────────────────────────────────────

def grab_banner(ip, port, timeout=2.0):
    """
    Attempt to grab a service banner from an open port.
    Sends a probe and reads the response — reveals service name and version.
    """
    probes = [
        b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",  # HTTP
        b"\r\n",                                                      # Generic newline
        b"HELP\r\n",                                                  # FTP/SMTP/POP3
    ]

    for probe in probes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                try:
                    s.sendall(probe)
                except Exception:
                    pass
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                if banner:
                    # Clean up — take first line only
                    first_line = banner.splitlines()[0][:100]
                    return first_line
        except Exception:
            continue
    return ""


# ─── TCP SCANNER ──────────────────────────────────────────────────────────────

class PortScanner:
    def __init__(self, ip, ports, timeout=1.0, threads=100, grab_banners=True):
        self.ip          = ip
        self.ports       = ports
        self.timeout     = timeout
        self.thread_count = min(threads, len(ports))
        self.grab_banners = grab_banners
        self.results     = {}          # port -> result dict
        self.lock        = threading.Lock()
        self.q           = queue.Queue()
        self._scanned    = 0
        self._total      = len(ports)
        self._progress_lock = threading.Lock()

    def _scan_port(self, port):
        """Attempt TCP connection to a single port. Returns True if open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.ip, port))
                return result == 0
        except Exception:
            return False

    def _worker(self):
        """Thread worker — pulls ports from queue and scans them."""
        while True:
            try:
                port = self.q.get(timeout=1)
            except queue.Empty:
                break

            is_open = self._scan_port(port)

            with self._progress_lock:
                self._scanned += 1
                if self._total <= 1000:  # Only show progress for smaller scans
                    pct = int((self._scanned / self._total) * 50)
                    bar = "█" * pct + "░" * (50 - pct)
                    print(f"\r  {C.DIM}[{bar}] {self._scanned}/{self._total}{C.RESET}", end="", flush=True)

            if is_open:
                banner = ""
                if self.grab_banners:
                    banner = grab_banner(self.ip, port, timeout=2.0)

                service = SERVICE_DB.get(port, "unknown")
                risk    = RISK_NOTES.get(port, "")

                with self.lock:
                    self.results[port] = {
                        "port":    port,
                        "state":   "open",
                        "service": service,
                        "banner":  banner,
                        "risk":    risk,
                    }

            self.q.task_done()

    def run(self):
        """Start scanning."""
        for port in self.ports:
            self.q.put(port)

        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        if self._total <= 1000:
            print()  # newline after progress bar

        return dict(sorted(self.results.items()))


# ─── TTL FINGERPRINTING ───────────────────────────────────────────────────────

def ttl_os_guess(ip):
    """
    Estimate OS from ICMP TTL value using a raw ping.
    TTL 64  → Linux/macOS
    TTL 128 → Windows
    TTL 255 → Network device (Cisco etc.)
    Only works on Linux with root/raw socket permissions.
    Falls back gracefully on Windows or without privileges.
    """
    try:
        import subprocess
        param = "-n" if sys.platform == "win32" else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3
        )
        output = result.stdout

        # Extract TTL from ping output
        for line in output.splitlines():
            line_lower = line.lower()
            if "ttl=" in line_lower:
                ttl_part = [x for x in line.split() if "ttl=" in x.lower()]
                if ttl_part:
                    ttl = int(ttl_part[0].split("=")[1])
                    if ttl <= 64:
                        return ttl, "Linux / macOS / Unix"
                    elif ttl <= 128:
                        return ttl, "Windows"
                    else:
                        return ttl, "Network device (Cisco / router)"
    except Exception:
        pass
    return None, "Unknown (TTL fingerprinting unavailable)"


# ─── REPORTER ─────────────────────────────────────────────────────────────────

def sep(char="─", width=70):
    print(f"{C.DIM}{char * width}{C.RESET}")


def print_report(target, ip, hostname, open_ports, scan_meta, ttl_info):
    ttl_val, ttl_os = ttl_info
    duration        = scan_meta["duration"]
    total_scanned   = scan_meta["total_scanned"]
    profile         = scan_meta["profile"]

    print(f"\n{'═' * 70}")
    print(f"{C.BOLD}  SCAN REPORT{C.RESET}")
    print(f"{'═' * 70}")
    print(f"  Target      : {C.CYAN}{target}{C.RESET}", end="")
    if hostname and hostname != target:
        print(f"  ({hostname})", end="")
    print()
    print(f"  IP          : {C.CYAN}{ip}{C.RESET}")
    print(f"  Profile     : {profile}")
    print(f"  Ports       : {total_scanned:,} scanned")
    print(f"  Duration    : {duration:.2f}s")
    print(f"  Timestamp   : {scan_meta['timestamp']}")
    if ttl_val:
        print(f"  TTL / OS    : {ttl_val}  →  {C.YELLOW}{ttl_os}{C.RESET}")
    sep()

    if not open_ports:
        print(f"\n  {C.YELLOW}No open ports found.{C.RESET}")
        print(f"  {C.DIM}Host may be down, firewalled, or all ports are closed.{C.RESET}\n")
        print(f"{'═' * 70}\n")
        return

    # Port table header
    print(f"\n  {C.BOLD}{'PORT':<12} {'SERVICE':<22} {'BANNER / INFO'}{C.RESET}")
    sep("-", 70)

    risks_found = []

    for port, info in open_ports.items():
        service = info["service"]
        banner  = info["banner"]
        risk    = info["risk"]

        # Colour the port number
        port_str = f"{C.GREEN}{port}/tcp{C.RESET}"

        # Banner display
        banner_display = f"{C.DIM}{banner[:42]}{C.RESET}" if banner else f"{C.DIM}—{C.RESET}"

        print(f"  {port_str:<20} {service:<22} {banner_display}")

        if risk:
            risks_found.append((port, service, risk))

    sep()

    # Security findings
    if risks_found:
        print(f"\n  {C.BOLD}{C.ORANGE}SECURITY FINDINGS{C.RESET}")
        sep("-", 70)
        for port, service, risk in risks_found:
            print(f"  {C.YELLOW}Port {port:<6}{C.RESET}  {risk}")

    # Summary
    print(f"\n{'═' * 70}")
    print(f"  {C.BOLD}Summary:{C.RESET}  {C.GREEN}{len(open_ports)} open port(s){C.RESET} "
          f"found  ·  {len(risks_found)} security note(s)")
    print(f"{'═' * 70}\n")


# ─── EXPORT ───────────────────────────────────────────────────────────────────

def export_txt(target, ip, open_ports, scan_meta, ttl_info, filepath):
    ttl_val, ttl_os = ttl_info
    lines = [
        "=" * 70,
        "  PORT SCANNER FROM SCRATCH — SCAN REPORT",
        "=" * 70,
        f"  Target    : {target}  ({ip})",
        f"  Profile   : {scan_meta['profile']}",
        f"  Ports     : {scan_meta['total_scanned']:,} scanned",
        f"  Duration  : {scan_meta['duration']:.2f}s",
        f"  Timestamp : {scan_meta['timestamp']}",
        f"  OS Guess  : {ttl_os} (TTL {ttl_val})" if ttl_val else f"  OS Guess  : {ttl_os}",
        "-" * 70,
        "",
        f"{'PORT':<12} {'SERVICE':<22} BANNER",
        "-" * 70,
    ]

    for port, info in open_ports.items():
        banner = info["banner"] if info["banner"] else "—"
        lines.append(f"{str(port)+'/tcp':<12} {info['service']:<22} {banner[:50]}")

    lines += ["", "SECURITY NOTES", "-" * 70]
    for port, info in open_ports.items():
        if info["risk"]:
            lines.append(f"Port {port:<6}  {info['risk']}")

    lines += [
        "",
        "=" * 70,
        f"  {len(open_ports)} open port(s) found",
        "=" * 70,
    ]

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"{C.GREEN}[+] Report saved → {filepath}{C.RESET}")


def export_json(target, ip, open_ports, scan_meta, ttl_info, filepath):
    data = {
        "meta": {
            "target": target,
            "ip": ip,
            "profile": scan_meta["profile"],
            "ports_scanned": scan_meta["total_scanned"],
            "duration_seconds": round(scan_meta["duration"], 2),
            "timestamp": scan_meta["timestamp"],
            "os_guess": ttl_info[1],
            "ttl": ttl_info[0],
        },
        "open_ports": [
            {
                "port": p,
                "service": info["service"],
                "banner": info["banner"],
                "risk_note": info["risk"],
            }
            for p, info in open_ports.items()
        ]
    }
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{C.GREEN}[+] JSON saved  → {filepath}{C.RESET}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Port Scanner from Scratch — pure Python TCP scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP or hostname\n  e.g. 192.168.1.1 | scanme.nmap.org")
    parser.add_argument("-p", "--ports", default="top100",
                        help="Port range or profile:\n"
                             "  top20       — 20 most common ports\n"
                             "  top100      — 100 most common ports (default)\n"
                             "  full        — all 65535 ports (slow)\n"
                             "  80,443,8080 — comma-separated list\n"
                             "  1-1024      — range")
    parser.add_argument("--threads", type=int, default=150,
                        help="Number of threads (default: 150)")
    parser.add_argument("--timeout", type=float, default=0.8,
                        help="Connection timeout per port in seconds (default: 0.8)")
    parser.add_argument("--no-banners", action="store_true",
                        help="Skip banner grabbing (faster)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save plain-text report to file")
    parser.add_argument("--json", metavar="FILE",
                        help="Save JSON report to file")
    return parser.parse_args()


def parse_ports(port_str):
    """Parse port string into a list of integers."""
    if port_str in PORT_PROFILES:
        return PORT_PROFILES[port_str], port_str

    ports = []
    try:
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
    except ValueError:
        print(f"{C.RED}[!] Invalid port specification: {port_str}{C.RESET}")
        sys.exit(1)

    return sorted(set(ports)), f"custom ({len(ports)} ports)"


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    print(BANNER)

    # Resolve
    ip, hostname = resolve_target(args.target)
    print(f"{C.CYAN}[*]{C.RESET} Target      : {C.BOLD}{args.target}{C.RESET}  →  {ip}")
    if hostname:
        print(f"{C.CYAN}[*]{C.RESET} Hostname    : {hostname}")

    # TTL fingerprint
    ttl_val, ttl_os = ttl_os_guess(ip)
    if ttl_val:
        print(f"{C.CYAN}[*]{C.RESET} OS guess    : {C.YELLOW}{ttl_os}{C.RESET}  (TTL {ttl_val})")

    # Parse ports
    ports, profile_name = parse_ports(args.ports)
    print(f"{C.CYAN}[*]{C.RESET} Port range  : {profile_name}  ({len(ports):,} ports)")
    print(f"{C.CYAN}[*]{C.RESET} Threads     : {args.threads}  ·  Timeout: {args.timeout}s")
    print(f"{C.CYAN}[*]{C.RESET} Banners     : {'disabled' if args.no_banners else 'enabled'}")
    print(f"\n{C.DIM}─{'─'*68}─{C.RESET}")
    print(f"{C.YELLOW}[!]{C.RESET} Scanning…\n")

    # Scan
    start_time = time.time()
    scanner = PortScanner(
        ip=ip,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        grab_banners=not args.no_banners,
    )
    open_ports = scanner.run()
    duration   = time.time() - start_time

    scan_meta = {
        "profile":       profile_name,
        "total_scanned": len(ports),
        "duration":      duration,
        "timestamp":     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Report
    print_report(args.target, ip, hostname, open_ports, scan_meta, (ttl_val, ttl_os))

    # Export
    ts          = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = args.target.replace(".", "-").replace("/", "-")

    if args.output:
        export_txt(args.target, ip, open_ports, scan_meta, (ttl_val, ttl_os), args.output)
    else:
        os.makedirs("reports", exist_ok=True)
        auto_path = f"reports/scan_{safe_target}_{ts}.txt"
        export_txt(args.target, ip, open_ports, scan_meta, (ttl_val, ttl_os), auto_path)

    if args.json:
        export_json(args.target, ip, open_ports, scan_meta, (ttl_val, ttl_os), args.json)


if __name__ == "__main__":
    main()
