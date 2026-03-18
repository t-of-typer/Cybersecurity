#!/usr/bin/env python3
"""
Network Recon Toolkit
---------------------
A Python-based network reconnaissance tool that wraps Nmap to perform
host discovery, port scanning, and service/OS detection — then generates
a clean, readable report in both terminal and text file formats.

Author : Pedro Fousianis
GitHub : github.com/t_of_typer
Usage  : python3 recon_toolkit.py -t <target> [options]
"""

import argparse
import datetime
import os
import sys

try:
    import nmap
except ImportError:
    print("[!] python-nmap not installed. Run: pip install python-nmap")
    sys.exit(1)


# ─── ANSI colours (gracefully disabled on Windows) ────────────────────────────

def supports_colour():
    return sys.platform != "win32" and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOUR = supports_colour()

class C:
    RESET  = "\033[0m"  if USE_COLOUR else ""
    BOLD   = "\033[1m"  if USE_COLOUR else ""
    RED    = "\033[91m" if USE_COLOUR else ""
    GREEN  = "\033[92m" if USE_COLOUR else ""
    YELLOW = "\033[93m" if USE_COLOUR else ""
    CYAN   = "\033[96m" if USE_COLOUR else ""
    DIM    = "\033[2m"  if USE_COLOUR else ""


# ─── BANNER ───────────────────────────────────────────────────────────────────

BANNER = f"""
{C.CYAN}{C.BOLD}
 ███████████  ██████████   █████████   ███████    ██████  █████
░░███░░░░░███░░███░░░░░█  ███░░░░░███ ███░░░░███ ███░░███░░███
 ░███    ░███ ░███  █ ░  ███     ░░░ ███    ░░███░███ ░░░  ░███
 ░██████████  ░██████   ░███        ░███     ░███░░██████  ░███
 ░███░░░░░███ ░███░░█   ░███        ░███     ░███ ░░░░███  ░███
 ░███    ░███ ░███ ░   █░░███     ███░░███    ███  ███ ░███ ░███      █
 █████   █████████████  ░░█████████  ░░░███████░  ░░██████  █████████{C.RESET}

{C.DIM}  Network Recon Toolkit v1.0  |  github.com/t_of_typer{C.RESET}
"""


# ─── SCAN PROFILES ────────────────────────────────────────────────────────────

SCAN_PROFILES = {
    "quick": {
        "args": "-T4 -F",
        "description": "Fast scan — top 100 ports",
    },
    "standard": {
        "args": "-T4 -sV -sC -O --open",
        "description": "Standard scan — services, scripts, OS detection",
    },
    "stealth": {
        "args": "-T2 -sS -O --open",
        "description": "Stealth SYN scan (requires root)",
    },
    "full": {
        "args": "-T4 -sV -sC -O -p- --open",
        "description": "Full scan — all 65535 ports (slow)",
    },
    "vuln": {
        "args": "-T4 -sV --script=vuln",
        "description": "Vulnerability scan using NSE scripts",
    },
}


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def banner():
    print(BANNER)


def separator(char="─", width=65):
    print(f"{C.DIM}{char * width}{C.RESET}")


def status(msg, level="info"):
    icons = {"info": f"{C.CYAN}[*]{C.RESET}", "ok": f"{C.GREEN}[+]{C.RESET}",
             "warn": f"{C.YELLOW}[!]{C.RESET}", "err": f"{C.RED}[-]{C.RESET}"}
    print(f"{icons.get(level, '[?]')} {msg}")


def port_colour(state):
    if state == "open":
        return C.GREEN
    elif state == "filtered":
        return C.YELLOW
    else:
        return C.RED


# ─── CORE SCANNER ─────────────────────────────────────────────────────────────

def run_scan(target, profile, custom_args=None):
    nm = nmap.PortScanner()
    args = custom_args if custom_args else SCAN_PROFILES[profile]["args"]

    status(f"Target     : {C.BOLD}{target}{C.RESET}")
    status(f"Profile    : {profile} — {SCAN_PROFILES.get(profile, {}).get('description', 'custom')}")
    status(f"Nmap args  : {args}")
    separator()
    status("Scanning… this may take a moment.", "warn")

    try:
        nm.scan(hosts=target, arguments=args)
    except nmap.PortScannerError as e:
        status(f"Scan error: {e}", "err")
        sys.exit(1)
    except Exception as e:
        status(f"Unexpected error: {e}", "err")
        sys.exit(1)

    return nm


# ─── REPORT BUILDER ───────────────────────────────────────────────────────────

def build_report(nm, target, profile):
    """Parse nmap results into a structured dict."""
    report = {
        "meta": {
            "target": target,
            "profile": profile,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "nmap_version": nm.nmap_version(),
            "command": nm.command_line(),
        },
        "hosts": [],
    }

    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname() or "N/A",
            "state": nm[host].state(),
            "os_matches": [],
            "ports": [],
        }

        # OS detection
        if "osmatch" in nm[host]:
            for match in nm[host]["osmatch"][:3]:
                host_data["os_matches"].append({
                    "name": match.get("name", "Unknown"),
                    "accuracy": match.get("accuracy", "?"),
                })

        # Ports
        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            for port in ports:
                p = nm[host][proto][port]
                port_data = {
                    "port": port,
                    "proto": proto,
                    "state": p.get("state", "?"),
                    "service": p.get("name", "?"),
                    "version": f"{p.get('product', '')} {p.get('version', '')}".strip(),
                    "cpe": p.get("cpe", ""),
                    "script_output": p.get("script", {}),
                }
                host_data["ports"].append(port_data)

        report["hosts"].append(host_data)

    return report


# ─── TERMINAL DISPLAY ─────────────────────────────────────────────────────────

def print_report(report):
    meta = report["meta"]
    separator("═")
    print(f"{C.BOLD}  SCAN REPORT{C.RESET}")
    separator("═")
    print(f"  Target     : {C.CYAN}{meta['target']}{C.RESET}")
    print(f"  Profile    : {meta['profile']}")
    print(f"  Timestamp  : {meta['timestamp']}")
    print(f"  Command    : {C.DIM}{meta['command']}{C.RESET}")
    separator()

    if not report["hosts"]:
        status("No live hosts found. Try a different target or profile.", "warn")
        return

    for host in report["hosts"]:
        print(f"\n{C.BOLD}  Host : {C.CYAN}{host['ip']}{C.RESET}  "
              f"({host['hostname']})  "
              f"[{C.GREEN if host['state'] == 'up' else C.RED}{host['state']}{C.RESET}]")

        # OS
        if host["os_matches"]:
            print(f"\n  {C.BOLD}OS Detection:{C.RESET}")
            for os in host["os_matches"]:
                print(f"    {C.DIM}•{C.RESET} {os['name']}  "
                      f"{C.DIM}(accuracy: {os['accuracy']}%){C.RESET}")

        # Ports table
        if host["ports"]:
            print(f"\n  {C.BOLD}{'PORT':<10} {'STATE':<12} {'SERVICE':<16} {'VERSION'}{C.RESET}")
            separator("-", 65)
            for p in host["ports"]:
                colour = port_colour(p["state"])
                version_str = p["version"] if p["version"] else "—"
                print(f"  {p['port']}/{p['proto']:<6} "
                      f"{colour}{p['state']:<12}{C.RESET}"
                      f"{p['service']:<16} "
                      f"{C.DIM}{version_str}{C.RESET}")

                # NSE script output (truncated)
                for script_name, output in p["script_output"].items():
                    preview = output.replace("\n", " ")[:80]
                    print(f"  {C.YELLOW}  [{script_name}]{C.RESET} {C.DIM}{preview}…{C.RESET}")
        else:
            status("No open ports found on this host.", "warn")

    separator("═")
    open_count = sum(
        1 for h in report["hosts"]
        for p in h["ports"] if p["state"] == "open"
    )
    print(f"  {C.BOLD}Summary:{C.RESET} {len(report['hosts'])} host(s) up — "
          f"{C.GREEN}{open_count} open port(s){C.RESET} found")
    separator("═")


# ─── FILE EXPORT ──────────────────────────────────────────────────────────────

def export_txt(report, filepath):
    """Export a plain-text version of the report."""
    meta = report["meta"]
    lines = [
        "=" * 65,
        "  NETWORK RECON TOOLKIT — SCAN REPORT",
        "=" * 65,
        f"  Target    : {meta['target']}",
        f"  Profile   : {meta['profile']}",
        f"  Timestamp : {meta['timestamp']}",
        f"  Command   : {meta['command']}",
        "-" * 65,
    ]

    for host in report["hosts"]:
        lines.append(f"\nHost : {host['ip']}  ({host['hostname']})  [{host['state']}]")

        if host["os_matches"]:
            lines.append("\nOS Detection:")
            for os in host["os_matches"]:
                lines.append(f"  • {os['name']}  (accuracy: {os['accuracy']}%)")

        if host["ports"]:
            lines.append(f"\n{'PORT':<10} {'STATE':<12} {'SERVICE':<16} {'VERSION'}")
            lines.append("-" * 60)
            for p in host["ports"]:
                version_str = p["version"] if p["version"] else "—"
                lines.append(f"{p['port']}/{p['proto']:<6} {p['state']:<12} "
                              f"{p['service']:<16} {version_str}")
                for script_name, output in p["script_output"].items():
                    preview = output.replace("\n", " ")[:80]
                    lines.append(f"  [{script_name}] {preview}…")
        else:
            lines.append("  No open ports found.")

    open_count = sum(
        1 for h in report["hosts"]
        for p in h["ports"] if p["state"] == "open"
    )
    lines += [
        "\n" + "=" * 65,
        f"  Summary: {len(report['hosts'])} host(s) up — {open_count} open port(s) found",
        "=" * 65,
    ]

    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    status(f"Report saved → {filepath}", "ok")


def export_json(report, filepath):
    import json
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    status(f"JSON saved  → {filepath}", "ok")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Recon Toolkit — Python/Nmap wrapper",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, hostname, or CIDR range\n"
                             "  e.g. 192.168.1.1 | scanme.nmap.org | 10.0.0.0/24")
    parser.add_argument("-p", "--profile", default="standard",
                        choices=SCAN_PROFILES.keys(),
                        help="\n".join(
                            f"  {k:10} — {v['description']}"
                            for k, v in SCAN_PROFILES.items()
                        ))
    parser.add_argument("--custom", metavar="ARGS",
                        help="Override profile with custom nmap arguments\n"
                             "  e.g. --custom \"-T4 -p 80,443 -sV\"")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save plain-text report to file")
    parser.add_argument("--json", metavar="FILE",
                        help="Save JSON report to file")
    parser.add_argument("--profiles", action="store_true",
                        help="List available scan profiles and exit")
    return parser.parse_args()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    banner()

    if args.profiles:
        print(f"{C.BOLD}Available scan profiles:{C.RESET}\n")
        for name, info in SCAN_PROFILES.items():
            print(f"  {C.CYAN}{name:<12}{C.RESET} {info['description']}")
            print(f"  {C.DIM}{'':12} nmap {info['args']}{C.RESET}\n")
        sys.exit(0)

    nm = run_scan(args.target, args.profile, args.custom)
    report = build_report(nm, args.target, args.profile)
    print_report(report)

    if args.output:
        export_txt(report, args.output)
    if args.json:
        export_json(report, args.json)

    # Auto-save with timestamp if no output specified
    if not args.output and not args.json:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = args.target.replace("/", "-").replace(".", "-")
        auto_path = f"report_{safe_target}_{ts}.txt"
        export_txt(report, auto_path)


if __name__ == "__main__":
    main()
