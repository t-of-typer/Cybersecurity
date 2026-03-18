#!/usr/bin/env python3
"""
Network Traffic Analyser (PCAP)
---------------------------------
Parses PCAP files captured with Wireshark or tcpdump and produces a
detailed security-focused analysis: protocol breakdown, top talkers,
suspicious patterns, cleartext credential detection, port scans,
DNS anomalies, and large data transfers.

Features:
  - Protocol distribution (TCP/UDP/ICMP/ARP/DNS/HTTP/HTTPS/FTP/Telnet)
  - Top talkers — most active source/destination IPs
  - Cleartext credential sniffing (HTTP Basic Auth, FTP, Telnet)
  - Port scan detection (horizontal + vertical)
  - DNS query analysis and tunnelling detection
  - Large/unusual data transfer detection
  - ARP spoofing detection
  - SYN flood / DoS pattern detection
  - Colour-coded terminal report + TXT/JSON export
  - Demo PCAP generator — works without a real capture file

Requirements:
  pip install scapy

Author : Pedro Fousianis
GitHub : github.com/t-of-typer/Cybersecurity
Usage  : python traffic_analyser.py -f capture.pcap
         python traffic_analyser.py --demo
"""

import argparse
import collections
import datetime
import ipaddress
import json
import os
import sys
import time

try:
    from scapy.all import (
        rdpcap, wrpcap, PcapWriter,
        Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        Raw, Padding,
        sniff
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("\n[!] Scapy is required. Install it with:")
    print("    pip install scapy\n")
    sys.exit(1)


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
    PURPLE = "\033[95m" if USE_COLOUR else ""


# ─── BANNER ───────────────────────────────────────────────────────────────────

BANNER = f"""{C.CYAN}{C.BOLD}
  ████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗
  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝
     ██║   ██████╔╝███████║█████╗  █████╗  ██║██║
     ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║
     ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝  ANALYSER
{C.RESET}{C.DIM}  Network Traffic Analyser v1.0  |  github.com/t-of-typer/Cybersecurity{C.RESET}
"""


# ─── KNOWN PORTS / SERVICES ───────────────────────────────────────────────────

CLEARTEXT_PORTS = {
    21: "FTP", 23: "Telnet", 80: "HTTP",
    143: "IMAP", 110: "POP3", 25: "SMTP",
}

DANGEROUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite/BackOrifice",
    6667: "IRC (botnet C2)",
    6666: "IRC (botnet C2)",
    9001: "Tor default",
    9050: "Tor SOCKS",
}

ENCRYPTED_PORTS = {443, 993, 995, 465, 8443, 22}


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def sep(char="─", width=72):
    print(f"{C.DIM}{char * width}{C.RESET}")

def is_private(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def is_multicast(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_multicast
    except ValueError:
        return False

def human_bytes(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ─── PCAP ANALYSER ────────────────────────────────────────────────────────────

class PcapAnalyser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.packets  = []
        self.results  = {}

    def load(self):
        print(f"{C.CYAN}[*]{C.RESET} Loading: {C.BOLD}{self.filepath}{C.RESET}")
        try:
            self.packets = rdpcap(self.filepath)
            print(f"{C.GREEN}[+]{C.RESET} Loaded {len(self.packets):,} packets")
            return True
        except FileNotFoundError:
            print(f"{C.RED}[!] File not found: {self.filepath}{C.RESET}")
            return False
        except Exception as e:
            print(f"{C.RED}[!] Error reading PCAP: {e}{C.RESET}")
            return False

    def analyse(self):
        print(f"{C.CYAN}[*]{C.RESET} Analysing traffic…")
        start = time.time()

        pkts = self.packets

        # ── Meta ──────────────────────────────────────────────────────────────
        timestamps = [float(p.time) for p in pkts if hasattr(p, 'time')]
        duration   = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
        total_bytes = sum(len(p) for p in pkts)

        # ── Protocol counters ─────────────────────────────────────────────────
        proto_counts = collections.Counter()
        for p in pkts:
            if p.haslayer(TCP):   proto_counts["TCP"] += 1
            if p.haslayer(UDP):   proto_counts["UDP"] += 1
            if p.haslayer(ICMP):  proto_counts["ICMP"] += 1
            if p.haslayer(ARP):   proto_counts["ARP"] += 1
            if p.haslayer(DNS):   proto_counts["DNS"] += 1
            if p.haslayer(HTTP):  proto_counts["HTTP"] += 1
            if not (p.haslayer(TCP) or p.haslayer(UDP) or
                    p.haslayer(ICMP) or p.haslayer(ARP)):
                proto_counts["Other"] += 1

        # ── Top talkers ───────────────────────────────────────────────────────
        src_bytes  = collections.defaultdict(int)
        dst_bytes  = collections.defaultdict(int)
        src_counts = collections.Counter()
        dst_counts = collections.Counter()

        for p in pkts:
            if p.haslayer(IP):
                src = p[IP].src
                dst = p[IP].dst
                size = len(p)
                src_bytes[src]  += size
                dst_bytes[dst]  += size
                src_counts[src] += 1
                dst_counts[dst] += 1

        # ── Port activity ─────────────────────────────────────────────────────
        dst_ports = collections.Counter()
        src_ports = collections.Counter()
        for p in pkts:
            if p.haslayer(TCP):
                dst_ports[p[TCP].dport] += 1
                src_ports[p[TCP].sport] += 1
            elif p.haslayer(UDP):
                dst_ports[p[UDP].dport] += 1

        # ── Cleartext credentials ─────────────────────────────────────────────
        cleartext_findings = []

        for p in pkts:
            if not p.haslayer(IP):
                continue

            src = p[IP].src
            dst = p[IP].dst

            # HTTP Basic Auth
            if p.haslayer(HTTPRequest):
                try:
                    req = p[HTTPRequest]
                    headers = bytes(req).decode("utf-8", errors="replace")
                    if "Authorization: Basic" in headers:
                        import base64
                        for line in headers.splitlines():
                            if "Authorization: Basic" in line:
                                b64 = line.split("Basic ")[-1].strip()
                                try:
                                    decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                                    cleartext_findings.append({
                                        "type": "HTTP Basic Auth",
                                        "src": src, "dst": dst,
                                        "data": decoded[:60],
                                        "risk": "CRITICAL",
                                    })
                                except Exception:
                                    pass
                    if req.fields.get("Method") in [b"POST", b"GET"]:
                        path = req.fields.get("Path", b"").decode("utf-8", errors="replace")
                        if p.haslayer(Raw):
                            body = p[Raw].load.decode("utf-8", errors="replace").lower()
                            if any(kw in body for kw in ["password=", "passwd=", "pwd=", "pass="]):
                                cleartext_findings.append({
                                    "type": "HTTP Form Credentials",
                                    "src": src, "dst": dst,
                                    "data": f"POST to {path} contains password field",
                                    "risk": "CRITICAL",
                                })
                except Exception:
                    pass

            # FTP credentials
            if p.haslayer(TCP) and p[TCP].dport == 21 and p.haslayer(Raw):
                try:
                    payload = p[Raw].load.decode("utf-8", errors="replace").strip()
                    if payload.upper().startswith(("USER ", "PASS ")):
                        cleartext_findings.append({
                            "type": "FTP Credentials",
                            "src": src, "dst": dst,
                            "data": payload[:60],
                            "risk": "CRITICAL",
                        })
                except Exception:
                    pass

            # Telnet data
            if p.haslayer(TCP) and p[TCP].dport == 23 and p.haslayer(Raw):
                try:
                    payload = p[Raw].load.decode("utf-8", errors="replace").strip()
                    if payload and len(payload) > 2:
                        cleartext_findings.append({
                            "type": "Telnet Data (plaintext session)",
                            "src": src, "dst": dst,
                            "data": payload[:60],
                            "risk": "HIGH",
                        })
                except Exception:
                    pass

        # ── Port scan detection ────────────────────────────────────────────────
        # Vertical scan: one source IP hitting many ports on one destination
        ip_port_map = collections.defaultdict(lambda: collections.defaultdict(set))
        syn_counts  = collections.Counter()

        for p in pkts:
            if p.haslayer(IP) and p.haslayer(TCP):
                flags = p[TCP].flags
                if flags & 0x02:  # SYN flag
                    src = p[IP].src
                    dst = p[IP].dst
                    dport = p[TCP].dport
                    ip_port_map[src][dst].add(dport)
                    syn_counts[src] += 1

        port_scan_findings = []
        for src, dsts in ip_port_map.items():
            for dst, ports in dsts.items():
                if len(ports) >= 15:
                    port_scan_findings.append({
                        "src": src,
                        "dst": dst,
                        "ports_contacted": len(ports),
                        "sample_ports": sorted(ports)[:10],
                        "type": "Vertical port scan",
                    })

        # Horizontal scan: one source hitting many destinations on same port
        src_dst_map = collections.defaultdict(lambda: collections.defaultdict(set))
        for p in pkts:
            if p.haslayer(IP) and p.haslayer(TCP):
                if p[TCP].flags & 0x02:
                    src_dst_map[p[IP].src][p[TCP].dport].add(p[IP].dst)

        for src, port_dsts in src_dst_map.items():
            for port, dsts in port_dsts.items():
                if len(dsts) >= 10:
                    port_scan_findings.append({
                        "src": src,
                        "port": port,
                        "hosts_contacted": len(dsts),
                        "type": "Horizontal port scan",
                    })

        # ── SYN flood detection ────────────────────────────────────────────────
        syn_flood_findings = []
        for src, count in syn_counts.most_common(5):
            if count > 200:
                syn_flood_findings.append({
                    "src": src,
                    "syn_count": count,
                    "type": "Possible SYN flood / DoS",
                })

        # ── ARP spoofing detection ─────────────────────────────────────────────
        arp_table   = {}  # ip -> set of MACs
        arp_findings = []

        for p in pkts:
            if p.haslayer(ARP) and p[ARP].op == 2:  # ARP reply
                ip  = p[ARP].psrc
                mac = p[ARP].hwsrc
                if ip not in arp_table:
                    arp_table[ip] = set()
                arp_table[ip].add(mac)

        for ip, macs in arp_table.items():
            if len(macs) > 1:
                arp_findings.append({
                    "ip": ip,
                    "macs": list(macs),
                    "type": "ARP spoofing / duplicate IP",
                })

        # ── DNS analysis ──────────────────────────────────────────────────────
        dns_queries  = collections.Counter()
        dns_findings = []
        long_dns     = []

        for p in pkts:
            if p.haslayer(DNS) and p.haslayer(DNSQR):
                try:
                    qname = p[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                    dns_queries[qname] += 1

                    # Long subdomain — possible DNS tunnelling
                    parts = qname.split(".")
                    longest_label = max((len(x) for x in parts), default=0)
                    if longest_label > 40 or len(qname) > 100:
                        long_dns.append(qname)
                except Exception:
                    pass

        if long_dns:
            dns_findings.append({
                "type": "Possible DNS tunnelling",
                "description": "Unusually long DNS queries detected",
                "samples": long_dns[:5],
                "risk": "HIGH",
            })

        # ── Large data transfers ───────────────────────────────────────────────
        flow_bytes = collections.defaultdict(int)
        for p in pkts:
            if p.haslayer(IP):
                key = (p[IP].src, p[IP].dst)
                flow_bytes[key] += len(p)

        large_transfers = [
            {"src": k[0], "dst": k[1], "bytes": v, "human": human_bytes(v)}
            for k, v in sorted(flow_bytes.items(), key=lambda x: -x[1])[:10]
            if v > 50_000
        ]

        # ── Dangerous port activity ────────────────────────────────────────────
        dangerous_findings = []
        for p in pkts:
            if p.haslayer(IP) and p.haslayer(TCP):
                dport = p[TCP].dport
                sport = p[TCP].sport
                for port in [dport, sport]:
                    if port in DANGEROUS_PORTS:
                        dangerous_findings.append({
                            "src": p[IP].src,
                            "dst": p[IP].dst,
                            "port": port,
                            "note": DANGEROUS_PORTS[port],
                        })

        # Deduplicate dangerous findings
        seen = set()
        deduped = []
        for f in dangerous_findings:
            key = (f["src"], f["dst"], f["port"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        dangerous_findings = deduped

        elapsed = time.time() - start

        self.results = {
            "meta": {
                "file": self.filepath,
                "total_packets": len(pkts),
                "total_bytes": total_bytes,
                "total_bytes_human": human_bytes(total_bytes),
                "duration_seconds": round(duration, 2),
                "analysed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "elapsed": round(elapsed, 2),
            },
            "protocols": dict(proto_counts.most_common()),
            "top_sources": [(ip, cnt, human_bytes(src_bytes[ip]))
                            for ip, cnt in src_counts.most_common(10)],
            "top_destinations": [(ip, cnt, human_bytes(dst_bytes[ip]))
                                 for ip, cnt in dst_counts.most_common(10)],
            "top_dst_ports": dst_ports.most_common(15),
            "dns_queries": dns_queries.most_common(10),
            "cleartext": cleartext_findings,
            "port_scans": port_scan_findings,
            "syn_floods": syn_flood_findings,
            "arp_spoofing": arp_findings,
            "dns_findings": dns_findings,
            "large_transfers": large_transfers,
            "dangerous_ports": dangerous_findings,
        }

        return self.results


# ─── REPORTER ─────────────────────────────────────────────────────────────────

def risk_colour(risk):
    return {"CRITICAL": C.RED, "HIGH": C.ORANGE, "MEDIUM": C.YELLOW, "LOW": C.DIM}.get(risk, C.RESET)

def print_report(r):
    meta = r["meta"]
    total = meta["total_packets"]

    print(f"\n{'═' * 72}")
    print(f"  {C.BOLD}TRAFFIC ANALYSIS REPORT{C.RESET}")
    print(f"{'═' * 72}")
    print(f"  File         : {C.CYAN}{meta['file']}{C.RESET}")
    print(f"  Packets      : {total:,}")
    print(f"  Total data   : {meta['total_bytes_human']}")
    print(f"  Duration     : {meta['duration_seconds']:.1f}s")
    print(f"  Analysed at  : {meta['analysed_at']}")
    print(f"  Analysis time: {meta['elapsed']}s")
    sep()

    # ── Protocol breakdown ────────────────────────────────────────────────────
    print(f"\n  {C.BOLD}Protocol Distribution{C.RESET}")
    sep("-", 72)
    for proto, count in r["protocols"].items():
        pct = (count / total * 100) if total else 0
        bar = "█" * int(pct / 2)
        print(f"  {proto:<8} {C.CYAN}{bar:<25}{C.RESET} {count:>6} pkts  {pct:.1f}%")

    # ── Top talkers ───────────────────────────────────────────────────────────
    print(f"\n  {C.BOLD}Top Source IPs{C.RESET}")
    sep("-", 72)
    print(f"  {'IP':<20} {'PACKETS':>8}  {'BYTES':>10}  TYPE")
    for ip, cnt, bts in r["top_sources"][:8]:
        ip_type = f"{C.DIM}(private){C.RESET}" if is_private(ip) else f"{C.YELLOW}(external){C.RESET}"
        print(f"  {C.CYAN}{ip:<20}{C.RESET} {cnt:>8}  {bts:>10}  {ip_type}")

    print(f"\n  {C.BOLD}Top Destination IPs{C.RESET}")
    sep("-", 72)
    for ip, cnt, bts in r["top_destinations"][:8]:
        ip_type = f"{C.DIM}(private){C.RESET}" if is_private(ip) else f"{C.YELLOW}(external){C.RESET}"
        print(f"  {C.CYAN}{ip:<20}{C.RESET} {cnt:>8}  {bts:>10}  {ip_type}")

    # ── Top destination ports ─────────────────────────────────────────────────
    print(f"\n  {C.BOLD}Top Destination Ports{C.RESET}")
    sep("-", 72)
    for port, count in r["top_dst_ports"][:12]:
        service = CLEARTEXT_PORTS.get(port, DANGEROUS_PORTS.get(port, ""))
        warning = f"  {C.RED}[!]{C.RESET}" if port in DANGEROUS_PORTS else (
                  f"  {C.YELLOW}[cleartext]{C.RESET}" if port in CLEARTEXT_PORTS else "")
        enc = f"  {C.GREEN}[encrypted]{C.RESET}" if port in ENCRYPTED_PORTS else ""
        print(f"  {port:<8} {count:>6} pkts  {service:<20}{warning}{enc}")

    # ── Security findings ─────────────────────────────────────────────────────
    sep()
    print(f"\n  {C.BOLD}Security Findings{C.RESET}")
    sep("-", 72)

    findings_count = 0

    # Cleartext creds
    if r["cleartext"]:
        findings_count += len(r["cleartext"])
        print(f"\n  {C.RED}{C.BOLD}[CRITICAL] Cleartext Credentials Detected{C.RESET}  "
              f"({len(r['cleartext'])} finding(s))")
        for f in r["cleartext"][:5]:
            rc = risk_colour(f["risk"])
            print(f"  {rc}  {f['type']}{C.RESET}")
            print(f"  {C.DIM}  {f['src']} -> {f['dst']}{C.RESET}")
            print(f"  {C.DIM}  Data: {f['data'][:70]}{C.RESET}")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET}  No cleartext credentials detected")

    # Port scans
    if r["port_scans"]:
        findings_count += len(r["port_scans"])
        print(f"\n  {C.ORANGE}{C.BOLD}[HIGH] Port Scan Activity{C.RESET}  "
              f"({len(r['port_scans'])} scan(s) detected)")
        for f in r["port_scans"]:
            if f["type"] == "Vertical port scan":
                ports_str = ", ".join(str(p) for p in f["sample_ports"])
                print(f"  {C.ORANGE}  {f['src']} -> {f['dst']}{C.RESET}  "
                      f"{f['ports_contacted']} ports  [{ports_str}...]")
            else:
                print(f"  {C.ORANGE}  {f['src']} -> port {f['port']}{C.RESET}  "
                      f"{f['hosts_contacted']} hosts contacted")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET}  No port scan patterns detected")

    # SYN floods
    if r["syn_floods"]:
        findings_count += len(r["syn_floods"])
        print(f"\n  {C.RED}{C.BOLD}[CRITICAL] Possible DoS / SYN Flood{C.RESET}  "
              f"({len(r['syn_floods'])} source(s))")
        for f in r["syn_floods"]:
            print(f"  {C.RED}  {f['src']}{C.RESET}  sent {f['syn_count']:,} SYN packets")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET}  No SYN flood patterns detected")

    # ARP spoofing
    if r["arp_spoofing"]:
        findings_count += len(r["arp_spoofing"])
        print(f"\n  {C.RED}{C.BOLD}[CRITICAL] ARP Spoofing Detected{C.RESET}  "
              f"({len(r['arp_spoofing'])} IP(s))")
        for f in r["arp_spoofing"]:
            print(f"  {C.RED}  IP {f['ip']}{C.RESET} claimed by MACs: "
                  f"{C.DIM}{', '.join(f['macs'])}{C.RESET}")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET}  No ARP spoofing detected")

    # DNS anomalies
    if r["dns_findings"]:
        findings_count += len(r["dns_findings"])
        print(f"\n  {C.ORANGE}{C.BOLD}[HIGH] DNS Anomalies{C.RESET}")
        for f in r["dns_findings"]:
            print(f"  {C.ORANGE}  {f['type']}:{C.RESET} {f['description']}")
            for s in f.get("samples", [])[:3]:
                print(f"  {C.DIM}    {s}{C.RESET}")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET}  No DNS anomalies detected")

    # Dangerous ports
    if r["dangerous_ports"]:
        findings_count += len(r["dangerous_ports"])
        print(f"\n  {C.RED}{C.BOLD}[HIGH] Dangerous Port Activity{C.RESET}  "
              f"({len(r['dangerous_ports'])} connection(s))")
        for f in r["dangerous_ports"][:5]:
            print(f"  {C.RED}  Port {f['port']}{C.RESET}  {f['note']}  "
                  f"{C.DIM}{f['src']} -> {f['dst']}{C.RESET}")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET}  No dangerous port activity detected")

    # Large transfers
    if r["large_transfers"]:
        print(f"\n  {C.YELLOW}{C.BOLD}[INFO] Large Data Transfers{C.RESET}")
        sep("-", 72)
        print(f"  {'SOURCE':<20} {'DESTINATION':<20} {'SIZE':>10}")
        for f in r["large_transfers"][:8]:
            ext = f"{C.YELLOW}(external){C.RESET}" if not is_private(f['dst']) else ""
            print(f"  {f['src']:<20} {f['dst']:<20} {f['human']:>10}  {ext}")

    # DNS top queries
    if r["dns_queries"]:
        print(f"\n  {C.BOLD}Top DNS Queries{C.RESET}")
        sep("-", 72)
        for domain, count in r["dns_queries"][:8]:
            print(f"  {count:>5}x  {C.DIM}{domain}{C.RESET}")

    # ── Summary ───────────────────────────────────────────────────────────────
    critical = len(r["cleartext"]) + len(r["syn_floods"]) + len(r["arp_spoofing"])
    high     = len(r["port_scans"]) + len(r["dangerous_ports"]) + len(r["dns_findings"])

    print(f"\n{'═' * 72}")
    print(f"  {C.BOLD}THREAT SUMMARY{C.RESET}")
    sep("-", 72)
    print(f"  {C.RED}CRITICAL{C.RESET}  {critical}  (cleartext creds, SYN floods, ARP spoofing)")
    print(f"  {C.ORANGE}HIGH{C.RESET}      {high}  (port scans, dangerous ports, DNS anomalies)")
    print(f"  {C.YELLOW}INFO{C.RESET}      {len(r['large_transfers'])}  (large data transfers)")

    if critical > 0:
        verdict = f"{C.RED}HIGH RISK — immediate investigation required{C.RESET}"
    elif high > 0:
        verdict = f"{C.ORANGE}ELEVATED — review flagged activity{C.RESET}"
    else:
        verdict = f"{C.GREEN}CLEAN — no significant threats detected{C.RESET}"

    print(f"\n  Overall: {verdict}")
    print(f"{'═' * 72}\n")


# ─── EXPORT ───────────────────────────────────────────────────────────────────

def export_txt(r, filepath):
    meta = r["meta"]
    lines = [
        "=" * 72,
        "  NETWORK TRAFFIC ANALYSER — REPORT",
        "=" * 72,
        f"  File     : {meta['file']}",
        f"  Packets  : {meta['total_packets']:,}",
        f"  Data     : {meta['total_bytes_human']}",
        f"  Duration : {meta['duration_seconds']}s",
        f"  Date     : {meta['analysed_at']}",
        "-" * 72,
        "",
        "PROTOCOL DISTRIBUTION",
        "-" * 72,
    ]
    for proto, count in r["protocols"].items():
        lines.append(f"  {proto:<10} {count:>6} packets")

    lines += ["", "CLEARTEXT CREDENTIALS", "-" * 72]
    for f in r["cleartext"]:
        lines.append(f"  [{f['risk']}] {f['type']}")
        lines.append(f"  {f['src']} -> {f['dst']}")
        lines.append(f"  {f['data'][:80]}")

    lines += ["", "PORT SCAN ACTIVITY", "-" * 72]
    for f in r["port_scans"]:
        if f["type"] == "Vertical port scan":
            lines.append(f"  {f['src']} -> {f['dst']}  ({f['ports_contacted']} ports)")
        else:
            lines.append(f"  {f['src']} port {f['port']}  ({f['hosts_contacted']} hosts)")

    lines += ["", "ARP SPOOFING", "-" * 72]
    for f in r["arp_spoofing"]:
        lines.append(f"  IP {f['ip']} seen with MACs: {', '.join(f['macs'])}")

    lines += ["", "LARGE TRANSFERS", "-" * 72]
    for f in r["large_transfers"]:
        lines.append(f"  {f['src']:<20} -> {f['dst']:<20}  {f['human']}")

    lines += ["", "=" * 72]

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"{C.GREEN}[+] Report saved -> {filepath}{C.RESET}")


def export_json(r, filepath):
    # Make results JSON-serialisable
    safe = json.loads(json.dumps(r, default=str))
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(safe, f, indent=2)
    print(f"{C.GREEN}[+] JSON saved  -> {filepath}{C.RESET}")


# ─── DEMO PCAP GENERATOR ──────────────────────────────────────────────────────

def generate_demo_pcap(path):
    """
    Generate a realistic demo PCAP containing:
    - Normal HTTPS/DNS traffic
    - HTTP Basic Auth (cleartext creds)
    - FTP login (cleartext)
    - Port scan activity
    - ARP spoofing
    - Large data transfer
    """
    import random
    from scapy.all import (
        Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Raw,
        wrpcap
    )

    packets = []
    base_time = time.time() - 300

    def pkt(src_ip, dst_ip, sport, dport, payload=b"", flags="S", t_offset=0, proto="tcp"):
        eth = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        ip  = IP(src=src_ip, dst=dst_ip, ttl=64)
        if proto == "tcp":
            layer = TCP(sport=sport, dport=dport, flags=flags)
        else:
            layer = UDP(sport=sport, dport=dport)
        p = eth / ip / layer
        if payload:
            p = p / Raw(load=payload)
        p.time = base_time + t_offset
        return p

    t = 0

    # Normal HTTPS traffic (many packets)
    for i in range(80):
        packets.append(pkt("192.168.1.10", "93.184.216.34", 50000+i, 443, flags="S", t_offset=t))
        packets.append(pkt("93.184.216.34", "192.168.1.10", 443, 50000+i, flags="SA", t_offset=t+0.001))
        t += 0.05

    # DNS queries
    for i, domain in enumerate(["google.com", "github.com", "api.example.com", "update.microsoft.com"]):
        dns_pkt = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") /
                   IP(src="192.168.1.10", dst="8.8.8.8") /
                   UDP(sport=12345, dport=53) /
                   DNS(rd=1, qd=DNSQR(qname=domain)))
        dns_pkt.time = base_time + t
        packets.append(dns_pkt)
        t += 0.1

    # HTTP Basic Auth — cleartext credentials
    http_auth = (b"GET /admin HTTP/1.1\r\n"
                 b"Host: 192.168.1.50\r\n"
                 b"Authorization: Basic cGVkcm86cGFzc3dvcmQxMjM=\r\n"
                 b"Connection: close\r\n\r\n")
    packets.append(pkt("192.168.1.10", "192.168.1.50", 54321, 80,
                       payload=http_auth, flags="PA", t_offset=t))
    t += 0.5

    # FTP login — cleartext
    for cmd in [b"USER pedro\r\n", b"PASS secretpass\r\n"]:
        packets.append(pkt("192.168.1.10", "192.168.1.60", 55555, 21,
                           payload=cmd, flags="PA", t_offset=t))
        t += 0.2

    # Port scan — SYN to 25 ports
    scan_ports = [22, 23, 25, 80, 110, 135, 139, 143, 443, 445,
                  3306, 3389, 5900, 6379, 8080, 8443, 27017,
                  1433, 1521, 2375, 4444, 5432, 6667, 9200, 31337]
    for port in scan_ports:
        packets.append(pkt("10.0.0.99", "192.168.1.10", 45678, port,
                           flags="S", t_offset=t))
        t += 0.02

    # ARP spoofing — same IP, two different MACs
    arp1 = (Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff",
                pdst="192.168.1.10", hwdst="11:22:33:44:55:66"))
    arp2 = (Ether(src="de:ad:be:ef:00:01", dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:01",
                pdst="192.168.1.10", hwdst="11:22:33:44:55:66"))
    arp1.time = base_time + t
    arp2.time = base_time + t + 0.5
    packets.extend([arp1, arp2])
    t += 1

    # Large data transfer (many big packets)
    for i in range(60):
        payload = b"X" * 1400
        packets.append(pkt("192.168.1.10", "203.0.113.5", 60000, 443,
                           payload=payload, flags="PA", t_offset=t))
        t += 0.01

    # DNS tunnelling attempt — long subdomain
    tunnel_domain = "aGVsbG93b3JsZGhlbGxvd29ybGQ.exfiltrate.evil.com"
    dns_tunnel = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") /
                  IP(src="192.168.1.10", dst="8.8.8.8") /
                  UDP(sport=12399, dport=53) /
                  DNS(rd=1, qd=DNSQR(qname=tunnel_domain)))
    dns_tunnel.time = base_time + t
    packets.append(dns_tunnel)

    # Dangerous port — Metasploit
    packets.append(pkt("10.0.0.99", "192.168.1.10", 55001, 4444,
                       flags="S", t_offset=t + 0.5))

    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    wrpcap(path, packets)
    print(f"{C.GREEN}[+] Demo PCAP generated -> {path}{C.RESET}")
    print(f"{C.DIM}    Contains: HTTPS traffic, HTTP Basic Auth, FTP creds, port scan,")
    print(f"    ARP spoofing, large transfer, DNS tunnelling, Metasploit port{C.RESET}\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyser — PCAP security analysis with Scapy",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-f", "--file", metavar="PCAP",
                        help="Path to .pcap or .pcapng file to analyse")
    parser.add_argument("--demo", action="store_true",
                        help="Generate a demo PCAP with attack scenarios and analyse it")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save plain-text report to file")
    parser.add_argument("--json", metavar="FILE",
                        help="Save JSON report to file")
    return parser.parse_args()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    print(BANNER)

    if not args.file and not args.demo:
        print(f"{C.YELLOW}[!]{C.RESET} No input specified. Use -f <file.pcap> or --demo\n")
        print(f"  Examples:")
        print(f"  {C.DIM}python traffic_analyser.py -f capture.pcap{C.RESET}")
        print(f"  {C.DIM}python traffic_analyser.py --demo{C.RESET}\n")
        sys.exit(0)

    filepath = args.file

    if args.demo:
        filepath = "sample_pcaps/demo_capture.pcap"
        generate_demo_pcap(filepath)

    analyser = PcapAnalyser(filepath)
    if not analyser.load():
        sys.exit(1)

    results = analyser.analyse()
    print_report(results)

    # Export
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("reports", exist_ok=True)

    if args.output:
        export_txt(results, args.output)
    else:
        auto_path = f"reports/traffic_report_{ts}.txt"
        export_txt(results, auto_path)

    if args.json:
        export_json(results, args.json)
    else:
        export_json(results, f"reports/traffic_report_{ts}.json")


if __name__ == "__main__":
    main()
