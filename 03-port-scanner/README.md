# 🔌 Port Scanner from Scratch

A TCP port scanner built entirely with raw Python sockets — no Nmap, no external dependencies. Shows exactly what happens at the TCP layer during a scan: connection attempts, banner grabbing, and service identification.

Built to demonstrate that I understand *what Nmap does under the hood*, not just how to run it — a common interview question in security roles.

---

## Features

- **Raw TCP socket scanning** — no Nmap or external libraries
- **Multi-threaded** — configurable thread count for speed (default 150)
- **Banner grabbing** — reveals service name and version from open ports
- **Service identification** — built-in database of 50+ common port/service mappings
- **TTL-based OS fingerprinting** — estimates target OS from ICMP TTL value
- **Security risk notes** — flags dangerous open ports (RDP, SMB, Redis, Docker API, etc.)
- **4 port profiles** — top20, top100, full (65535), or custom range/list
- **Auto-export** to TXT and JSON reports
- **Zero dependencies** — pure Python standard library

---

## How It Works

```
Target IP:Port
      │
      ▼
socket.connect_ex(ip, port)
      │
      ├── Returns 0  → PORT OPEN  → send probe → read banner
      │
      └── Returns !0 → PORT CLOSED / FILTERED
```

The key function is `socket.connect_ex()` — unlike `connect()`, it returns an error code instead of raising an exception. Return code `0` means the TCP three-way handshake completed (port is open). Anything else means closed or filtered.

This is the same mechanism Nmap uses for a TCP Connect scan (`-sT`).

---

## Demo

```
[*] Target      : scanme.nmap.org  →  45.33.32.156
[*] OS guess    : Linux / macOS / Unix  (TTL 55)
[*] Port range  : top100  (100 ports)
[*] Threads     : 150  ·  Timeout: 0.8s

══════════════════════════════════════════════════════════════════════
  SCAN REPORT
══════════════════════════════════════════════════════════════════════
  Target      : scanme.nmap.org  (45.33.32.156)
  Profile     : top100
  Ports       : 100 scanned
  Duration    : 4.21s
  TTL / OS    : 55  →  Linux / macOS / Unix
  ──────────────────────────────────────────────────────────────────

  PORT         SERVICE                BANNER / INFO
  ──────────────────────────────────────────────────────────────────
  22/tcp       SSH                    SSH-2.0-OpenSSH_6.6.1p1 Ubuntu
  80/tcp       HTTP                   HTTP/1.1 200 OK
  9929/tcp     unknown                NPING-ECHO
  31337/tcp    unknown                —

══════════════════════════════════════════════════════════════════════
  Summary:  4 open port(s) found  ·  0 security note(s)
══════════════════════════════════════════════════════════════════════
```

---

## Installation

No installation needed — pure Python standard library.

```bash
git clone https://github.com/t-of-typer/Cybersecurity.git
cd Cybersecurity/03-port-scanner
```

---

## Usage

```bash
# Scan top 100 common ports (default)
python port_scanner.py -t scanme.nmap.org

# Quick scan — top 20 ports
python port_scanner.py -t 192.168.1.1 -p top20

# Specific ports
python port_scanner.py -t 192.168.1.1 -p 22,80,443,3306,3389

# Port range
python port_scanner.py -t 192.168.1.1 -p 1-1024

# Full scan (all 65535 ports) — slow
python port_scanner.py -t 192.168.1.1 -p full --threads 300

# Faster scan (no banner grabbing)
python port_scanner.py -t 192.168.1.1 --no-banners

# Save to JSON
python port_scanner.py -t 192.168.1.1 --json results.json

# Custom timeout and thread count
python port_scanner.py -t 192.168.1.1 --timeout 0.5 --threads 200
```

---

## Port Profiles

| Profile | Ports | Use case |
|---------|-------|----------|
| `top20` | 20 most critical | Quick triage |
| `top100` | 100 most common | Default, balanced |
| `full` | All 65535 | Thorough audit |
| Custom | e.g. `80,443` or `1-1024` | Targeted |

---

## Security Risk Detection

The scanner automatically flags dangerous open ports:

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Credentials sent in plaintext |
| 23 | Telnet | Everything in plaintext |
| 445 | SMB | Common ransomware/lateral movement |
| 3389 | RDP | Common brute-force target |
| 2375 | Docker API | Critical — unauthenticated access |
| 6379 | Redis | Often unauthenticated by default |
| 4444 | — | Metasploit default — possible backdoor |

---

## Project Structure

```
03-port-scanner/
├── port_scanner.py     # Main script
├── README.md           # This file
└── reports/            # Auto-saved scan reports
```

---

## Skills Demonstrated

- TCP/IP fundamentals — how the three-way handshake works
- Raw socket programming in Python
- Multi-threading with `queue.Queue` and `threading.Thread`
- Service banner grabbing and protocol probing
- OS fingerprinting via TTL analysis
- Security risk identification for common dangerous ports
- CLI tooling with `argparse`
- Structured JSON/TXT report generation

---

## Legal Notice

> **Only scan systems you own or have explicit written permission to scan.**
> Unauthorised port scanning may be illegal in your jurisdiction.
> Use `scanme.nmap.org` for legal testing — it is provided by the Nmap project for this purpose.

---

## Author

**Pedro Fousianis Dumitru**
Cybersecurity Analyst | Dublin, Ireland
[LinkedIn](https://linkedin.com/in/pedro-fousianis) · [GitHub](https://github.com/t-of-typer/Cybersecurity)
