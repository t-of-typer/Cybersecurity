# 🔍 Network Recon Toolkit

A Python-based network reconnaissance tool that wraps Nmap to perform host discovery, port scanning, service/version detection, and OS fingerprinting — then generates clean, readable reports in both terminal and file formats.

Built as part of a hands-on cybersecurity portfolio to demonstrate practical knowledge of network enumeration, TCP/IP, and the recon phase of penetration testing methodology.

---

## Features

- **5 scan profiles** — quick, standard, stealth, full, and vulnerability scan
- **Service & version detection** via Nmap NSE scripts
- **OS fingerprinting** with accuracy scores
- **Colourised terminal output** for fast readability
- **Auto-export** to `.txt` and `.json` report files
- **Custom Nmap argument passthrough** for advanced users
- Clean, modular code — easy to extend

---

## Demo

```
 ███████████  ██████████   ██████  ███████    ██████  █████
 ░░███░░░░░███░░███░░░░░█  ███░░███░░███░░███ ███░░███░░███
  ░███    ░███ ░███  █ ░  ░███ ░░░  ░███ ░░░ ░███ ░░░  ░███
  ░██████████  ░██████    ░░██████  ░███     ░░██████  ░███
  ...

[*] Target     : scanme.nmap.org
[*] Profile    : standard — services, scripts, OS detection
[!] Scanning… this may take a moment.

══════════════════════════════════════════════════════════════════
  SCAN REPORT
══════════════════════════════════════════════════════════════════
  Host : 45.33.32.156  (scanme.nmap.org)  [up]

  OS Detection:
    • Linux 4.15 - 5.8  (accuracy: 95%)

  PORT       STATE        SERVICE          VERSION
  ──────────────────────────────────────────────────────────────
  22/tcp     open         ssh              OpenSSH 6.6.1p1
  80/tcp     open         http             Apache httpd 2.4.7
  9929/tcp   open         nping-echo       Nping echo
══════════════════════════════════════════════════════════════════
  Summary: 1 host(s) up — 3 open port(s) found
```

---

## Installation

### Prerequisites
- Python 3.8+
- Nmap installed on your system

```bash
# Install Nmap (Linux)
sudo apt install nmap

# Install Nmap (macOS)
brew install nmap
```

### Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/network-recon-toolkit.git
cd network-recon-toolkit

# Install Python dependency
pip install -r requirements.txt
```

---

## Usage

```bash
# Standard scan (default)
python3 recon_toolkit.py -t scanme.nmap.org

# Quick scan — top 100 ports
python3 recon_toolkit.py -t 192.168.1.1 -p quick

# Stealth SYN scan (requires sudo)
sudo python3 recon_toolkit.py -t 192.168.1.0/24 -p stealth

# Vulnerability scan
sudo python3 recon_toolkit.py -t 10.0.0.1 -p vuln

# Full port scan with JSON output
python3 recon_toolkit.py -t 192.168.1.1 -p full --json results.json

# Custom Nmap arguments
python3 recon_toolkit.py -t 10.0.0.1 --custom "-T4 -p 22,80,443 -sV"

# List all profiles
python3 recon_toolkit.py --profiles
```

---

## Scan Profiles

| Profile    | Description                                | Nmap Args               |
|------------|--------------------------------------------|-------------------------|
| `quick`    | Fast scan, top 100 ports                   | `-T4 -F`                |
| `standard` | Services, scripts, OS detection (default)  | `-T4 -sV -sC -O --open` |
| `stealth`  | SYN scan, requires root                    | `-T2 -sS -O --open`     |
| `full`     | All 65535 ports, slow                      | `-T4 -sV -sC -O -p-`    |
| `vuln`     | NSE vulnerability scripts                  | `-T4 -sV --script=vuln` |

---

## Output Files

Reports are auto-saved to the working directory as:
```
report_192-168-1-1_20260318_143022.txt
```

You can also specify output paths:
```bash
python3 recon_toolkit.py -t 10.0.0.1 -o my_report.txt --json my_report.json
```

---

## Project Structure

```
network-recon-toolkit/
├── recon_toolkit.py     # Main script
├── requirements.txt     # Python dependencies
├── README.md            # This file
└── sample_output/
    └── example_report.txt
```

---

## Skills Demonstrated

- Network reconnaissance methodology (OSCP/CEH concepts)
- TCP/IP fundamentals — ports, protocols, service banners
- Python scripting — argparse, file I/O, subprocess wrapping
- Nmap proficiency — scan types, NSE scripts, OS detection
- Structured report generation (text + JSON)
- Security tool development

---

## Legal & Ethical Notice

> **Only scan systems you own or have explicit written permission to scan.**
> Unauthorised scanning may be illegal under the Computer Fraud and Abuse Act (CFAA),
> the Computer Misuse Act (UK), and equivalent legislation in your jurisdiction.
> Use responsibly and ethically.

---

## Author

**Pedro Fousianis Dumitru**
Cybersecurity Analyst | Dublin, Ireland
[LinkedIn](https://linkedin.com/in/pedro-fousianis) · [GitHub](https://github.com/t_of_typer)

---

## Roadmap

- [ ] HTML report export
- [ ] CVE lookup integration (NVD API)
- [ ] Scheduled/automated scans
- [ ] Slack/email alerting on new open ports
=======
# Cybersecurity
Cybersecurity projects
>>>>>>> a605426012907ac52138853359af5c83278f0f64
