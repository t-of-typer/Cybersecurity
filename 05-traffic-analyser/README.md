# 📡 Network Traffic Analyser (PCAP)

A Python-based PCAP analyser that parses network captures from Wireshark or tcpdump and produces a detailed security-focused report. Detects real attack patterns in captured traffic — cleartext credentials, port scans, ARP spoofing, DNS tunnelling, and more.

Built to demonstrate practical Wireshark + Python integration and the ability to analyse network traffic the way a SOC analyst or incident responder would.

---

## Features

- **Protocol breakdown** — TCP, UDP, ICMP, ARP, DNS, HTTP distribution
- **Top talkers** — most active source/destination IPs with byte counts
- **Cleartext credential detection** — HTTP Basic Auth, FTP USER/PASS, Telnet sessions
- **Port scan detection** — vertical (many ports, one host) and horizontal (one port, many hosts)
- **SYN flood / DoS detection** — abnormal SYN packet rates
- **ARP spoofing detection** — same IP claimed by multiple MAC addresses
- **DNS tunnelling detection** — abnormally long subdomains used for data exfiltration
- **Large data transfer tracking** — possible data exfiltration
- **Dangerous port alerting** — Metasploit (4444), BackOrifice (31337), IRC C2, Tor
- **Threat severity scoring** — CRITICAL / HIGH / INFO summary
- **Demo PCAP generator** — works without a real capture file
- **Auto-export** — TXT and JSON reports saved automatically

---

## Demo

```
[*] Loading: sample_pcaps/demo_capture.pcap
[+] Loaded 234 packets
[*] Analysing traffic…

════════════════════════════════════════════════════════════════════════
  TRAFFIC ANALYSIS REPORT
════════════════════════════════════════════════════════════════════════
  Packets      : 234
  Total data   : 132.4 KB
  Duration     : 18.3s

  Protocol Distribution
  TCP        163 pkts  69.7%
  UDP         12 pkts   5.1%
  DNS         10 pkts   4.3%
  ARP          2 pkts   0.9%

  Security Findings
  ──────────────────────────────────────────────────────────────────────
  [CRITICAL] Cleartext Credentials Detected  (3 finding(s))
    HTTP Basic Auth — 192.168.1.10 -> 192.168.1.50
    Data: pedro:password123

    FTP Credentials — 192.168.1.10 -> 192.168.1.60
    Data: USER pedro

  [HIGH] Port Scan Activity  (1 scan detected)
    10.0.0.99 -> 192.168.1.10  25 ports  [22, 23, 25, 80, 110...]

  [CRITICAL] ARP Spoofing Detected  (1 IP)
    IP 192.168.1.1 claimed by MACs: aa:bb:cc:dd:ee:ff, de:ad:be:ef:00:01

  [HIGH] DNS Anomalies
    Possible DNS tunnelling: Unusually long DNS queries detected
    aGVsbG93b3JsZGhlbGxvd29ybGQ.exfiltrate.evil.com

  THREAT SUMMARY
  CRITICAL  5
  HIGH      3
  Overall: HIGH RISK — immediate investigation required
```

---

## Installation

```bash
git clone https://github.com/t-of-typer/Cybersecurity.git
cd Cybersecurity/05-traffic-analyser

pip install scapy
```

> **Windows users:** Scapy requires [Npcap](https://npcap.com/) for live capture.
> For PCAP file analysis only, Npcap is not strictly required.

---

## Usage

```bash
# Analyse a real PCAP file
python traffic_analyser.py -f capture.pcap

# Generate demo PCAP and analyse it (no Wireshark needed)
python traffic_analyser.py --demo

# Save report to a specific file
python traffic_analyser.py -f capture.pcap -o my_report.txt

# Save JSON output
python traffic_analyser.py -f capture.pcap --json results.json

# Demo with JSON export
python traffic_analyser.py --demo --json demo_results.json
```

### Capturing your own PCAP (Linux/Mac)
```bash
# Capture 500 packets on eth0
sudo tcpdump -i eth0 -c 500 -w capture.pcap

# Capture only HTTP/HTTPS traffic
sudo tcpdump -i eth0 port 80 or port 443 -w web_traffic.pcap
```

Or use **Wireshark**: File → Export Specified Packets → save as `.pcap`

---

## What It Detects

| Detection | Method | Severity |
|---|---|---|
| HTTP Basic Auth | Parse Authorization header, base64 decode | CRITICAL |
| FTP credentials | Match USER/PASS commands on port 21 | CRITICAL |
| Telnet sessions | Flag any plaintext data on port 23 | HIGH |
| Vertical port scan | One source SYN-ing 15+ ports on one host | HIGH |
| Horizontal port scan | One source hitting 10+ hosts on same port | HIGH |
| SYN flood / DoS | Source sending 200+ SYN packets | CRITICAL |
| ARP spoofing | Same IP advertised with different MACs | CRITICAL |
| DNS tunnelling | Labels > 40 chars or queries > 100 chars | HIGH |
| Dangerous ports | 4444, 31337, 6667, 9050, 1337... | HIGH |
| Large transfers | Flows > 50KB to external IPs | INFO |

---

## Project Structure

```
05-traffic-analyser/
├── traffic_analyser.py       # Main script
├── requirements.txt          # scapy
├── README.md                 # This file
├── sample_pcaps/
│   └── demo_capture.pcap     # Auto-generated demo
└── reports/
    ├── traffic_report_*.txt  # Auto-saved reports
    └── traffic_report_*.json
```

---

## Skills Demonstrated

- Deep packet inspection with Scapy
- Layer-by-layer protocol analysis (Ethernet → IP → TCP/UDP → Application)
- Pattern recognition across packet streams (scans, floods, spoofing)
- Security threat classification and severity scoring
- Base64 decoding for HTTP Basic Auth credential extraction
- DNS query analysis and anomaly detection
- TCP flag analysis (SYN, ACK, PSH, RST)
- ARP table monitoring for spoofing indicators
- JSON/TXT structured report generation

---

## Legal Notice

> **Only analyse traffic from networks you own or have explicit permission to monitor.**
> Capturing or analysing network traffic without authorisation may be illegal.
> The demo PCAP is synthetically generated — no real credentials or PII are included.

---

## Author

**Pedro Fousianis Dumitru**
Cybersecurity Analyst | Dublin, Ireland
[LinkedIn](https://linkedin.com/in/pedro-fousianis) · [GitHub](https://github.com/t-of-typer/Cybersecurity)
