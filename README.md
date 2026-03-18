# Cybersecurity Portfolio — Pedro Fousianis

> Hands-on cybersecurity projects built while transitioning from enterprise software engineering into security.
> Each project targets real-world skills used in SOC, penetration testing, and security engineering roles.

---

## About Me

I'm a SAP Application Consultant at Capgemini with 3+ years of experience in L2/L3 incident management, root-cause analysis, and enterprise systems — now actively transitioning into cybersecurity.

I hold the **Google Cybersecurity Professional Certificate (2026)** and am currently training at **42 Madrid Fundación Telefónica**, where I build low-level systems projects in C while deepening my understanding of networking and operating systems.

This repository documents my practical learning journey — every project here is something I built, ran, and debugged myself.

📍 Dublin, Ireland &nbsp;|&nbsp; Open to work &nbsp;|&nbsp; [LinkedIn](https://linkedin.com/in/pedro-fousianis)

---

## Projects

| # | Project | Focus Area | Stack | Difficulty |
|---|---------|-----------|-------|------------|
| 01 | [Network Recon Toolkit](#01---network-recon-toolkit) | Recon / Enumeration | Python, Nmap | ⭐⭐ |
| 02 | [Log Analyser & Anomaly Detector](#02---log-analyser--anomaly-detector) | SOC / Blue Team | Python | ⭐⭐ |
| 03 | [Port Scanner from Scratch](#03---port-scanner-from-scratch) | Networking / TCP-IP | Python, Sockets | ⭐⭐ |
| 04 | [Password Auditor & Breach Checker](#04---password-auditor--breach-checker) | Security Awareness | Python, API | ⭐ |
| 05 | [Network Traffic Analyser](#05---network-traffic-analyser) | Packet Analysis | Python, Scapy | ⭐⭐⭐ |

---

## 01 — Network Recon Toolkit

> **`/01-network-recon-toolkit`**

A Python wrapper around Nmap that performs host discovery, port scanning, service/version detection, and OS fingerprinting across 5 configurable scan profiles. Outputs colour-coded terminal reports and auto-exports to TXT and JSON.

**Skills demonstrated:** Network enumeration, Nmap proficiency, scan profile selection, Python scripting, structured report generation

```bash
python recon_toolkit.py -t scanme.nmap.org -p standard
python recon_toolkit.py -t 192.168.1.0/24 -p stealth
python recon_toolkit.py --profiles
```

**Scan profiles:** `quick` · `standard` · `stealth` · `full` · `vuln`

---

## 02 — Log Analyser & Anomaly Detector

> **`/02-log-analyser`**

Pure Python SSH authentication log parser that detects brute force attacks, credential stuffing, successful logins after repeated failures, and off-hours access. Implements SIEM-style detection logic with configurable thresholds and severity scoring.

**Skills demonstrated:** Log analysis, regex parsing, threat detection patterns, SIEM concepts (Splunk/Chronicle), Python collections, CLI tooling

```bash
# Run against a live Linux auth log
sudo python log_analyser.py -f /var/log/auth.log

# Generate a demo log with built-in attack scenarios
python log_analyser.py --demo
```

**Detects:** Brute force · Credential stuffing · Post-brute success (compromise indicator) · Off-hours logins · Sudo activity

---

## 03 — Port Scanner from Scratch

> **`/03-port-scanner`** *(coming soon)*

TCP port scanner built with raw Python sockets — no Nmap dependency. Demonstrates understanding of what happens at the TCP layer during a scan, with threading for speed and banner grabbing for service identification.

---

## 04 — Password Auditor & Breach Checker

> **`/04-password-auditor`** *(coming soon)*

Checks password strength against NIST guidelines and queries the HaveIBeenPwned API using k-anonymity (no plain-text passwords are ever sent) to check for known data breaches.

---

## 05 — Network Traffic Analyser

> **`/05-traffic-analyser`** *(coming soon)*

Uses Scapy to parse PCAP files captured with Wireshark — summarises protocols, identifies top talkers, flags unencrypted credentials in cleartext protocols (HTTP, FTP, Telnet), and highlights anomalous traffic patterns.

---

## Skills Across This Portfolio

| Category | Tools & Concepts |
|---|---|
| Network security | Nmap · Wireshark · Scapy · TCP/IP · Port scanning · Packet analysis |
| SOC / Blue team | Log analysis · SIEM logic · Brute force detection · Incident triage |
| Scripting | Python · Regex · Sockets · API integration · Argparse |
| Frameworks | OWASP · NIST · CIA Triad · Kill chain methodology |
| Systems | Linux · Bash · File I/O · Process management |

---

## Certifications

- 🟢 **Google Cybersecurity Professional Certificate** — Coursera, March 2026
- 🟢 **Put It to Work: Prepare for Cybersecurity Jobs** — Google, March 2026
- 🔵 **42 Madrid Fundación Telefónica** — Common Core (Systems & Security), Jan 2023 – Present
- ⬜ CompTIA Security+ *(in progress)*

---

## Background

Before focusing on security, I spent 3+ years at **Capgemini** as an SAP Application Consultant — managing L2/L3 incidents, debugging complex enterprise integrations, and maintaining 99.5% system availability for mission-critical SAP MES environments. That background gives me a perspective on security that goes beyond tools: I understand enterprise systems, how they fail, and how attackers think about the attack surface they expose.

---

*This portfolio is actively growing — new projects added regularly.*
