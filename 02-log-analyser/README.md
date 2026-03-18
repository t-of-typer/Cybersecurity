# 🔎 Log Analyser & Anomaly Detector

A Python-based SSH authentication log analyser that parses Linux `auth.log` files to detect suspicious activity, generate threat summaries, and produce clean reports — with zero external dependencies.

Built as part of a hands-on cybersecurity portfolio to demonstrate practical knowledge of SOC analysis, log parsing, threat detection patterns, and Python scripting.

---

## Features

- **Brute force detection** — flags IPs exceeding a configurable failed-login threshold
- **Credential stuffing detection** — identifies IPs trying many different usernames
- **Success-after-failure alerts** — catches IPs that failed repeatedly then logged in (possible compromise)
- **Off-hours login detection** — flags logins outside business hours (configurable window)
- **Top attacking IPs** — ranked bar chart of most aggressive sources
- **Most targeted usernames** — shows what accounts attackers are probing
- **Sudo activity log** — tracks privileged command execution
- **Threat severity scoring** — CRITICAL / HIGH / MEDIUM / LOW summary
- **Auto report export** — saves findings to timestamped `.txt` file
- **Built-in demo mode** — generates a realistic fake log to test against
- **Zero dependencies** — pure Python standard library only

---

## Demo

```
[*] Loading log file: sample_logs/demo_auth.log
[*] Parsing 89 lines…
[*] Running anomaly detection…

══════════════════════════════════════════════════════════════════════
  ANALYSIS REPORT
══════════════════════════════════════════════════════════════════════
  Failed logins          58
  Successful logins       7
  Sudo commands           2

  [CRITICAL] Brute Force Attempts  (2 source(s) detected)

  IP ADDRESS           ATTEMPTS  FIRST SEEN           TARGETED USERS
  ────────────────────────────────────────────────────────────────────
  185.234.219.42            30  Mar 14 03:00:01      root, admin, ubuntu +2 more
  45.142.212.100             8  Mar 14 11:00:03      root

  [CRITICAL] Successful Login After Brute Force  (1 event(s))

  ⚠  These IPs failed repeatedly then succeeded — possible compromise!
  185.234.219.42       user: root  at Mar 14 03:59:59  (30 prior failures)

  [HIGH] Credential Stuffing  (1 source(s) detected)

  91.108.4.77           tried 12 usernames  admin, test, oracle +9 more

  THREAT SUMMARY
  CRITICAL  3
  HIGH      1
  MEDIUM    2

  Overall: ⚠  HIGH RISK — investigate immediately
```

---

## Installation

No dependencies required — uses Python standard library only.

```bash
git clone https://github.com/t-of-typer/log-analyser.git
cd log-analyser
```

---

## Usage

```bash
# Run against a real Linux auth log (may need sudo)
sudo python3 log_analyser.py -f /var/log/auth.log

# Generate a demo log and analyse it (works on Windows/Mac/Linux)
python3 log_analyser.py --demo

# Save report to a specific file
python3 log_analyser.py --demo -o my_report.txt

# Custom thresholds
python3 log_analyser.py -f /var/log/auth.log --brute-threshold 10 --off-hours-start 20 --off-hours-end 7

# Windows — run with demo log
python log_analyser.py --demo
```

---

## Detection Logic

| Detection | Method | Default Threshold |
|---|---|---|
| Brute force | Failed logins from single IP | ≥ 5 attempts |
| Credential stuffing | Distinct usernames from single IP | ≥ 3 usernames |
| Success after failure | Successful login from known brute-force IP | any |
| Off-hours login | Successful login outside business hours | 22:00 – 06:00 |

All thresholds are configurable via CLI flags.

---

## Project Structure

```
log-analyser/
├── log_analyser.py        # Main script
├── README.md              # This file
├── sample_logs/
│   └── demo_auth.log      # Auto-generated demo log
└── reports/
    └── log_report_*.txt   # Auto-saved reports
```

---

## Skills Demonstrated

- Log parsing and pattern matching with `re` (regex)
- Python data structures — `defaultdict`, `Counter`, collections
- Security analysis methodology — brute force, credential stuffing, lateral movement indicators
- SIEM-style detection logic (mirrors Splunk/Chronicle rule concepts)
- CLI tooling with `argparse`
- File I/O and automated report generation
- Understanding of Linux `auth.log` format and SSH authentication flow

---

## Extending This Tool

Ideas for further development:
- [ ] GeoIP lookup for attacking IPs (using `ip-api.com`)
- [ ] Slack/email alert integration
- [ ] Support for `/var/log/secure` (RHEL/CentOS format)
- [ ] JSON output for SIEM ingestion
- [ ] Watchdog mode — tail live log file and alert in real time
- [ ] Whitelist for known-good IPs

---

## Legal Notice

> This tool is for **defensive, educational, and authorised use only**.
> Only analyse logs from systems you own or have explicit permission to monitor.

---

## Author

**Pedro Fousianis Dumitru**
Cybersecurity Analyst | Dublin, Ireland
[LinkedIn](https://linkedin.com/in/pedro-fousianis) · [GitHub](https://github.com/t-of-typer)
