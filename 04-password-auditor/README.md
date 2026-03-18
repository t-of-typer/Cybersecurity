# 🔑 Password Auditor & Breach Checker

A Python password strength analyser that checks against NIST SP 800-63B guidelines and queries the HaveIBeenPwned (HIBP) API using **k-anonymity** — your password is never sent over the network. Zero external dependencies.

---

## How k-anonymity works (your password stays private)

```
Your password: "hunter2"
       │
       ▼
SHA-1 hash: F3BBBD66A63D4BF1747940578EC3D0103530E21D
       │
       ▼
Send ONLY first 5 chars: "F3BBB"  → api.pwnedpasswords.com/range/F3BBB
       │
       ▼
API returns ALL hashes starting with F3BBB (~500 results)
       │
       ▼
We check locally: does "D66A63D4BF1747940578EC3D0103530E21D" appear?
       │
       ▼
Yes → found in 17,043 breaches   |   No → not in any known breach
```

**Your actual password never leaves your machine.**

---

## Features

- **NIST SP 800-63B strength analysis** — length, entropy, character diversity
- **Pattern detection** — keyboard walks, sequential chars, date patterns, l33tspeak
- **Common password check** — built-in dictionary of 100+ most common passwords
- **Shannon entropy calculation** — measures true randomness in bits
- **Crack time estimate** — rough time to crack at 10 billion guesses/second
- **HaveIBeenPwned API** — checks against billions of known breached passwords
- **Interactive mode** — uses `getpass` to hide input (doesn't echo to terminal)
- **Batch mode** — audit an entire password list from a file
- **Score bar** — visual 0–100 strength score with A–F grade
- **Zero dependencies** — pure Python standard library

---

## Demo

```
  Enter password: ********

[*] Analysing…
[*] Checking breach database (k-anonymity)…

═════════════════════════════════════════════════════════════════
  PASSWORD AUDIT REPORT
═════════════════════════════════════════════════════════════════
  Password    : p*******3
  Length      : 9 characters
  Entropy     : 2.75 bits
  Charset     : 36 possible characters
  Crack time  : 3 minutes  (@ 10B guesses/sec)

  Score  : ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  16/100  [F]

  Types  : a-z  0-9  no A-Z  no !@#

  [BREACHED] Found in 7,718,791 known data breaches!
  This password has been exposed and should NEVER be used.

  Issues found:
    x  This is an extremely common password — appears in breach lists
    x  Missing: uppercase letters, special characters (!@#$...)
    x  Low entropy (2.75 bits) — too predictable

  Suggestions:
    >  Use a unique passphrase or password manager
    >  Add uppercase letters, special characters (!@#$...)
═════════════════════════════════════════════════════════════════
```

---

## Installation

No dependencies — pure Python standard library.

```bash
git clone https://github.com/t-of-typer/Cybersecurity.git
cd Cybersecurity/04-password-auditor
```

---

## Usage

```bash
# Interactive mode (recommended — hides input)
python password_auditor.py

# Audit a single password
python password_auditor.py -p "MyPassword123"

# Batch audit from file
python password_auditor.py --batch sample_passwords.txt

# Offline mode (no HIBP check)
python password_auditor.py --no-hibp

# Show full password in output (not masked)
python password_auditor.py --show

# Batch + offline + show
python password_auditor.py --batch passwords.txt --no-hibp --show
```

---

## Scoring System

| Score | Grade | Meaning |
|-------|-------|---------|
| 80–100 | A | Strong — good length, diversity, entropy |
| 65–79 | B | Good — minor improvements possible |
| 45–64 | C | Moderate — several weaknesses |
| 25–44 | D | Weak — significant issues |
| 0–24 | F | Very weak / common / breached |

Automatic penalties applied for: common passwords · repeated chars · keyboard walks · sequential patterns · date patterns · l33tspeak substitutions

---

## NIST SP 800-63B Compliance Checks

| Check | NIST Guidance |
|---|---|
| Minimum length | 8 chars min, 15+ recommended |
| Maximum length | No artificial cap (64+ supported) |
| Common passwords | Block passwords on known breach lists |
| Sequential patterns | Flag and penalise predictable sequences |
| Character requirements | Encourage all types, do not mandate specific combos |

---

## Project Structure

```
04-password-auditor/
├── password_auditor.py      # Main script
├── sample_passwords.txt     # Sample batch file for testing
└── README.md                # This file
```

---

## Skills Demonstrated

- SHA-1 hashing with Python's `hashlib`
- k-anonymity implementation for privacy-safe API calls
- Shannon entropy calculation
- Regex-based pattern detection
- NIST security framework knowledge
- REST API consumption with `urllib`
- Secure input handling with `getpass`
- Batch processing and CLI tooling with `argparse`

---

## Legal Notice

> For educational and authorised security auditing only.
> Do not use to audit passwords you do not own or have permission to test.

---

## Author

**Pedro Fousianis Dumitru**
Cybersecurity Analyst | Dublin, Ireland
[LinkedIn](https://linkedin.com/in/pedro-fousianis) · [GitHub](https://github.com/t-of-typer/Cybersecurity)
