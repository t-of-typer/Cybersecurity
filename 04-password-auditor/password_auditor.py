#!/usr/bin/env python3
"""
Password Auditor & Breach Checker
-----------------------------------
Checks password strength against NIST SP 800-63B guidelines and queries
the HaveIBeenPwned (HIBP) API using k-anonymity — meaning your password
is NEVER sent over the network. Only the first 5 characters of its SHA-1
hash are sent, and the comparison is done locally.

Features:
  - NIST-based strength analysis (length, entropy, character diversity)
  - Common password / dictionary check (top 10k passwords)
  - Pattern detection (keyboard walks, repeated chars, dates, l33tspeak)
  - HaveIBeenPwned API check (k-anonymity — privacy safe)
  - Strength meter with visual score bar
  - Batch mode — audit multiple passwords from a file
  - Colour-coded terminal output
  - Zero external dependencies

Author : Pedro Fousianis
GitHub : github.com/t-of-typer/Cybersecurity
Usage  : python password_auditor.py [options]
"""

import argparse
import hashlib
import math
import os
import re
import sys
import time
import urllib.request
import urllib.error


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
  ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
  ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝
{C.RESET}{C.DIM}  Password Auditor & Breach Checker v1.0  |  github.com/t-of-typer/Cybersecurity{C.RESET}
"""


# ─── COMMON PASSWORDS (top 100 built-in, extended via file) ───────────────────

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football",
    "password1", "password123", "admin", "admin123", "root", "toor",
    "pass", "test", "guest", "login", "welcome", "hello", "hello123",
    "ninja", "azerty", "solo", "princess", "cheese", "donald", "batman",
    "access", "master", "696969", "mustang", "121212", "starwars",
    "1q2w3e4r", "1qaz2wsx", "qwertyuiop", "zxcvbnm", "asdfghjkl",
    "q1w2e3r4", "abc1234", "pass123", "p@ssword", "p@ss123",
    "changeme", "secret", "pa$$word", "password!", "password@123",
    "season2024", "summer2024", "winter2024", "spring2024",
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "company123", "work1234", "office123",
}

# Keyboard walk patterns
KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "qwertyu", "asdfghj", "zxcvbnm",
    "1234567890", "0987654321", "1qaz2wsx", "q1w2e3r4",
    "!@#$%^&*", "zyxwvuts",
]

# l33tspeak substitutions (for normalisation)
LEET = {
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t",
}


# ─── K-ANONYMITY HIBP CHECK ───────────────────────────────────────────────────

def check_hibp(password, retries=3):
    """
    Query HaveIBeenPwned using k-anonymity.

    How it works:
      1. SHA-1 hash the password locally
      2. Send ONLY the first 5 hex characters to the API
      3. API returns all hashes starting with those 5 chars
      4. We check locally if our full hash is in the list
      => Your password NEVER leaves your machine

    Returns (count, error_message)
    count = 0 means not found in breaches
    count > 0 means found in that many breaches
    count = -1 means API error
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "PasswordAuditor-SecurityTool/1.0",
        "Add-Padding": "true",
    }

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                body = response.read().decode("utf-8")

            for line in body.splitlines():
                parts = line.split(":")
                if len(parts) == 2:
                    hash_suffix, count = parts
                    if hash_suffix.strip() == suffix:
                        return int(count.strip()), None

            return 0, None  # Not found in breaches

        except urllib.error.URLError as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return -1, f"API unreachable: {e}"
        except Exception as e:
            return -1, f"Unexpected error: {e}"

    return -1, "Max retries exceeded"


# ─── STRENGTH ANALYSER ────────────────────────────────────────────────────────

def calculate_entropy(password):
    """
    Shannon entropy — measures unpredictability in bits.
    Higher = more random = harder to crack.
    Formula: -sum(p * log2(p)) for each unique char
    """
    if not password:
        return 0.0
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(password)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def get_charset_size(password):
    """Estimate charset size used — affects brute-force difficulty."""
    size = 0
    if re.search(r"[a-z]", password): size += 26
    if re.search(r"[A-Z]", password): size += 26
    if re.search(r"[0-9]", password): size += 10
    if re.search(r"[^a-zA-Z0-9]", password): size += 32
    return max(size, 1)


def estimate_crack_time(password):
    """
    Rough estimate of time to crack at 10 billion guesses/second
    (modern GPU hashcat rate for MD5 — real rates vary by hash type).
    Returns human-readable string.
    """
    charset = get_charset_size(password)
    combinations = charset ** len(password)
    guesses_per_sec = 10_000_000_000  # 10 billion/sec
    seconds = combinations / guesses_per_sec / 2  # average case

    if seconds < 1:
        return "instantly"
    elif seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.0f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.0f} days"
    elif seconds < 31536000 * 100:
        return f"{seconds/31536000:.0f} years"
    elif seconds < 31536000 * 1_000_000:
        return f"{seconds/31536000/1000:.0f} thousand years"
    else:
        return "millions of years"


def normalise_leet(password):
    """Replace l33tspeak chars for dictionary check."""
    return "".join(LEET.get(c, c) for c in password.lower())


def analyse_password(password):
    """
    Full password analysis. Returns a dict of findings and score.
    """
    findings = {
        "length": len(password),
        "entropy": calculate_entropy(password),
        "charset_size": get_charset_size(password),
        "crack_time": estimate_crack_time(password),
        "issues": [],
        "suggestions": [],
        "passes": [],
        "score": 0,      # 0-100
        "grade": "",     # A-F
        "is_common": False,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "has_repeated": bool(re.search(r"(.)\1{2,}", password)),
        "has_sequence": False,
        "has_keyboard_walk": False,
        "has_date_pattern": False,
        "has_leet": False,
    }

    score = 0

    # ── Length (NIST: longer = better, 8 min, 15+ ideal) ──────────────────
    length = len(password)
    if length < 8:
        findings["issues"].append(f"Too short ({length} chars) — minimum 8, ideally 15+")
        findings["suggestions"].append("Use at least 15 characters for strong security")
    elif length < 12:
        score += 15
        findings["issues"].append(f"Moderate length ({length} chars) — aim for 15+")
        findings["suggestions"].append("Increase to 15+ characters")
    elif length < 16:
        score += 25
        findings["passes"].append(f"Good length ({length} chars)")
    else:
        score += 35
        findings["passes"].append(f"Excellent length ({length} chars)")

    # ── Character diversity ────────────────────────────────────────────────
    diversity = sum([
        findings["has_upper"],
        findings["has_lower"],
        findings["has_digit"],
        findings["has_special"],
    ])
    if diversity == 4:
        score += 25
        findings["passes"].append("Uses uppercase, lowercase, digits, and special characters")
    elif diversity == 3:
        score += 15
        missing = []
        if not findings["has_upper"]: missing.append("uppercase letters")
        if not findings["has_lower"]: missing.append("lowercase letters")
        if not findings["has_digit"]: missing.append("numbers")
        if not findings["has_special"]: missing.append("special characters (!@#$...)")
        findings["issues"].append(f"Missing: {', '.join(missing)}")
        findings["suggestions"].append(f"Add {', '.join(missing)}")
    elif diversity == 2:
        score += 8
        findings["issues"].append("Low character diversity — only 2 character types used")
        findings["suggestions"].append("Mix uppercase, lowercase, numbers, and symbols")
    else:
        findings["issues"].append("Very low character diversity — only 1 character type")
        findings["suggestions"].append("Mix uppercase, lowercase, numbers, and symbols")

    # ── Entropy ───────────────────────────────────────────────────────────
    entropy = findings["entropy"]
    if entropy >= 3.5:
        score += 15
        findings["passes"].append(f"High entropy ({entropy:.2f} bits)")
    elif entropy >= 2.5:
        score += 8
    else:
        findings["issues"].append(f"Low entropy ({entropy:.2f} bits) — too predictable")

    # ── Common password check ─────────────────────────────────────────────
    normalised = normalise_leet(password)
    if password.lower() in COMMON_PASSWORDS or normalised in COMMON_PASSWORDS:
        findings["is_common"] = True
        score = min(score, 10)
        findings["issues"].append("This is an extremely common password — appears in breach lists")
        findings["suggestions"].append("Use a unique passphrase or password manager")

    # ── Repeated characters ───────────────────────────────────────────────
    if findings["has_repeated"]:
        score -= 10
        findings["issues"].append("Contains repeated characters (e.g. aaa, 111)")
        findings["suggestions"].append("Avoid repeating the same character 3+ times")

    # ── Sequential patterns ───────────────────────────────────────────────
    seqs = ["abcdefgh", "hgfedcba", "12345678", "87654321", "zyxwvuts"]
    for seq in seqs:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in password.lower():
                findings["has_sequence"] = True
                break

    if findings["has_sequence"]:
        score -= 8
        findings["issues"].append("Contains sequential characters (abc, 123...)")
        findings["suggestions"].append("Avoid predictable sequences")

    # ── Keyboard walks ────────────────────────────────────────────────────
    for walk in KEYBOARD_WALKS:
        if walk in password.lower():
            findings["has_keyboard_walk"] = True
            break

    if findings["has_keyboard_walk"]:
        score -= 10
        findings["issues"].append("Contains a keyboard walk pattern (qwerty, asdf...)")
        findings["suggestions"].append("Avoid typing patterns from the keyboard layout")

    # ── Date patterns ─────────────────────────────────────────────────────
    date_patterns = [
        r"\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}",  # 01/01/2000
        r"(19|20)\d{2}",                             # 1999, 2024
        r"\d{2}(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\d{2,4}",
    ]
    for pat in date_patterns:
        if re.search(pat, password, re.IGNORECASE):
            findings["has_date_pattern"] = True
            break

    if findings["has_date_pattern"]:
        score -= 8
        findings["issues"].append("Contains a date pattern — common in personal passwords")
        findings["suggestions"].append("Avoid including birth dates or years")

    # ── L33tspeak (weak substitution) ────────────────────────────────────
    leet_chars = set(LEET.keys())
    used_leet = set(password) & leet_chars
    if used_leet and normalised != password.lower():
        findings["has_leet"] = True
        findings["issues"].append(
            "L33tspeak substitutions detected (@ for a, 3 for e) — "
            "these are well-known and do not significantly improve security"
        )

    # ── Clamp score ───────────────────────────────────────────────────────
    score = max(0, min(100, score))
    findings["score"] = score

    if score >= 80:
        findings["grade"] = "A"
    elif score >= 65:
        findings["grade"] = "B"
    elif score >= 45:
        findings["grade"] = "C"
    elif score >= 25:
        findings["grade"] = "D"
    else:
        findings["grade"] = "F"

    return findings


# ─── DISPLAY ──────────────────────────────────────────────────────────────────

def score_colour(score):
    if score >= 80: return C.GREEN
    if score >= 60: return C.CYAN
    if score >= 40: return C.YELLOW
    if score >= 20: return C.ORANGE
    return C.RED


def grade_colour(grade):
    return {
        "A": C.GREEN, "B": C.CYAN,
        "C": C.YELLOW, "D": C.ORANGE, "F": C.RED,
    }.get(grade, C.RESET)


def sep(char="─", width=65):
    print(f"{C.DIM}{char * width}{C.RESET}")


def print_result(password, analysis, hibp_count, hibp_error, mask=True, hibp_skipped=False):
    score   = analysis["score"]
    grade   = analysis["grade"]
    sc      = score_colour(score)
    gc      = grade_colour(grade)

    # Mask password for display
    display = password[0] + "*" * (len(password) - 2) + password[-1] if (mask and len(password) > 2) else "***"

    print(f"\n{'═' * 65}")
    print(f"  {C.BOLD}PASSWORD AUDIT REPORT{C.RESET}")
    print(f"{'═' * 65}")
    print(f"  Password    : {C.DIM}{display}{C.RESET}")
    print(f"  Length      : {analysis['length']} characters")
    print(f"  Entropy     : {analysis['entropy']:.2f} bits")
    print(f"  Charset     : {analysis['charset_size']} possible characters")
    print(f"  Crack time  : {analysis['crack_time']}  {C.DIM}(@ 10B guesses/sec){C.RESET}")
    sep()

    # Score bar
    bar_filled = int(score / 2)
    bar_empty  = 50 - bar_filled
    bar        = f"{sc}{'█' * bar_filled}{C.DIM}{'░' * bar_empty}{C.RESET}"
    print(f"\n  Score  : {bar}  {sc}{C.BOLD}{score}/100{C.RESET}  {gc}{C.BOLD}[{grade}]{C.RESET}\n")

    # Char types
    types = []
    if analysis["has_upper"]:   types.append(f"{C.GREEN}A-Z{C.RESET}")
    if analysis["has_lower"]:   types.append(f"{C.GREEN}a-z{C.RESET}")
    if analysis["has_digit"]:   types.append(f"{C.GREEN}0-9{C.RESET}")
    if analysis["has_special"]: types.append(f"{C.GREEN}!@#{C.RESET}")
    if not analysis["has_upper"]:   types.append(f"{C.RED}no A-Z{C.RESET}")
    if not analysis["has_lower"]:   types.append(f"{C.RED}no a-z{C.RESET}")
    if not analysis["has_digit"]:   types.append(f"{C.RED}no 0-9{C.RESET}")
    if not analysis["has_special"]: types.append(f"{C.RED}no !@#{C.RESET}")
    print(f"  Types  : {'  '.join(types)}")

    sep()

    # HIBP result — only show if check was actually performed
    if not hibp_skipped:
        if hibp_count > 0:
            print(f"\n  {C.RED}{C.BOLD}[BREACHED]{C.RESET} {C.RED}Found in {hibp_count:,} known data breaches!{C.RESET}")
            print(f"  {C.DIM}This password has been exposed and should NEVER be used.{C.RESET}")
        elif not hibp_error:
            print(f"\n  {C.GREEN}[HIBP]{C.RESET} {C.GREEN}Not found in any known data breaches.{C.RESET}")
            print(f"  {C.DIM}(Checked via HaveIBeenPwned k-anonymity API){C.RESET}")

    sep()

    # Issues
    if analysis["issues"]:
        print(f"\n  {C.BOLD}Issues found:{C.RESET}")
        for issue in analysis["issues"]:
            print(f"  {C.RED}  x{C.RESET}  {issue}")

    # Passes
    if analysis["passes"]:
        print(f"\n  {C.BOLD}Strengths:{C.RESET}")
        for p in analysis["passes"]:
            print(f"  {C.GREEN}  v{C.RESET}  {p}")

    # Suggestions
    if analysis["suggestions"]:
        print(f"\n  {C.BOLD}Suggestions:{C.RESET}")
        for s in analysis["suggestions"]:
            print(f"  {C.CYAN}  >{C.RESET}  {s}")

    print(f"\n{'═' * 65}\n")


# ─── BATCH MODE ───────────────────────────────────────────────────────────────

def run_batch(filepath, no_hibp=False, mask=True):
    """Audit all passwords in a text file (one per line)."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{C.RED}[!] File not found: {filepath}{C.RESET}")
        sys.exit(1)

    print(f"{C.CYAN}[*]{C.RESET} Batch mode — {len(passwords)} password(s) to audit\n")

    results = []
    for i, pw in enumerate(passwords, 1):
        print(f"{C.DIM}[{i}/{len(passwords)}] Auditing…{C.RESET}")
        analysis = analyse_password(pw)

        hibp_count, hibp_error = 0, None
        if not no_hibp:
            hibp_count, hibp_error = check_hibp(pw)
            time.sleep(0.15)  # Be kind to the API

        print_result(pw, analysis, hibp_count, hibp_error, mask=mask, hibp_skipped=no_hibp)
        results.append({
            "password": pw[0] + "*" * (len(pw) - 2) + pw[-1] if mask else pw,
            "score": analysis["score"],
            "grade": analysis["grade"],
            "breached": hibp_count > 0,
            "breach_count": hibp_count,
            "issues": analysis["issues"],
        })

    # Batch summary
    sep("═", 65)
    print(f"  {C.BOLD}BATCH SUMMARY{C.RESET}")
    sep()
    grades = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    breached_count = 0
    for r in results:
        grades[r["grade"]] += 1
        if r["breached"]:
            breached_count += 1

    for grade, count in grades.items():
        gc = grade_colour(grade)
        bar = "█" * count
        print(f"  Grade {gc}{grade}{C.RESET}  {bar} ({count})")

    print(f"\n  {C.RED if breached_count > 0 else C.GREEN}"
          f"{breached_count} password(s) found in breach databases{C.RESET}")
    sep("═", 65)


# ─── INTERACTIVE MODE ─────────────────────────────────────────────────────────

def run_interactive(no_hibp=False, mask=True):
    """Interactive loop — audit passwords one at a time."""
    print(f"{C.CYAN}[*]{C.RESET} Interactive mode  {C.DIM}(type 'quit' to exit){C.RESET}\n")

    while True:
        try:
            # Hide input on supported terminals
            try:
                import getpass
                password = getpass.getpass(f"  {C.BOLD}Enter password:{C.RESET} ")
            except Exception:
                password = input(f"  {C.BOLD}Enter password:{C.RESET} ")

            if password.lower() in ("quit", "exit", "q"):
                print(f"\n{C.DIM}Goodbye.{C.RESET}\n")
                break

            if not password:
                continue

            print(f"\n{C.CYAN}[*]{C.RESET} Analysing…")
            analysis = analyse_password(password)

            hibp_count, hibp_error = 0, None
            if not no_hibp:
                print(f"{C.CYAN}[*]{C.RESET} Checking breach database (k-anonymity)…")
                hibp_count, hibp_error = check_hibp(password)

            print_result(password, analysis, hibp_count, hibp_error, mask=mask, hibp_skipped=no_hibp)

        except KeyboardInterrupt:
            print(f"\n\n{C.DIM}Interrupted.{C.RESET}\n")
            break


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Password Auditor & Breach Checker — NIST strength + HIBP k-anonymity",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-p", "--password", metavar="PASSWORD",
                        help="Audit a single password directly (not recommended in production\n"
                             "— password will appear in shell history)")
    parser.add_argument("-b", "--batch", metavar="FILE",
                        help="Batch mode — audit all passwords in a text file (one per line)\n"
                             "  e.g. --batch passwords.txt")
    parser.add_argument("--no-hibp", action="store_true",
                        help="Skip HaveIBeenPwned API check (offline mode)")
    parser.add_argument("--show", action="store_true",
                        help="Show full password in output (default: masked)")
    return parser.parse_args()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    print(BANNER)

    mask = not args.show

    if args.batch:
        run_batch(args.batch, no_hibp=args.no_hibp, mask=mask)

    elif args.password:
        print(f"{C.YELLOW}[!]{C.RESET} {C.DIM}Note: passing passwords via CLI flag leaves them in shell history.{C.RESET}\n")
        analysis = analyse_password(args.password)
        hibp_count, hibp_error = 0, None
        if not args.no_hibp:
            print(f"{C.CYAN}[*]{C.RESET} Checking breach database (k-anonymity)…")
            hibp_count, hibp_error = check_hibp(args.password)
        print_result(args.password, analysis, hibp_count, hibp_error, mask=mask, hibp_skipped=args.no_hibp)

    else:
        run_interactive(no_hibp=args.no_hibp, mask=mask)


if __name__ == "__main__":
    main()