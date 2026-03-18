#!/usr/bin/env python3
"""
Log Analyser & Anomaly Detector
--------------------------------
Parses Linux authentication logs (/var/log/auth.log) to detect suspicious
activity including brute-force attempts, credential stuffing, successful
logins after failures, and off-hours access.

Outputs a colour-coded terminal report and saves findings to a text file.

Author : Pedro Fousianis
GitHub : github.com/t-of-typer
Usage  : python3 log_analyser.py -f /var/log/auth.log [options]
         python3 log_analyser.py -f sample_logs/auth.log --demo
"""

import argparse
import collections
import datetime
import ipaddress
import os
import re
import sys


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

BANNER = f"""
{C.CYAN}{C.BOLD}
  ██╗      ██████╗  ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
  ██║     ██╔═══██╗██╔════╝     ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗
  ██║     ██║   ██║██║  ███╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗█████╗  ██████╔╝
  ██║     ██║   ██║██║   ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██╔══╝  ██╔══██╗
  ███████╗╚██████╔╝╚██████╔╝    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║███████╗██║  ██║
  ╚══════╝ ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
{C.RESET}{C.DIM}  Log Analyser & Anomaly Detector v1.0  |  github.com/t-of-typer{C.RESET}
"""


# ─── THRESHOLDS ───────────────────────────────────────────────────────────────

THRESHOLDS = {
    "brute_force_attempts": 5,       # Failed logins from one IP before alert
    "credential_stuffing_users": 3,  # Distinct usernames tried from one IP
    "off_hours_start": 22,           # 10 PM
    "off_hours_end": 6,              # 6 AM
    "top_ips": 10,                   # How many IPs to show in summary
}


# ─── REGEX PATTERNS ───────────────────────────────────────────────────────────

PATTERNS = {
    # Failed password: sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
    "failed_password": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+) port"
    ),
    # Accepted password/publickey
    "accepted_login": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) from (\S+) port"
    ),
    # Invalid user
    "invalid_user": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*sshd\[\d+\]: Invalid user (\S+) from (\S+)"
    ),
    # Disconnected / connection closed
    "disconnected": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*sshd\[\d+\]: Disconnected from (?:invalid user )?(\S+)? ?(\S+) port"
    ),
    # sudo usage
    "sudo": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*sudo.*:\s+(\S+) : .*COMMAND=(.*)"
    ),
    # New session opened (su/sudo)
    "session_opened": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*session opened for user (\S+)"
    ),
}


# ─── LOG PARSER ───────────────────────────────────────────────────────────────

class LogParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.lines = []
        self.events = {
            "failed": [],       # (timestamp_str, user, ip)
            "accepted": [],     # (timestamp_str, user, ip)
            "invalid_user": [], # (timestamp_str, user, ip)
            "sudo": [],         # (timestamp_str, user, command)
            "sessions": [],     # (timestamp_str, user)
        }

    def load(self):
        try:
            with open(self.filepath, "r", errors="replace") as f:
                self.lines = f.readlines()
            return True
        except FileNotFoundError:
            print(f"{C.RED}[!] File not found: {self.filepath}{C.RESET}")
            return False
        except PermissionError:
            print(f"{C.RED}[!] Permission denied. Try: sudo python3 log_analyser.py ...{C.RESET}")
            return False

    def parse(self):
        for line in self.lines:
            for event_type, pattern in PATTERNS.items():
                match = pattern.search(line)
                if match:
                    groups = match.groups()
                    if event_type == "failed_password":
                        self.events["failed"].append(groups)
                    elif event_type == "accepted_login":
                        self.events["accepted"].append(groups)
                    elif event_type == "invalid_user":
                        self.events["invalid_user"].append(groups)
                    elif event_type == "sudo":
                        self.events["sudo"].append(groups)
                    elif event_type == "session_opened":
                        self.events["sessions"].append(groups)
                    break  # One match per line is enough


# ─── ANOMALY DETECTOR ─────────────────────────────────────────────────────────

class AnomalyDetector:
    def __init__(self, events):
        self.events = events
        self.findings = {
            "brute_force": [],
            "credential_stuffing": [],
            "success_after_failure": [],
            "off_hours_logins": [],
            "top_attacking_ips": [],
            "invalid_users": [],
        }

    def parse_time(self, ts_str):
        """Parse syslog timestamp (no year) into datetime, assume current year."""
        try:
            year = datetime.datetime.now().year
            return datetime.datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None

    def is_off_hours(self, ts_str):
        dt = self.parse_time(ts_str)
        if not dt:
            return False
        h = dt.hour
        return h >= THRESHOLDS["off_hours_start"] or h < THRESHOLDS["off_hours_end"]

    def is_private_ip(self, ip_str):
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False

    def run(self):
        self._detect_brute_force()
        self._detect_credential_stuffing()
        self._detect_success_after_failure()
        self._detect_off_hours()
        self._top_attacking_ips()
        self._summarise_invalid_users()
        return self.findings

    def _detect_brute_force(self):
        """IPs with >= threshold failed attempts."""
        ip_failures = collections.defaultdict(list)
        for ts, user, ip in self.events["failed"]:
            ip_failures[ip].append((ts, user))

        for ip, attempts in ip_failures.items():
            if len(attempts) >= THRESHOLDS["brute_force_attempts"]:
                self.findings["brute_force"].append({
                    "ip": ip,
                    "count": len(attempts),
                    "first_seen": attempts[0][0],
                    "last_seen": attempts[-1][0],
                    "targeted_users": list({a[1] for a in attempts}),
                    "private": self.is_private_ip(ip),
                })
        # Sort by count descending
        self.findings["brute_force"].sort(key=lambda x: x["count"], reverse=True)

    def _detect_credential_stuffing(self):
        """IPs trying many different usernames — credential stuffing pattern."""
        ip_users = collections.defaultdict(set)
        for ts, user, ip in self.events["failed"]:
            ip_users[ip].add(user)
        for ts, user, ip in self.events["invalid_user"]:
            ip_users[ip].add(user)

        for ip, users in ip_users.items():
            if len(users) >= THRESHOLDS["credential_stuffing_users"]:
                self.findings["credential_stuffing"].append({
                    "ip": ip,
                    "user_count": len(users),
                    "users": list(users)[:10],  # cap display at 10
                })
        self.findings["credential_stuffing"].sort(key=lambda x: x["user_count"], reverse=True)

    def _detect_success_after_failure(self):
        """IPs that failed multiple times then succeeded — possible successful attack."""
        failed_ips = collections.defaultdict(int)
        for ts, user, ip in self.events["failed"]:
            failed_ips[ip] += 1

        for ts, user, ip in self.events["accepted"]:
            if failed_ips.get(ip, 0) >= THRESHOLDS["brute_force_attempts"]:
                self.findings["success_after_failure"].append({
                    "ip": ip,
                    "user": user,
                    "timestamp": ts,
                    "prior_failures": failed_ips[ip],
                })

    def _detect_off_hours(self):
        """Successful logins outside business hours."""
        for ts, user, ip in self.events["accepted"]:
            if self.is_off_hours(ts):
                self.findings["off_hours_logins"].append({
                    "timestamp": ts,
                    "user": user,
                    "ip": ip,
                    "private": self.is_private_ip(ip),
                })

    def _top_attacking_ips(self):
        ip_count = collections.Counter(ip for _, _, ip in self.events["failed"])
        self.findings["top_attacking_ips"] = ip_count.most_common(THRESHOLDS["top_ips"])

    def _summarise_invalid_users(self):
        user_count = collections.Counter(user for _, user, _ in self.events["invalid_user"])
        self.findings["invalid_users"] = user_count.most_common(10)


# ─── REPORTER ─────────────────────────────────────────────────────────────────

def severity_colour(level):
    return {
        "CRITICAL": C.RED,
        "HIGH":     C.ORANGE,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.DIM,
        "INFO":     C.CYAN,
    }.get(level, C.RESET)


def sep(char="─", width=70):
    print(f"{C.DIM}{char * width}{C.RESET}")


def print_report(events, findings, filepath, elapsed):
    total_lines   = sum(len(v) for v in events.values())
    total_failed  = len(events["failed"])
    total_success = len(events["accepted"])
    total_sudo    = len(events["sudo"])

    print(f"\n{C.BOLD}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}  ANALYSIS REPORT{C.RESET}")
    print(f"{'═' * 70}")
    print(f"  File      : {C.CYAN}{filepath}{C.RESET}")
    print(f"  Analysed  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Scan time : {elapsed:.2f}s")
    sep()
    print(f"  {C.BOLD}Event totals{C.RESET}")
    print(f"  {'Failed logins':<28} {C.RED}{total_failed}{C.RESET}")
    print(f"  {'Successful logins':<28} {C.GREEN}{total_success}{C.RESET}")
    print(f"  {'Sudo commands':<28} {C.YELLOW}{total_sudo}{C.RESET}")
    print(f"  {'Invalid user attempts':<28} {len(events['invalid_user'])}")
    sep()

    # ── Brute Force ──────────────────────────────────────────────────────────
    bf = findings["brute_force"]
    lvl = "CRITICAL" if bf else "INFO"
    col = severity_colour(lvl)
    print(f"\n  {col}{C.BOLD}[{lvl}] Brute Force Attempts{C.RESET}  ({len(bf)} source(s) detected)")

    if bf:
        print(f"\n  {'IP ADDRESS':<20} {'ATTEMPTS':>9}  {'FIRST SEEN':<20}  TARGETED USERS")
        sep("-", 70)
        for item in bf[:15]:
            users_preview = ", ".join(item["targeted_users"][:4])
            if len(item["targeted_users"]) > 4:
                users_preview += f" +{len(item['targeted_users'])-4} more"
            flag = f" {C.DIM}(internal){C.RESET}" if item["private"] else ""
            print(f"  {C.RED}{item['ip']:<20}{C.RESET} {item['count']:>9}  "
                  f"{item['first_seen']:<20}  {C.DIM}{users_preview}{C.RESET}{flag}")
    else:
        print(f"  {C.GREEN}No brute force activity detected.{C.RESET}")

    # ── Credential Stuffing ───────────────────────────────────────────────────
    cs = findings["credential_stuffing"]
    lvl = "HIGH" if cs else "INFO"
    col = severity_colour(lvl)
    print(f"\n  {col}{C.BOLD}[{lvl}] Credential Stuffing{C.RESET}  ({len(cs)} source(s) detected)")

    if cs:
        print(f"\n  {'IP ADDRESS':<20} {'USERNAMES TRIED':>15}")
        sep("-", 70)
        for item in cs[:10]:
            users_preview = ", ".join(item["users"][:5])
            if len(item["users"]) > 5:
                users_preview += f" +{len(item['users'])-5} more"
            print(f"  {C.ORANGE}{item['ip']:<20}{C.RESET} {item['user_count']:>15}  "
                  f"{C.DIM}{users_preview}{C.RESET}")
    else:
        print(f"  {C.GREEN}No credential stuffing patterns detected.{C.RESET}")

    # ── Success After Failure ─────────────────────────────────────────────────
    saf = findings["success_after_failure"]
    lvl = "CRITICAL" if saf else "INFO"
    col = severity_colour(lvl)
    print(f"\n  {col}{C.BOLD}[{lvl}] Successful Login After Brute Force{C.RESET}  ({len(saf)} event(s))")

    if saf:
        print(f"\n  {C.RED}⚠  These IPs failed repeatedly then succeeded — possible compromise!{C.RESET}")
        sep("-", 70)
        for item in saf:
            print(f"  {C.RED}{item['ip']:<20}{C.RESET}  user: {C.BOLD}{item['user']}{C.RESET}  "
                  f"at {item['timestamp']}  "
                  f"({C.RED}{item['prior_failures']} prior failures{C.RESET})")
    else:
        print(f"  {C.GREEN}No suspicious successful logins detected.{C.RESET}")

    # ── Off-Hours Logins ──────────────────────────────────────────────────────
    oh = findings["off_hours_logins"]
    lvl = "MEDIUM" if oh else "INFO"
    col = severity_colour(lvl)
    print(f"\n  {col}{C.BOLD}[{lvl}] Off-Hours Logins{C.RESET}  "
          f"(between {THRESHOLDS['off_hours_start']}:00–{THRESHOLDS['off_hours_end']:02d}:00)  "
          f"({len(oh)} event(s))")

    if oh:
        sep("-", 70)
        for item in oh[:10]:
            flag = f" {C.DIM}(internal){C.RESET}" if item["private"] else f" {C.YELLOW}(external){C.RESET}"
            print(f"  {item['timestamp']:<22} user: {C.BOLD}{item['user']:<15}{C.RESET} "
                  f"from {item['ip']}{flag}")
        if len(oh) > 10:
            print(f"  {C.DIM}  … and {len(oh)-10} more{C.RESET}")
    else:
        print(f"  {C.GREEN}No off-hours logins detected.{C.RESET}")

    # ── Top Attacking IPs ─────────────────────────────────────────────────────
    tai = findings["top_attacking_ips"]
    if tai:
        print(f"\n  {C.BOLD}Top Attacking IPs (by failed attempts){C.RESET}")
        sep("-", 70)
        max_count = tai[0][1] if tai else 1
        for rank, (ip, count) in enumerate(tai, 1):
            bar_len = int((count / max_count) * 30)
            bar = "█" * bar_len
            print(f"  {rank:>2}. {C.RED}{ip:<20}{C.RESET}  {count:>5}  {C.DIM}{bar}{C.RESET}")

    # ── Most Targeted Invalid Users ───────────────────────────────────────────
    iu = findings["invalid_users"]
    if iu:
        print(f"\n  {C.BOLD}Most Targeted Usernames (invalid user attempts){C.RESET}")
        sep("-", 70)
        for user, count in iu:
            print(f"  {C.DIM}{'•'}{C.RESET} {user:<20} {count} attempts")

    # ── Sudo Activity ─────────────────────────────────────────────────────────
    if events["sudo"]:
        print(f"\n  {C.BOLD}Sudo Command Activity{C.RESET}")
        sep("-", 70)
        for ts, user, cmd in events["sudo"][:10]:
            print(f"  {ts:<22}  {C.YELLOW}{user:<15}{C.RESET}  {C.DIM}{cmd[:50]}{C.RESET}")
        if len(events["sudo"]) > 10:
            print(f"  {C.DIM}  … and {len(events['sudo'])-10} more sudo events{C.RESET}")

    # ── Final Score ───────────────────────────────────────────────────────────
    critical = len(bf) + len(saf)
    high     = len(cs)
    medium   = len(oh)

    print(f"\n{'═' * 70}")
    print(f"  {C.BOLD}THREAT SUMMARY{C.RESET}")
    sep("-", 70)
    print(f"  {C.RED}CRITICAL{C.RESET}  {critical}  (brute force sources + successful-after-failure)")
    print(f"  {C.ORANGE}HIGH{C.RESET}      {high}  (credential stuffing sources)")
    print(f"  {C.YELLOW}MEDIUM{C.RESET}    {medium}  (off-hours logins)")

    if critical > 0:
        overall = f"{C.RED}⚠  HIGH RISK — investigate immediately{C.RESET}"
    elif high > 0:
        overall = f"{C.ORANGE}⚠  ELEVATED — review flagged IPs{C.RESET}"
    elif medium > 0:
        overall = f"{C.YELLOW}ℹ  LOW — monitor off-hours activity{C.RESET}"
    else:
        overall = f"{C.GREEN}✓  CLEAN — no significant anomalies{C.RESET}"

    print(f"\n  Overall: {overall}")
    print(f"{'═' * 70}\n")


# ─── FILE EXPORT ──────────────────────────────────────────────────────────────

def export_report(events, findings, filepath, output_path):
    total_failed  = len(events["failed"])
    total_success = len(events["accepted"])
    lines = [
        "=" * 70,
        "  LOG ANALYSER & ANOMALY DETECTOR — REPORT",
        "=" * 70,
        f"  File      : {filepath}",
        f"  Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-" * 70,
        f"  Failed logins    : {total_failed}",
        f"  Successful logins: {total_success}",
        f"  Sudo events      : {len(events['sudo'])}",
        "",
        "BRUTE FORCE ATTEMPTS",
        "-" * 70,
    ]
    for item in findings["brute_force"]:
        lines.append(f"  {item['ip']:<20} {item['count']:>6} attempts  "
                     f"users: {', '.join(item['targeted_users'][:5])}")

    lines += ["", "CREDENTIAL STUFFING", "-" * 70]
    for item in findings["credential_stuffing"]:
        lines.append(f"  {item['ip']:<20} tried {item['user_count']} usernames")

    lines += ["", "SUCCESS AFTER BRUTE FORCE", "-" * 70]
    for item in findings["success_after_failure"]:
        lines.append(f"  {item['ip']:<20} user: {item['user']}  at {item['timestamp']}")

    lines += ["", "OFF-HOURS LOGINS", "-" * 70]
    for item in findings["off_hours_logins"]:
        lines.append(f"  {item['timestamp']:<22} user: {item['user']:<15} from {item['ip']}")

    lines += ["", "=" * 70]

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    print(f"{C.GREEN}[+] Report saved → {output_path}{C.RESET}")


# ─── DEMO LOG GENERATOR ───────────────────────────────────────────────────────

def generate_demo_log(path):
    """
    Generates a realistic fake auth.log for demonstration purposes.
    Includes brute force, credential stuffing, off-hours login, and clean activity.
    """
    import random

    months = ["Jan", "Feb", "Mar"]
    m = random.choice(months)

    attacker1 = "185.234.219.42"   # Brute force attacker
    attacker2 = "91.108.4.77"      # Credential stuffer
    attacker3 = "45.142.212.100"   # Low-level scanner
    legit_user = "pedro"
    server     = "webserver01"

    lines = []

    def ts(day, hour, minute, second):
        return f"{m} {day:2d} {hour:02d}:{minute:02d}:{second:02d}"

    # Normal activity
    for i in range(5):
        lines.append(f"{ts(14, 9, i*3, 10)} {server} sshd[1001]: Accepted password for {legit_user} from 192.168.1.5 port 5522{i} ssh2")
        lines.append(f"{ts(14, 9, i*3, 11)} {server} sshd[1001]: pam_unix(sshd:session): session opened for user {legit_user} by (uid=0)")

    # Brute force from attacker1 — 30 failures
    users_bf = ["root", "admin", "ubuntu", "deploy", "git"]
    for i in range(30):
        u = users_bf[i % len(users_bf)]
        lines.append(f"{ts(14, 3, i % 59, i % 59)} {server} sshd[2{i:03d}]: Failed password for {u} from {attacker1} port {40000+i} ssh2")

    # Successful login from attacker1 after brute force
    lines.append(f"{ts(14, 3, 59, 59)} {server} sshd[2999]: Accepted password for root from {attacker1} port 41234 ssh2")

    # Credential stuffing from attacker2 — many different usernames
    stuffed_users = ["admin", "test", "user1", "oracle", "postgres", "mysql",
                     "ftp", "mail", "backup", "www-data", "jenkins", "tomcat"]
    for i, u in enumerate(stuffed_users):
        lines.append(f"{ts(14, 14, i, 10)} {server} sshd[3{i:03d}]: Invalid user {u} from {attacker2}")
        lines.append(f"{ts(14, 14, i, 11)} {server} sshd[3{i:03d}]: Failed password for invalid user {u} from {attacker2} port {50000+i} ssh2")

    # Off-hours legitimate (late night)
    lines.append(f"{ts(14, 23, 45, 12)} {server} sshd[4001]: Accepted password for {legit_user} from 192.168.1.10 port 6000 ssh2")
    lines.append(f"{ts(14, 2, 15, 30)} {server} sshd[4002]: Accepted password for {legit_user} from 203.0.113.55 port 6001 ssh2")

    # Low-level scanner
    for i in range(8):
        lines.append(f"{ts(14, 11, i*5, i)} {server} sshd[5{i:03d}]: Failed password for root from {attacker3} port {60000+i} ssh2")

    # Sudo activity
    lines.append(f"{ts(14, 9, 30, 0)} {server} sudo: {legit_user} : TTY=pts/0 ; PWD=/home/{legit_user} ; USER=root ; COMMAND=/usr/bin/apt update")
    lines.append(f"{ts(14, 9, 31, 5)} {server} sudo: {legit_user} : TTY=pts/0 ; PWD=/home/{legit_user} ; USER=root ; COMMAND=/bin/systemctl restart nginx")

    # Shuffle to simulate real log ordering
    random.shuffle(lines)

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"{C.GREEN}[+] Demo log generated → {path}{C.RESET}")
    print(f"{C.DIM}    Contains: brute force, credential stuffing, off-hours logins, sudo activity{C.RESET}\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Log Analyser & Anomaly Detector — SSH auth log parser",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-f", "--file", default="/var/log/auth.log",
                        help="Path to auth.log file (default: /var/log/auth.log)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save report to text file")
    parser.add_argument("--demo", action="store_true",
                        help="Generate a demo auth.log and analyse it")
    parser.add_argument("--brute-threshold", type=int,
                        default=THRESHOLDS["brute_force_attempts"],
                        help=f"Failed attempts before brute force alert (default: {THRESHOLDS['brute_force_attempts']})")
    parser.add_argument("--off-hours-start", type=int,
                        default=THRESHOLDS["off_hours_start"],
                        help=f"Off-hours window start (24h, default: {THRESHOLDS['off_hours_start']})")
    parser.add_argument("--off-hours-end", type=int,
                        default=THRESHOLDS["off_hours_end"],
                        help=f"Off-hours window end (24h, default: {THRESHOLDS['off_hours_end']})")
    return parser.parse_args()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    print(BANNER)

    # Apply custom thresholds
    THRESHOLDS["brute_force_attempts"]  = args.brute_threshold
    THRESHOLDS["off_hours_start"]       = args.off_hours_start
    THRESHOLDS["off_hours_end"]         = args.off_hours_end

    filepath = args.file

    # Demo mode — generate fake log
    if args.demo:
        demo_path = "sample_logs/demo_auth.log"
        os.makedirs("sample_logs", exist_ok=True)
        generate_demo_log(demo_path)
        filepath = demo_path

    # Parse
    print(f"{C.CYAN}[*]{C.RESET} Loading log file: {C.BOLD}{filepath}{C.RESET}")
    parser = LogParser(filepath)
    if not parser.load():
        sys.exit(1)

    print(f"{C.CYAN}[*]{C.RESET} Parsing {len(parser.lines):,} lines…")
    start = datetime.datetime.now()
    parser.parse()

    # Detect
    print(f"{C.CYAN}[*]{C.RESET} Running anomaly detection…")
    detector = AnomalyDetector(parser.events)
    findings = detector.run()
    elapsed = (datetime.datetime.now() - start).total_seconds()

    # Print
    print_report(parser.events, findings, filepath, elapsed)

    # Export
    if args.output:
        export_report(parser.events, findings, filepath, args.output)
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        auto_path = f"reports/log_report_{ts}.txt"
        os.makedirs("reports", exist_ok=True)
        export_report(parser.events, findings, filepath, auto_path)


if __name__ == "__main__":
    main()
