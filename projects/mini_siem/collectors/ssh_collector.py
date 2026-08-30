"""
ssh_collector.py
----------------
Adapted from Day 09's ssh_bruteforce_detect.py.

The original script did parsing AND detection AND firewall-blocking all in
one file. In a SIEM, we split those jobs up:
    - a COLLECTOR just parses raw logs into normalized events (this file)
    - the RULE ENGINE (rules.py) decides what's suspicious
    - a future RESPONDER could do the actual blocking (kept separate on
      purpose -- you never want your parser also holding firewall access)

We reused the original regex almost as-is, and added a second regex for
successful logins ("Accepted password"/"Accepted publickey"), because the
brute-force rule in this project needs to see BOTH failures and the
eventual success to say "this wasn't just noise, they got in."
"""

import re
from datetime import datetime

from siem_core import log_event

FAILED_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed\s+(?:password|publickey)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

ACCEPTED_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def _to_iso(match, year):
    raw_time = f"{year} {match.group('month')} {match.group('day')} {match.group('time')}"
    dt = datetime.strptime(raw_time, "%Y %b %d %H:%M:%S")
    return dt.isoformat()


def collect(conn, log_path, year=None):
    """Parse an auth.log-style file for SSH login attempts and emit events."""
    year = year or datetime.now().year
    count = 0
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = FAILED_PATTERN.search(line)
            if m:
                log_event(
                    conn,
                    source="ssh",
                    event_type="auth_failed",
                    timestamp=_to_iso(m, year),
                    host=m.group("host"),
                    user=m.group("user"),
                    src_ip=m.group("ip"),
                    severity="low",
                    message=f"Failed SSH login for {m.group('user')} from {m.group('ip')}",
                    raw=line.strip(),
                )
                count += 1
                continue

            m = ACCEPTED_PATTERN.search(line)
            if m:
                log_event(
                    conn,
                    source="ssh",
                    event_type="auth_success",
                    timestamp=_to_iso(m, year),
                    host=m.group("host"),
                    user=m.group("user"),
                    src_ip=m.group("ip"),
                    severity="info",
                    message=f"Successful SSH login for {m.group('user')} from {m.group('ip')}",
                    raw=line.strip(),
                )
                count += 1
    return count
