"""
identity_collector.py
----------------------
New collector (no Day-X script covered this, but it lives in the same
auth.log the SSH collector reads, so it's a natural addition).

Parses two kinds of real Linux auth.log lines:
    useradd[1234]: new user: name=bob, UID=1002, GID=1002, home=/home/bob, shell=/bin/bash
    usermod[1234]: add 'bob' to group 'sudo'

Also parses simple "defense evasion" style lines that show up in the same
auth.log stream on a real box (firewall disabled, logs cleared, security
service stopped), e.g.:
    Aug 30 22:21:00 web01 root: ufw disable
    Aug 30 22:22:00 web01 root: auth.log cleared
    Aug 30 22:23:00 web01 systemctl[500]: Stopped auditd.service

These feed:
    Rule: Account Creation Outside Business Hours
    Rule: Privilege Group Modification
    Rule: Security Service / Log Tampering
"""

import re
from datetime import datetime

from siem_core import log_event

TIMESTAMP_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
)

USERADD_PATTERN = re.compile(r"useradd\[\d+\]:\s+new user:\s+name=(?P<user>[^,]+),")
USERMOD_PATTERN = re.compile(r"usermod\[\d+\]:\s+add\s+'(?P<user>[^']+)'\s+to\s+group\s+'(?P<group>[^']+)'")

HIGH_PRIV_GROUPS = {"sudo", "wheel", "admin", "administrators", "domain admins"}

TAMPER_PATTERNS = [
    (re.compile(r"ufw\s+disable"), "firewall_disabled", "UFW firewall disabled"),
    (re.compile(r"netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off"), "firewall_disabled", "Windows firewall disabled"),
    (re.compile(r"auth\.log\s+cleared|wevtutil\s+cl"), "log_cleared", "Security log cleared"),
    (re.compile(r"systemctl\[\d+\]:\s+Stopped\s+(?P<svc>\S+)"), "service_stopped", "Security service stopped"),
]


def _to_iso(prefix_match, year):
    raw_time = f"{year} {prefix_match.group('month')} {prefix_match.group('day')} {prefix_match.group('time')}"
    return datetime.strptime(raw_time, "%Y %b %d %H:%M:%S").isoformat()


def collect(conn, log_path, year=None):
    year = year or datetime.now().year
    count = 0
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            prefix = TIMESTAMP_PREFIX.search(line)
            if not prefix:
                continue
            ts = _to_iso(prefix, year)
            host = prefix.group("host")

            m = USERADD_PATTERN.search(line)
            if m:
                log_event(
                    conn,
                    source="identity",
                    event_type="user_created",
                    timestamp=ts,
                    host=host,
                    user=m.group("user"),
                    severity="info",
                    message=f"New local user created: {m.group('user')}",
                    raw=line.strip(),
                )
                count += 1
                continue

            m = USERMOD_PATTERN.search(line)
            if m:
                group = m.group("group").lower()
                sev = "high" if group in HIGH_PRIV_GROUPS else "info"
                log_event(
                    conn,
                    source="identity",
                    event_type="group_modified",
                    timestamp=ts,
                    host=host,
                    user=m.group("user"),
                    severity=sev,
                    message=f"User {m.group('user')} added to group '{group}'",
                    raw=line.strip() + f"|group={group}",
                )
                count += 1
                continue

            for pattern, event_type, label in TAMPER_PATTERNS:
                tm = pattern.search(line)
                if tm:
                    detail = tm.groupdict().get("svc") if tm.groupdict().get("svc") else ""
                    log_event(
                        conn,
                        source="identity",
                        event_type=event_type,
                        timestamp=ts,
                        host=host,
                        user=None,
                        severity="critical",
                        message=f"{label}{(': ' + detail) if detail else ''}",
                        raw=line.strip(),
                    )
                    count += 1
                    break
    return count
