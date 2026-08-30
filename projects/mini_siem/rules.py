"""
rules.py
--------
Every rule follows the same shape: read some events, look for the pattern,
call log_alert() when it matches. Rules never touch raw log files -- that's
the whole point of normalizing everything into the `events` table first.

Each rule function returns the number of alerts it raised, and run_all()
sums them up so the CLI can print a one-line summary.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

from siem_core import log_alert

HIGH_PRIV_GROUPS = {"sudo", "wheel", "admin", "administrators", "domain admins"}
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = timedelta(seconds=60)


def _ts(row):
    return datetime.fromisoformat(row["timestamp"])


# ---------------------------------------------------------------------------
# 1. Authentication & Identity
# ---------------------------------------------------------------------------

def rule_bruteforce(conn):
    """>=5 failed logins for a user, followed by a success for that same
    user, all within a 5-minute window. This is what actually distinguishes
    a successful brute-force from someone who just fat-fingered their
    password a few times."""
    events = conn.execute(
        "SELECT * FROM events WHERE event_type IN ('auth_failed','auth_success') "
        "ORDER BY timestamp"
    ).fetchall()

    failures = defaultdict(list)  # user -> [ (timestamp, event_row) ]
    alerted_users = set()
    count = 0

    for row in events:
        user = row["user"]
        if row["event_type"] == "auth_failed":
            failures[user].append(row)
            # keep only failures inside the sliding window
            cutoff = _ts(row) - BRUTE_FORCE_WINDOW
            failures[user] = [r for r in failures[user] if _ts(r) >= cutoff]
        else:  # auth_success
            recent_fails = [r for r in failures[user] if _ts(row) - _ts(r) <= BRUTE_FORCE_WINDOW]
            if len(recent_fails) >= BRUTE_FORCE_THRESHOLD and user not in alerted_users:
                ips = sorted({r["src_ip"] for r in recent_fails})
                log_alert(
                    conn,
                    rule="Brute-Force Login Success",
                    severity="critical",
                    description=(
                        f"User '{user}' had {len(recent_fails)} failed logins "
                        f"from {', '.join(ips)} followed by a SUCCESSFUL login "
                        f"within {int(BRUTE_FORCE_WINDOW.total_seconds()/60)} minutes."
                    ),
                    src_ip=row["src_ip"],
                    user=user,
                    event_ids=[r["id"] for r in recent_fails] + [row["id"]],
                )
                alerted_users.add(user)
                count += 1
    return count


def rule_offhours_account_creation(conn):
    """Business hours defined as 06:00-20:00 on Mon-Fri. Anything outside
    that (nights, or any time on Sat/Sun) gets flagged."""
    rows = conn.execute("SELECT * FROM events WHERE event_type = 'user_created'").fetchall()
    count = 0
    for row in rows:
        dt = _ts(row)
        is_weekend = dt.weekday() >= 5  # 5=Sat, 6=Sun
        is_offhours = dt.hour >= 20 or dt.hour < 6
        if is_weekend or is_offhours:
            reason = "weekend" if is_weekend else "outside 06:00-20:00"
            log_alert(
                conn,
                rule="Account Creation Outside Business Hours",
                severity="high",
                description=(
                    f"User '{row['user']}' was created on {row['host']} at "
                    f"{dt.isoformat()} ({reason}) -- possible unauthorized persistence."
                ),
                user=row["user"],
                event_ids=[row["id"]],
            )
            count += 1
    return count


def rule_privilege_escalation(conn):
    rows = conn.execute("SELECT * FROM events WHERE event_type = 'group_modified'").fetchall()
    count = 0
    for row in rows:
        m = re.search(r"added to group '(\w[\w\- ]*)'", row["message"])
        group = m.group(1) if m else None
        if group in HIGH_PRIV_GROUPS:
            log_alert(
                conn,
                rule="Privilege Group Modification",
                severity="critical",
                description=f"User '{row['user']}' was added to the high-privilege "
                             f"group '{group}' on {row['host']}.",
                user=row["user"],
                event_ids=[row["id"]],
            )
            count += 1
    return count


# ---------------------------------------------------------------------------
# 2. Endpoint & Process Execution
# ---------------------------------------------------------------------------

def rule_suspicious_child_process(conn):
    rows = conn.execute("SELECT * FROM events WHERE event_type = 'suspicious_child_process'").fetchall()
    for row in rows:
        log_alert(
            conn, rule="Suspicious Child Process Spawning", severity="high",
            description=f"{row['message']} on {row['host']} -- possible web "
                         f"shell / malicious macro execution.",
            event_ids=[row["id"]],
        )
    return len(rows)


def rule_lolbin(conn):
    rows = conn.execute("SELECT * FROM events WHERE event_type = 'lolbin_exec'").fetchall()
    for row in rows:
        log_alert(
            conn, rule="Living-off-the-Land Binary Usage", severity="high",
            description=f"{row['message']} on {row['host']}.",
            event_ids=[row["id"]],
        )
    return len(rows)


def rule_encoded_exec(conn):
    rows = conn.execute("SELECT * FROM events WHERE event_type = 'encoded_exec'").fetchall()
    for row in rows:
        log_alert(
            conn, rule="Encoded/Obfuscated Command Execution", severity="high",
            description=f"{row['message']} on {row['host']}.",
            event_ids=[row["id"]],
        )
    return len(rows)


def rule_log_tampering(conn):
    rows = conn.execute(
        "SELECT * FROM events WHERE event_type IN ('log_cleared','firewall_disabled','service_stopped')"
    ).fetchall()
    for row in rows:
        log_alert(
            conn, rule="Security Service / Log Tampering", severity="critical",
            description=f"{row['message']} on {row['host']} -- possible defense evasion.",
            event_ids=[row["id"]],
        )
    return len(rows)


# ---------------------------------------------------------------------------
# 3. Network & Perimeter
# ---------------------------------------------------------------------------

def rule_port_scan(conn):
    """>=20 distinct destination ports dropped from one source IP within a
    60-second sliding window."""
    rows = conn.execute(
        "SELECT * FROM events WHERE event_type = 'firewall_drop' ORDER BY timestamp"
    ).fetchall()

    window = defaultdict(list)  # src_ip -> [row, ...]
    alerted_ips = set()
    count = 0

    for row in rows:
        ip = row["src_ip"]
        window[ip].append(row)
        cutoff = _ts(row) - PORT_SCAN_WINDOW
        window[ip] = [r for r in window[ip] if _ts(r) >= cutoff]

        ports = set()
        for r in window[ip]:
            m = re.search(r"dpt=(\d+)", r["raw"])
            if m:
                ports.add(m.group(1))

        if len(ports) >= PORT_SCAN_THRESHOLD and ip not in alerted_ips:
            log_alert(
                conn,
                rule="Port Scanning / Reconnaissance",
                severity="medium",
                description=(
                    f"Source IP {ip} triggered {len(ports)} dropped SYN packets "
                    f"across distinct ports within {int(PORT_SCAN_WINDOW.total_seconds())}s "
                    f"-- looks like Nmap/masscan-style scanning."
                ),
                src_ip=ip,
                event_ids=[r["id"] for r in window[ip]],
            )
            alerted_ips.add(ip)
            count += 1
    return count


# ---------------------------------------------------------------------------
# 4. Deception & Persistence (bonus categories beyond the original brief)
# ---------------------------------------------------------------------------

def rule_canary_triggered(conn):
    rows = conn.execute("SELECT * FROM events WHERE event_type = 'canary_triggered'").fetchall()
    for row in rows:
        log_alert(
            conn, rule="Canary Token Triggered", severity="critical",
            description=f"{row['message']} -- treat as a confirmed intrusion indicator.",
            src_ip=row["src_ip"], event_ids=[row["id"]],
        )
    return len(rows)


def rule_persistence_finding(conn):
    rows = conn.execute(
        "SELECT * FROM events WHERE event_type = 'persistence_finding' "
        "AND severity IN ('high','critical')"
    ).fetchall()
    for row in rows:
        log_alert(
            conn, rule="Systemd Persistence Indicator", severity=row["severity"],
            description=f"{row['message']} on {row['host']}.",
            event_ids=[row["id"]],
        )
    return len(rows)


ALL_RULES = [
    rule_bruteforce,
    rule_offhours_account_creation,
    rule_privilege_escalation,
    rule_suspicious_child_process,
    rule_lolbin,
    rule_encoded_exec,
    rule_log_tampering,
    rule_port_scan,
    rule_canary_triggered,
    rule_persistence_finding,
]


def run_all(conn):
    results = {}
    for rule_fn in ALL_RULES:
        results[rule_fn.__name__] = rule_fn(conn)
    return results
