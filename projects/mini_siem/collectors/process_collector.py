"""
process_collector.py
---------------------
New collector for endpoint/process rules. There's no Day-X script for this,
so it defines a small, easy-to-produce process-execution log format (the
kind of thing a real EDR agent or `auditd` execve rule would give you):

    2026-08-30T22:30:00 host=web01 parent=cmd.exe child=powershell.exe pid=5566 cmd="powershell.exe -EncodedCommand SQBFAFgA..."

Each line is "key=value" pairs separated by spaces, with cmd="..." holding
the full command line (quotes so it can contain spaces).

From one parsed line we can raise THREE different findings depending on
what the command line looks like:
    - suspicious_child_process : a web server / office app spawned a shell
    - lolbin_exec              : a trusted native binary used to fetch/run payloads
    - encoded_exec             : base64/obfuscated command execution

These feed:
    Rule: Suspicious Child Process Spawning
    Rule: Living-off-the-Land Binaries (LOLBins)
    Rule: Encoded PowerShell / Bash Execution
"""

import re
from datetime import datetime

from siem_core import log_event

LINE_PATTERN = re.compile(
    r'^(?P<ts>\S+)\s+host=(?P<host>\S+)\s+parent=(?P<parent>\S+)\s+'
    r'child=(?P<child>\S+)\s+pid=(?P<pid>\d+)\s+cmd="(?P<cmd>.*)"\s*$'
)

# Parents that should almost never spawn an interactive shell.
WATCHED_PARENTS = {
    "nginx", "httpd", "w3wp.exe", "apache2",
    "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
}
SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "/bin/bash", "/bin/sh", "bash", "sh"}

LOLBIN_PATTERNS = [
    re.compile(r"certutil(\.exe)?\s+-urlcache\s+-split\s+-f", re.IGNORECASE),
    re.compile(r"bitsadmin(\.exe)?\s+/transfer", re.IGNORECASE),
    re.compile(r"curl\s+.*\|\s*(sh|bash)\b", re.IGNORECASE),
    re.compile(r"wget\s+.*\|\s*(sh|bash)\b", re.IGNORECASE),
]

ENCODED_PATTERNS = [
    re.compile(r"-enc(odedcommand)?\b", re.IGNORECASE),
    re.compile(r"echo\s+.*\|\s*base64\s+-d\s*\|\s*(sh|bash)\b", re.IGNORECASE),
    re.compile(r"base64\s+-d", re.IGNORECASE),
]


def collect(conn, log_path):
    count = 0
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LINE_PATTERN.search(line)
            if not m:
                continue
            ts, host, parent, child, cmd = (
                m.group("ts"), m.group("host"), m.group("parent"),
                m.group("child"), m.group("cmd"),
            )

            # Always store the raw execution as a low-severity baseline event.
            log_event(
                conn, source="process", event_type="process_exec", timestamp=ts,
                host=host, severity="info",
                message=f"{parent} -> {child}", raw=line.strip(),
            )
            count += 1

            if parent.lower() in {p.lower() for p in WATCHED_PARENTS} and child.lower() in SHELL_CHILDREN:
                log_event(
                    conn, source="process", event_type="suspicious_child_process", timestamp=ts,
                    host=host, severity="high",
                    message=f"{parent} spawned shell {child} (pid {m.group('pid')})",
                    raw=line.strip(),
                )
                count += 1

            if any(p.search(cmd) for p in LOLBIN_PATTERNS):
                log_event(
                    conn, source="process", event_type="lolbin_exec", timestamp=ts,
                    host=host, severity="high",
                    message=f"LOLBin-style command: {cmd}",
                    raw=line.strip(),
                )
                count += 1

            if any(p.search(cmd) for p in ENCODED_PATTERNS):
                log_event(
                    conn, source="process", event_type="encoded_exec", timestamp=ts,
                    host=host, severity="high",
                    message=f"Encoded/obfuscated command execution: {cmd}",
                    raw=line.strip(),
                )
                count += 1
    return count
