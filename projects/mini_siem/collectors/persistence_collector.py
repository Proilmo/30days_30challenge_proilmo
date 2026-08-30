"""
persistence_collector.py
-------------------------
Thin wrapper: runs persistence_scanner_lib's scan (Day 10's logic) and turns
each finding into a normalized SIEM event. This one isn't a "log tail" like
the others -- it's a periodic/scheduled collector, meant to be run every so
often (e.g. via cron every hour) rather than continuously streaming.

Doesn't feed a separate "rule" in rules.py -- HIGH/CRITICAL findings are
serious enough on their own that this collector raises them straight to
alert-worthy severity, and rules.py just picks up anything at that level.
"""

from datetime import datetime

from siem_core import log_event
from collectors.persistence_scanner_lib import run_full_scan

LEVEL_TO_SEVERITY = {"CRITICAL": "critical", "HIGH": "high"}


def collect(conn, extra_dirs=None, host="localhost", scan_real_system=True):
    findings = run_full_scan(extra_dirs=extra_dirs, scan_real_system=scan_real_system)
    now = datetime.utcnow().isoformat()
    for finding in findings:
        log_event(
            conn,
            source="persistence",
            event_type="persistence_finding",
            timestamp=now,
            host=host,
            severity=LEVEL_TO_SEVERITY.get(finding["level"], "medium"),
            message=f"{finding['reason']} ({finding['file']})",
            raw=f"{finding['file']} | {finding['detail']}",
        )
    return len(findings)
