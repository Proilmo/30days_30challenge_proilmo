"""
network_collector.py
---------------------
Loosely inspired by trafficanalyser.py (Day-X), but simplified so it doesn't
need scapy/root/live capture just to run in a demo. Instead of sniffing
packets, it parses a text firewall log in classic iptables LOG format --
the same DROP-with-SYN lines a real Linux firewall would already be writing:

    Aug 30 03:20:01 fw kernel: [12345.678] IPTABLES-DROP: IN=eth0 OUT=
        SRC=45.33.12.9 DST=10.0.0.5 PROTO=TCP SPT=40001 DPT=22 SYN

If you DO want to feed this from live/pcap traffic instead, trafficanalyser.py
already computes exactly the fields needed (src IP, dst port, SYN flag) --
you'd just call log_event() from inside its analyze_packet() function
instead of printing, using event_type="firewall_drop".

This feeds:
    Rule: Port Scanning / Reconnaissance
"""

import re
from datetime import datetime

from siem_core import log_event

LINE_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+.*"
    r"IPTABLES-DROP:.*SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+DST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3})"
    r".*PROTO=(?P<proto>\S+)\s+SPT=(?P<spt>\d+)\s+DPT=(?P<dpt>\d+)"
)


def _to_iso(m, year):
    raw_time = f"{year} {m.group('month')} {m.group('day')} {m.group('time')}"
    return datetime.strptime(raw_time, "%Y %b %d %H:%M:%S").isoformat()


def collect(conn, log_path, year=None):
    year = year or datetime.now().year
    count = 0
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LINE_PATTERN.search(line)
            if not m:
                continue
            log_event(
                conn,
                source="network",
                event_type="firewall_drop",
                timestamp=_to_iso(m, year),
                host=m.group("host"),
                src_ip=m.group("src"),
                severity="info",
                message=f"Dropped {m.group('proto')} SYN {m.group('src')} -> "
                        f"{m.group('dst')}:{m.group('dpt')}",
                raw=line.strip() + f"|dpt={m.group('dpt')}",
            )
            count += 1
    return count
