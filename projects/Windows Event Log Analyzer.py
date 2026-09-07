"""
Windows Event Log Analyzer
---------------------------
Reads Windows Event Logs (live, via pywin32), parses key security event
fields, filters events, and runs simple pattern-based analysis
(frequency stats, brute-force detection, spikes, suspicious logons).

Requirements:
    pip install pywin32

Usage:
    python event_log_analyzer.py
"""

import re
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime

import win32evtlog  # pip install pywin32


# ============================================================
# 1. FIELD PARSING (per Event ID)
# ============================================================

EVENT_FIELD_PATTERNS = {
    4624: {  # Successful logon
        "account": r"Account Name:\s*([^\r\n]+)",
        "logon_type": r"Logon Type:\s*(\d+)",
        "source_ip": r"Source Network Address:\s*([^\r\n]+)",
        "domain": r"Account Domain:\s*([^\r\n]+)",
    },
    4625: {  # Failed logon
        "account": r"Account Name:\s*([^\r\n]+)",
        "logon_type": r"Logon Type:\s*(\d+)",
        "source_ip": r"Source Network Address:\s*([^\r\n]+)",
        "failure_reason": r"Failure Reason:\s*([^\r\n]+)",
        "status_code": r"Status:\s*(0x[0-9A-Fa-f]+)",
    },
    4672: {  # Special privileges assigned (admin logon)
        "account": r"Account Name:\s*([^\r\n]+)",
        "privileges": r"Privileges:\s*([^\r\n]+(?:\r?\n\s+\S+)*)",
    },
    4720: {  # User account created
        "account": r"Account Name:\s*([^\r\n]+)",
    },
    4726: {  # User account deleted
        "account": r"Target Account Name:\s*([^\r\n]+)",
    },
    4688: {  # New process created
        "process_name": r"New Process Name:\s*([^\r\n]+)",
        "command_line": r"Command Line:\s*([^\r\n]+)",
        "creator_account": r"Creator Process Name:\s*([^\r\n]+)",
    },
    4732: {  # Member added to a security-enabled group
        "member": r"Member:\s*[^\r\n]*Account Name:\s*([^\r\n]+)",
        "group": r"Group:\s*\r?\n\s*Security ID:[^\r\n]*\r?\n\s*Group Name:\s*([^\r\n]+)",
    },
}


def parse_event_fields(event):
    """Extract structured fields from a raw event message based on Event ID."""
    patterns = EVENT_FIELD_PATTERNS.get(event["event_id"])
    if not patterns:
        return {}

    parsed = {}
    for field_name, pattern in patterns.items():
        match = re.search(pattern, event["message"], re.MULTILINE)
        parsed[field_name] = match.group(1).strip() if match else None
    return parsed


def extract_account(event):
    """Convenience helper to pull just the account name field, if present."""
    return event.get("fields", {}).get("account", "UNKNOWN")


# ============================================================
# 2. READING EVENTS
# ============================================================

def read_events(log_type="Security", limit=500):
    """Read events from a Windows log (System, Application, Security)."""
    handle = win32evtlog.OpenEventLog(None, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []
    while len(events) < limit:
        records = win32evtlog.ReadEventLog(handle, flags, 0)
        if not records:
            break
        for r in records:
            event = {
                "time": r.TimeGenerated.Format(),
                "source": r.SourceName,
                "event_id": r.EventID & 0xFFFF,  # strip severity bits
                "type": r.EventType,
                "message": win32evtlog.SafeFormatMessage(r, log_type),
            }
            event["fields"] = parse_event_fields(event)
            events.append(event)
            if len(events) >= limit:
                break
    win32evtlog.CloseEventLog(handle)
    return events


def parse_time(time_str):
    """Parse the pywin32 time string into a datetime object."""
    # pywin32's .Format() typically returns e.g. '09/07/26 14:32:10'
    return datetime.strptime(time_str, "%m/%d/%y %H:%M:%S")


# ============================================================
# 3. FILTERING
# ============================================================

def filter_events(events, keyword=None, event_id=None, source=None,
                   start_time=None, end_time=None):
    """Filter events by keyword, event ID, source, or time range."""
    result = events

    if keyword:
        result = [e for e in result if keyword.lower() in e["message"].lower()]

    if event_id:
        result = [e for e in result if e["event_id"] == event_id]

    if source:
        result = [e for e in result if source.lower() in e["source"].lower()]

    if start_time or end_time:
        filtered = []
        for e in result:
            try:
                t = parse_time(e["time"])
            except ValueError:
                continue
            if start_time and t < start_time:
                continue
            if end_time and t > end_time:
                continue
            filtered.append(e)
        result = filtered

    return result


# ============================================================
# 4. ANALYSIS
# ============================================================

def analyze_frequency(events):
    """Basic counts: most common event IDs, sources, severity types."""
    by_id = Counter(e["event_id"] for e in events)
    by_source = Counter(e["source"] for e in events)
    by_type = Counter(e["type"] for e in events)
    return {
        "top_event_ids": by_id.most_common(10),
        "top_sources": by_source.most_common(10),
        "by_severity": dict(by_type),
    }


def detect_brute_force(events, threshold=5):
    """Flag account/IP pairs with repeated failed logons (Event ID 4625)."""
    failures = [e for e in events if e["event_id"] == 4625]
    by_account_ip = defaultdict(list)

    for e in failures:
        account = e["fields"].get("account", "UNKNOWN")
        ip = e["fields"].get("source_ip", "UNKNOWN")
        by_account_ip[(account, ip)].append(e["time"])

    alerts = []
    for (account, ip), timestamps in by_account_ip.items():
        if len(timestamps) >= threshold:
            alerts.append({
                "account": account,
                "source_ip": ip,
                "failed_attempts": len(timestamps),
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
            })
    return alerts


def detect_spikes(events, bucket="hour", multiplier=2.0):
    """Detect time buckets where event volume is well above the average."""
    buckets = defaultdict(int)
    for e in events:
        try:
            dt = parse_time(e["time"])
        except ValueError:
            continue
        key = dt.strftime("%Y-%m-%d %H:00") if bucket == "hour" else dt.strftime("%Y-%m-%d")
        buckets[key] += 1

    counts = list(buckets.values())
    avg = sum(counts) / len(counts) if counts else 0
    spikes = {k: v for k, v in buckets.items() if v > avg * multiplier}
    return {"baseline_avg": round(avg, 2), "spikes": spikes}


def detect_logon_after_failures(events, min_failures=3):
    """Flag a successful logon (4624) preceded by several failures (4625)
    from the same account, which may indicate a successful brute force."""
    findings = []
    sorted_events = sorted(events, key=lambda e: e["time"])

    for i, e in enumerate(sorted_events):
        if e["event_id"] != 4624:
            continue
        account = e["fields"].get("account", "UNKNOWN")
        recent_fails = [
            x for x in sorted_events[:i]
            if x["event_id"] == 4625 and x["fields"].get("account", "UNKNOWN") == account
        ]
        if len(recent_fails) >= min_failures:
            findings.append({
                "account": account,
                "success_time": e["time"],
                "preceding_failures": len(recent_fails),
            })
    return findings


def generate_report(events):
    """Bundle all analysis functions into a single summary report."""
    return {
        "total_events": len(events),
        "frequency": analyze_frequency(events),
        "brute_force_alerts": detect_brute_force(events),
        "spikes": detect_spikes(events),
        "suspicious_logons": detect_logon_after_failures(events),
    }


# ============================================================
# 5. OUTPUT
# ============================================================

def save_events_to_csv(events, filename="events.csv"):
    """Save raw/filtered events to CSV (flattens the 'fields' dict to JSON)."""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["time", "source", "event_id", "type", "message", "fields"]
        )
        writer.writeheader()
        for e in events:
            row = dict(e)
            row["fields"] = json.dumps(e.get("fields", {}))
            writer.writerow(row)


def save_report_to_json(report, filename="report.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)


def print_report_summary(report):
    print("\n=== EVENT LOG ANALYSIS SUMMARY ===")
    print(f"Total events analyzed: {report['total_events']}")

    print("\nTop Event IDs:")
    for eid, count in report["frequency"]["top_event_ids"]:
        print(f"  {eid}: {count}")

    print("\nBrute-force alerts:")
    if report["brute_force_alerts"]:
        for a in report["brute_force_alerts"]:
            print(f"  {a['account']} from {a['source_ip']} "
                  f"- {a['failed_attempts']} failures "
                  f"({a['first_seen']} -> {a['last_seen']})")
    else:
        print("  None detected")

    print("\nVolume spikes:")
    print(f"  Baseline avg/bucket: {report['spikes']['baseline_avg']}")
    for k, v in report["spikes"]["spikes"].items():
        print(f"  {k}: {v} events")

    print("\nSuspicious logons (success after repeated failures):")
    if report["suspicious_logons"]:
        for s in report["suspicious_logons"]:
            print(f"  {s['account']} succeeded at {s['success_time']} "
                  f"after {s['preceding_failures']} failures")
    else:
        print("  None detected")
    print("===================================\n")


# ============================================================
# 6. MAIN
# ============================================================

if __name__ == "__main__":
    LOG_TYPE = "Security"   # "System", "Application", or "Security"
    LIMIT = 1000

    print(f"Reading up to {LIMIT} events from '{LOG_TYPE}' log...")
    events = read_events(log_type=LOG_TYPE, limit=LIMIT)
    print(f"Read {len(events)} events.")

    # --- Filtering example ---
    failed_logons = filter_events(events, event_id=4625)
    save_events_to_csv(failed_logons, "failed_logons.csv")
    print(f"Saved {len(failed_logons)} failed logon events to failed_logons.csv")

    # --- Analysis ---
    report = generate_report(events)
    print_report_summary(report)
    save_report_to_json(report, "report.json")
    print("Full report saved to report.json")