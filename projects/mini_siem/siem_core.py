"""
siem_core.py
------------
The heart of the mini-SIEM: a normalized event store + alert store in SQLite.

Every collector (ssh_collector, identity_collector, process_collector,
network_collector, persistence_collector, canary_collector) parses its own
log format but ends up calling the SAME function here: log_event(). That's
the whole trick behind a SIEM -- lots of different, messy log formats all
get squeezed into one common table so that rules can be written ONCE
against a normalized shape instead of once per log format.

Table: events
    id          auto-increment primary key
    timestamp   ISO-8601 string, when the activity happened (not when we saw it)
    source      which collector produced this event, e.g. "ssh", "identity"
    event_type  normalized category, e.g. "auth_failed", "user_created"
    host        hostname the event happened on (if known)
    user        username involved (if any)
    src_ip      source IP involved (if any)
    severity    info / low / medium / high / critical (informational default,
                rules are what actually decide "this is bad")
    message     short human-readable summary
    raw         the original, un-parsed log line (kept for investigation)

Table: alerts
    id           auto-increment primary key
    timestamp    when the rule fired (when analyze() ran)
    rule         name of the rule that fired
    severity     low / medium / high / critical
    description  human-readable explanation
    src_ip       relevant source IP, if any
    user         relevant username, if any
    event_ids    JSON list of event.id rows that support this alert (evidence)
"""

import sqlite3
import json
from datetime import datetime

DB_PATH = "siem.db"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def get_conn(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT NOT NULL,
            source     TEXT NOT NULL,
            event_type TEXT NOT NULL,
            host       TEXT,
            user       TEXT,
            src_ip     TEXT,
            severity   TEXT DEFAULT 'info',
            message    TEXT,
            raw        TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            rule        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            description TEXT NOT NULL,
            src_ip      TEXT,
            user        TEXT,
            event_ids   TEXT
        )
    """)
    conn.commit()


def reset_db(conn):
    """Wipe events/alerts so each `run` starts from a clean slate.
    (A mini-SIEM demo re-parses the sample logs fully each time rather than
    tracking file offsets like a production log shipper would.)"""
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM alerts")
    conn.commit()


def log_event(conn, source, event_type, timestamp=None, host=None, user=None,
              src_ip=None, severity="info", message="", raw=""):
    timestamp = timestamp or datetime.utcnow().isoformat()
    cur = conn.execute(
        """INSERT INTO events (timestamp, source, event_type, host, user,
                                src_ip, severity, message, raw)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, source, event_type, host, user, src_ip, severity, message, raw),
    )
    conn.commit()
    return cur.lastrowid


def log_alert(conn, rule, severity, description, src_ip=None, user=None, event_ids=None):
    cur = conn.execute(
        """INSERT INTO alerts (timestamp, rule, severity, description, src_ip, user, event_ids)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.utcnow().isoformat(),
            rule,
            severity,
            description,
            src_ip,
            user,
            json.dumps(event_ids or []),
        ),
    )
    conn.commit()
    return cur.lastrowid


def all_events(conn):
    return conn.execute("SELECT * FROM events ORDER BY timestamp").fetchall()


def events_by_type(conn, event_type):
    return conn.execute(
        "SELECT * FROM events WHERE event_type = ? ORDER BY timestamp", (event_type,)
    ).fetchall()


def all_alerts(conn):
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY "
        "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, timestamp"
    ).fetchall()
    return rows
