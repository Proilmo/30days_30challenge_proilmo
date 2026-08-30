"""
canary_collector.py
--------------------
Day 12's canary.py already does the hard work: it runs a Flask listener,
and the moment someone opens a bait file/URL, it writes a row into its own
`canary.db` (events table) with token name, source IP, user-agent, and
timestamp.

This collector doesn't reimplement any of that. It just opens canary.db
(read-only) and imports each trigger row as a SIEM event. A canary firing
is about as close to a "ground truth" signal as security tooling gets --
there is no legitimate reason for anyone to touch a decoy file -- so every
trigger is treated as critical.
"""

import sqlite3

from siem_core import log_event


def collect(conn, canary_db_path="canary.db"):
    try:
        canary_conn = sqlite3.connect(canary_db_path)
        canary_conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        return 0

    count = 0
    try:
        rows = canary_conn.execute("""
            SELECT events.triggered_at, events.source_ip, events.user_agent,
                   tokens.name AS token_name
            FROM events JOIN tokens ON tokens.id = events.token_id
            ORDER BY events.triggered_at
        """).fetchall()
    except sqlite3.OperationalError:
        # canary.db exists but hasn't been initialized (no tables) yet.
        canary_conn.close()
        return 0

    for row in rows:
        log_event(
            conn,
            source="canary",
            event_type="canary_triggered",
            timestamp=row["triggered_at"],
            severity="critical",
            src_ip=row["source_ip"],
            message=f"Canary token '{row['token_name']}' was triggered by {row['source_ip']}"
                    f" ({row['user_agent']})",
            raw=f"token={row['token_name']} ip={row['source_ip']} ua={row['user_agent']}",
        )
        count += 1

    canary_conn.close()
    return count
