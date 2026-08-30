#!/usr/bin/env python3
"""
seed_demo_canary.py
--------------------
Optional helper: creates a canary.db with the SAME schema canary.py uses,
and inserts one fake "trigger" event, so you can see rule_canary_triggered
fire without needing to run the full canary.py Flask listener and actually
open a bait file yourself.

In real use, you'd just run `python canary.py serve` (from Day 12) and
canary.db gets created and populated for you automatically whenever
someone opens a bait file/URL. This script only exists to make the mini-
SIEM demo runnable in one shot.
"""

import sqlite3
from datetime import datetime, timezone

conn = sqlite3.connect("canary.db")
conn.execute("""CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY, name TEXT, token_type TEXT, created_at TEXT, notes TEXT)""")
conn.execute("""CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, token_id TEXT, triggered_at TEXT,
    source_ip TEXT, user_agent TEXT, referrer TEXT)""")
conn.execute(
    "INSERT OR IGNORE INTO tokens VALUES (?,?,?,?,?)",
    ("demo-tok-1", "finance-Q3.docx", "doc", datetime.now(timezone.utc).isoformat(), "demo seed"),
)
conn.execute(
    "INSERT INTO events (token_id, triggered_at, source_ip, user_agent, referrer) VALUES (?,?,?,?,?)",
    ("demo-tok-1", datetime.now(timezone.utc).isoformat(), "91.203.5.12", "Mozilla/5.0 (Windows NT 10.0)", None),
)
conn.commit()
conn.close()
print("[seed] canary.db seeded with one demo trigger event.")
