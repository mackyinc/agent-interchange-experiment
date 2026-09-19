#!/usr/bin/env python3
"""Seed the clearly labelled operator message and set the launch timestamp once."""

from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.app import SCHEMA, SEED_MESSAGE, init_db  # noqa: E402


def main() -> int:
    database = os.environ.get("AGENT_DB", "/var/lib/agent-interchange/agent-interchange.sqlite3")
    init_db(database)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    conn = sqlite3.connect(database)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        start = conn.execute("SELECT value FROM settings WHERE key='experiment_start_utc'").fetchone()
        if not start:
            conn.execute("INSERT INTO settings(key, value) VALUES('experiment_start_utc', ?)", (now,))
        visitor = "node-operator"
        existing = conn.execute("SELECT id FROM messages WHERE author_type='operator' LIMIT 1").fetchone()
        if not existing:
            conn.execute("INSERT INTO messages(created_at, visitor_id, message, reply_to, request_id, author_type) VALUES(?, ?, ?, NULL, NULL, 'operator')", (now, visitor, SEED_MESSAGE))
        conn.commit()
        actual = conn.execute("SELECT value FROM settings WHERE key='experiment_start_utc'").fetchone()[0]
        print(actual)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

