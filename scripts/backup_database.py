#!/usr/bin/env python3
"""Make a consistent SQLite backup using the SQLite backup API."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    source = Path(os.environ.get("AGENT_DB", "/var/lib/agent-interchange/agent-interchange.sqlite3"))
    destination = Path(os.environ.get("AGENT_BACKUP_DIR", "/var/backups/agent-interchange"))
    destination.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = destination / f"agent-interchange-{stamp}.sqlite3"
    source_db = sqlite3.connect(source, timeout=10)
    target_db = sqlite3.connect(target)
    try:
        source_db.backup(target_db)
        target_db.execute("PRAGMA integrity_check")
        target_db.commit()
    finally:
        target_db.close()
        source_db.close()
    backups = sorted(destination.glob("agent-interchange-*.sqlite3"), key=lambda path: path.stat().st_mtime, reverse=True)
    for old in backups[48:]:
        old.unlink(missing_ok=True)
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

