"""
Historical Tracking — SQLite audit result storage with trend analysis.

Stores audit results over time and provides trend data for the dashboard.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "audit_history.db")


def get_db():
    """Get a database connection, creating tables if needed."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS audit_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            audit_type TEXT NOT NULL,
            grade TEXT NOT NULL,
            score REAL NOT NULL,
            summary TEXT NOT NULL,
            backend TEXT DEFAULT 'unknown'
        )
    """)
    db.commit()
    return db


def save_run(audit_type: str, grade: str, score: float, summary: dict, backend: str = "unknown"):
    """Save an audit run to the database."""
    db = get_db()
    db.execute(
        "INSERT INTO audit_runs (timestamp, audit_type, grade, score, summary, backend) VALUES (?, ?, ?, ?, ?, ?)",
        (
            datetime.now(timezone.utc).isoformat(),
            audit_type,
            grade,
            score,
            json.dumps(summary),
            backend,
        ),
    )
    db.commit()
    db.close()


def get_history(audit_type: str = None, limit: int = 50):
    """Get audit history, optionally filtered by type."""
    db = get_db()
    if audit_type:
        rows = db.execute(
            "SELECT * FROM audit_runs WHERE audit_type = ? ORDER BY timestamp DESC LIMIT ?",
            (audit_type, limit),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM audit_runs ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    db.close()
    return [dict(row) for row in rows]


def get_trend_data(audit_type: str, limit: int = 20):
    """Get score trend data for charting."""
    db = get_db()
    rows = db.execute(
        "SELECT timestamp, grade, score, backend FROM audit_runs WHERE audit_type = ? ORDER BY timestamp DESC LIMIT ?",
        (audit_type, limit),
    ).fetchall()
    db.close()
    # Reverse to chronological order
    return [dict(row) for row in reversed(rows)]


def get_latest_grades():
    """Get the most recent grade for each audit type."""
    db = get_db()
    rows = db.execute("""
        SELECT audit_type, grade, score, timestamp
        FROM audit_runs
        WHERE id IN (
            SELECT MAX(id) FROM audit_runs GROUP BY audit_type
        )
        ORDER BY audit_type
    """).fetchall()
    db.close()
    return {row["audit_type"]: dict(row) for row in rows}
