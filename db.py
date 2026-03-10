"""
db.py — Database connection and schema initialization.

Shared infrastructure used by all four team members.
Standard library only: sqlite3.

Usage from any other module:
    from db import query, query_one, execute, init_db
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "cleanplate.db")


def get_conn() -> sqlite3.Connection:
    """
    Return an open connection with row-by-name access and FK enforcement.
    Callers are responsible for closing it, or use as a context manager.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def query(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """SELECT — returns all matching rows."""
    with get_conn() as conn:
        return conn.execute(sql, params).fetchall()


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    """SELECT — returns the first matching row, or None."""
    with get_conn() as conn:
        return conn.execute(sql, params).fetchone()


def execute(sql: str, params: tuple = ()) -> int:
    """INSERT / UPDATE / DELETE — commits and returns lastrowid."""
    with get_conn() as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid


def init_db() -> None:
    """Create all tables on first run. Safe to call every startup."""
    with get_conn() as conn:
        conn.executescript("""
            -- Users ---------------------------------------------------------
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            -- Households -----------------------------------------------------
            CREATE TABLE IF NOT EXISTS households (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                invite_code TEXT    NOT NULL UNIQUE,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            -- Membership (user <-> household, with role) ----------------------
            CREATE TABLE IF NOT EXISTS members (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      INTEGER NOT NULL REFERENCES users(id),
                household_id INTEGER NOT NULL REFERENCES households(id),
                role         TEXT    NOT NULL DEFAULT 'roommate',
                joined_at    TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE (user_id, household_id)
            );

            -- Chores ---------------------------------------------------------
            CREATE TABLE IF NOT EXISTS chores (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                household_id INTEGER NOT NULL REFERENCES households(id),
                title        TEXT    NOT NULL,
                description  TEXT    NOT NULL DEFAULT '',
                assigned_to  INTEGER REFERENCES users(id),
                due_date     TEXT,
                status       TEXT    NOT NULL DEFAULT 'pending',
                created_by   INTEGER NOT NULL REFERENCES users(id),
                created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
                completed_at TEXT
            );

            -- Complaints -----------------------------------------------------
            CREATE TABLE IF NOT EXISTS complaints (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                chore_id     INTEGER NOT NULL REFERENCES chores(id),
                submitted_by INTEGER NOT NULL REFERENCES users(id),
                description  TEXT    NOT NULL,
                resolved     INTEGER NOT NULL DEFAULT 0,
                resolution   TEXT,
                resolved_by  INTEGER REFERENCES users(id),
                created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
            );
                           
            -- Notifications --------------------------------------------------
            CREATE TABLE IF NOT EXISTS notifications (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      INTEGER NOT NULL REFERENCES users(id),
                household_id INTEGER NOT NULL REFERENCES households(id),
                message      TEXT    NOT NULL,
                created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
                read         INTEGER NOT NULL DEFAULT 0
            );

            -- Audit log (HMAC-chained) ---------------------------------------
            CREATE TABLE IF NOT EXISTS audit_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                household_id INTEGER NOT NULL REFERENCES households(id),
                seq          INTEGER NOT NULL,
                timestamp    TEXT    NOT NULL DEFAULT (datetime('now')),
                actor_id     INTEGER NOT NULL REFERENCES users(id),
                action       TEXT    NOT NULL,
                details      TEXT    NOT NULL DEFAULT '{}',
                prev_hash    TEXT    NOT NULL,
                entry_hash   TEXT    NOT NULL,
                UNIQUE (household_id, seq)
            );

            -- HMAC key (singleton) -------------------------------------------
            CREATE TABLE IF NOT EXISTS audit_key (
                id  INTEGER PRIMARY KEY CHECK (id = 1),
                key TEXT NOT NULL
            );
        """)
        conn.commit()
