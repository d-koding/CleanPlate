"""
db.py — Database connection and schema initialization.

Shared infrastructure used by all four team members.
Standard library only: sqlite3.

Usage from any other module:
    from db import query, query_one, execute, init_db
"""

import sqlite3
import os
from contextlib import closing

DB_PATH = os.path.join(os.path.dirname(__file__), "cleanplate.db")


def get_conn() -> sqlite3.Connection:
    """
    Return an open connection with row-by-name access and FK enforcement.
    Callers are responsible for closing it, or use as a context manager.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def query(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """SELECT — returns all matching rows."""
    with closing(get_conn()) as conn:
        return conn.execute(sql, params).fetchall()


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    """SELECT — returns the first matching row, or None."""
    with closing(get_conn()) as conn:
        return conn.execute(sql, params).fetchone()


def execute(sql: str, params: tuple = ()) -> int:
    """INSERT / UPDATE / DELETE — commits and returns lastrowid."""
    with closing(get_conn()) as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid


def init_db() -> None:
    """Create all tables on first run. Safe to call every startup."""
    with closing(get_conn()) as conn:
        conn.executescript("""
            -- Users ---------------------------------------------------------
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                display_name  TEXT,
                password_hash TEXT    NOT NULL,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until  TEXT,
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

            -- Chore assignees (many-to-many) ---------------------------------
            CREATE TABLE IF NOT EXISTS chore_assignees (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                chore_id INTEGER NOT NULL REFERENCES chores(id) ON DELETE CASCADE,
                user_id  INTEGER NOT NULL REFERENCES users(id),
                UNIQUE (chore_id, user_id)
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

            -- Password reset tokens -----------------------------------------
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT    NOT NULL,
                expires_at TEXT    NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0,
                created_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            -- Email verification tokens ------------------------------------
            CREATE TABLE IF NOT EXISTS email_verifications (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                code       TEXT    NOT NULL,
                expires_at TEXT    NOT NULL,
                created_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );
        """)

        user_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "display_name" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
        if "email" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "email_verified" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
        if "failed_login_attempts" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0")
        if "locked_until" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
        # Grandfather existing accounts that predate email verification
        conn.execute("UPDATE users SET email_verified = 1 WHERE email IS NULL OR email = ''")

        conn.execute(
            "UPDATE users SET display_name = username WHERE display_name IS NULL OR display_name = ''"
        )
        conn.execute(
            """INSERT OR IGNORE INTO chore_assignees (chore_id, user_id)
               SELECT id, assigned_to
               FROM chores
               WHERE assigned_to IS NOT NULL"""
        )
        conn.commit()
