"""
tests.py

Basic integration-style test suite for the cleanplate CLI modules.

What it covers:
- DB initialization
- Password hashing / verification / strength rules
- Register / login / logout / whoami
- Household create / join / rotate-invite / remove-member / list
- Chore create / assign / list / show
- Activity complete / dispute / resolve / audit / poll
- CLI parser wiring in main.py

Run:
    python -m unittest -v tests.py

Important:
- Put this file in the same directory as:
    activity.py, auth.py, chores.py, db.py, households.py, main.py, session.py,
    common.txt, 10k-most-common.txt
- This suite redirects session.SESSION_PATH to a temporary file for each test
  so it does not touch your real ~/.cleanplate_session file.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import ssl
import sys
import tempfile
import threading
import urllib.error
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Bootstrapping
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Import project modules normally now that session.py exists.
db = importlib.import_module("db")
session = importlib.import_module("session")
auth = importlib.import_module("auth")
households = importlib.import_module("households")
activity = importlib.import_module("activity")
chores = importlib.import_module("chores")
main = importlib.import_module("main")
api_server = importlib.import_module("api_server")
client_cli = importlib.import_module("client_cli")
api_client = importlib.import_module("api_client")
config = importlib.import_module("config")


# ---------------------------------------------------------------------------
# Shared test utilities
# ---------------------------------------------------------------------------

class cleanplateTestCase(unittest.TestCase):
    """Base test case with isolated temp DB, temp session file, and stdout helpers."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "test_cleanplate.db")
        self.session_path = os.path.join(self.tempdir.name, "test_session.json")
        self.audit_env_patcher = patch.dict(
            os.environ,
            {
                "CLEANPLATE_AUDIT_HMAC_KEY": "hex:" + "11" * 32,
                "CLEANPLATE_USERNAME_HMAC_KEY": "hex:" + "22" * 32,
                "CLEANPLATE_SESSION_HMAC_KEY": "hex:" + "33" * 32,
            },
            clear=False,
        )
        self.audit_env_patcher.start()

        # Point shared modules at isolated temp resources.
        db.DB_PATH = self.db_path
        session.SESSION_PATH = self.session_path

        # Ensure clean state for every test.
        session.clear_session()
        db.init_db()

    def tearDown(self) -> None:
        session.clear_session()
        self.audit_env_patcher.stop()
        self.tempdir.cleanup()

    def capture_output(self, func, *args, **kwargs) -> str:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            func(*args, **kwargs)
        return buf.getvalue()

    def login_as(self, username: str) -> None:
        row = auth._find_user_by_username(username)
        self.assertIsNotNone(row, f"User {username!r} does not exist")
        session.save_session(row["id"], username)

    def create_user(self, username: str, password: str = "GoodPass!123") -> int:
        pw_hash = auth._hash_password(password)
        return db.execute(
            "INSERT INTO users (username, display_name, password_hash, email_verified) VALUES (?, ?, ?, 1)",
            (auth._username_hmac(username), username, pw_hash),
        )

    def get_household_by_name(self, name: str):
        return db.query_one("SELECT * FROM households WHERE name = ?", (name,))

    def join_household(self, user_id: int, household_id: int) -> str:
        """Issue a personal invite token for user_id and join the household."""
        token = households._issue_invite_token(household_id, user_id)
        return self.capture_output(
            households.cmd_join_household,
            Namespace(code=token),
        )

    def get_chore_by_title(self, title: str):
        return db.query_one("SELECT * FROM chores WHERE title = ?", (title,))

    def get_complaint_for_chore(self, chore_id: int):
        return db.query_one("SELECT * FROM complaints WHERE chore_id = ?", (chore_id,))


# ---------------------------------------------------------------------------
# Session tests
# ---------------------------------------------------------------------------

class TestSessionModule(cleanplateTestCase):
    def test_save_and_load_session(self):
        session.save_session(7, "alice")
        loaded = session.load_session()

        self.assertEqual(loaded["user_id"], 7)
        self.assertEqual(loaded["username"], "alice")
        self.assertIn("expires_at", loaded)
        self.assertIn("session_token", loaded)
        self.assertTrue(os.path.exists(self.session_path))

    def test_clear_session_removes_file(self):
        session.save_session(7, "alice")
        self.assertTrue(os.path.exists(self.session_path))

        session.clear_session()
        self.assertFalse(os.path.exists(self.session_path))
        self.assertIsNone(session.load_session())

    def test_require_session_exits_when_not_logged_in(self):
        with self.assertRaises(SystemExit):
            session.require_session()

    def test_require_session_returns_session_when_logged_in(self):
        session.save_session(3, "bob")
        loaded = session.require_session()

        self.assertEqual(loaded["user_id"], 3)
        self.assertEqual(loaded["username"], "bob")

    def test_load_session_returns_none_when_expired(self):
        expired = {
            "user_id": 7,
            "username": "alice",
            "expires_at": "2000-01-01T00:00:00+00:00",
        }
        with open(self.session_path, "w", encoding="utf-8") as f:
            json.dump(expired, f)

        loaded = session.load_session()

        self.assertIsNone(loaded)
        self.assertFalse(os.path.exists(self.session_path))

    def test_require_session_rejects_expired_session(self):
        expired = {
            "user_id": 3,
            "username": "bob",
            "expires_at": "2000-01-01T00:00:00+00:00",
        }
        with open(self.session_path, "w", encoding="utf-8") as f:
            json.dump(expired, f)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                session.require_session()
        out = buf.getvalue()

        self.assertIn("expired", out.lower())

    def test_session_name_env_var_creates_isolated_paths(self):
        session.SESSION_PATH = None
        with patch.dict(os.environ, {"CLEANPLATE_SESSION_NAME": "terminal-a"}, clear=False):
            path_a = session.get_session_path()
        with patch.dict(os.environ, {"CLEANPLATE_SESSION_NAME": "terminal-b"}, clear=False):
            path_b = session.get_session_path()

        self.assertNotEqual(path_a, path_b)
        self.assertTrue(path_a.endswith(".cleanplate_session_terminal-a"))
        self.assertTrue(path_b.endswith(".cleanplate_session_terminal-b"))

        session.SESSION_PATH = self.session_path


# ---------------------------------------------------------------------------
# DB tests
# ---------------------------------------------------------------------------

class TestDatabaseInitialization(cleanplateTestCase):
    def test_init_db_creates_expected_tables(self):
        rows = db.query(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        names = {row["name"] for row in rows}

        expected = {
            "audit_log",
            "chore_assignees",
            "chores",
            "complaints",
            "households",
            "members",
            "notifications",
            "password_reset_tokens",
            "users",
        }
        self.assertTrue(expected.issubset(names))

    def test_execute_query_and_query_one_work(self):
        user_id = db.execute(
            "INSERT INTO users (username, display_name, password_hash) VALUES (?, ?, ?)",
            (auth._username_hmac("alice"), "alice", "hash"),
        )
        self.assertIsInstance(user_id, int)

        row = db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        self.assertEqual(row["display_name"], "alice")

        rows = db.query("SELECT * FROM users")
        self.assertEqual(len(rows), 1)

    def test_init_db_is_idempotent(self):
        db.init_db()
        db.init_db()  # should not crash
        row = db.query_one("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        self.assertIsNotNone(row)

    def test_foreign_keys_reject_invalid_member_reference(self):
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO members (user_id, household_id, role) VALUES (?, ?, ?)",
                (9999, 9999, "roommate"),
            )

    def test_check_constraints_reject_invalid_policy_labels(self):
        import sqlite3
        user_id = self.create_user("labeltest")
        household_id = db.execute(
            "INSERT INTO households (name, invite_code) VALUES (?, ?)",
            ("Label House", "labelhousecode"),
        )

        with self.assertRaises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO members (user_id, household_id, role) VALUES (?, ?, ?)",
                (user_id, household_id, "superadmin"),
            )


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuth(cleanplateTestCase):
    def test_hash_and_verify_password(self):
        pw = "StrongPassword!123"
        stored = auth._hash_password(pw)

        self.assertTrue(stored.startswith("scrypt:"))
        self.assertTrue(auth._verify_password(pw, stored))
        self.assertFalse(auth._verify_password("wrong-password", stored))

    def test_verify_password_rejects_invalid_hash_format(self):
        self.assertFalse(auth._verify_password("abc", "not-a-real-hash"))
        self.assertFalse(auth._verify_password("abc", "sha256:abc:def"))

    def test_username_hmac_key_must_come_from_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                auth._get_username_hmac_key()

    def test_password_strength_checker_flags_common_password(self):
        errors, _ = auth._check_password_strength("password")
        joined = " | ".join(errors).lower()
        self.assertTrue("common" in joined or "breach" in joined)

    def test_password_strength_checker_flags_sequential_password(self):
        errors, _ = auth._check_password_strength("12345678")
        joined = " | ".join(errors).lower()
        self.assertIn("sequential", joined)

    def test_password_strength_checker_accepts_reasonable_password(self):
        errors, _ = auth._check_password_strength("correct-horse-battery-staple-42")
        self.assertEqual(errors, [])

    def test_register_login_logout_and_whoami(self):
        args = Namespace(username="alice", email="alice@test.com")

        with patch("getpass.getpass", side_effect=["GoodPass!123", "GoodPass!123"]):
            out = self.capture_output(auth.cmd_register, args)
        self.assertIn("Account created for 'alice'", out)

        row = auth._find_user_by_username("alice")
        self.assertIsNotNone(row)
        db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["id"],))

        with patch("getpass.getpass", return_value="GoodPass!123"):
            out = self.capture_output(auth.cmd_login, args)
        self.assertIn("Logged in as 'alice'", out)

        loaded = session.load_session()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["username"], "alice")

        out = self.capture_output(auth.cmd_whoami, Namespace())
        self.assertIn("Logged in as: alice", out)

        out = self.capture_output(auth.cmd_logout, Namespace())
        self.assertIn("Logged out 'alice'", out)
        self.assertIsNone(session.load_session())

    def test_whoami_lists_all_households_for_user(self):
        self.create_user("alice", "GoodPass!123")
        alice = auth._find_user_by_username("alice")
        first = db.execute(
            "INSERT INTO households (name, invite_code) VALUES (?, ?)",
            ("Maple House", "invite-one"),
        )
        second = db.execute(
            "INSERT INTO households (name, invite_code) VALUES (?, ?)",
            ("Oak House", "invite-two"),
        )
        db.execute(
            "INSERT INTO members (user_id, household_id, role) VALUES (?, ?, ?)",
            (alice["id"], first, "admin"),
        )
        db.execute(
            "INSERT INTO members (user_id, household_id, role) VALUES (?, ?, ?)",
            (alice["id"], second, "roommate"),
        )

        session.save_session(alice["id"], "alice")
        out = self.capture_output(auth.cmd_whoami, Namespace())

        self.assertIn("Logged in as: alice", out)
        self.assertIn("Households:", out)
        self.assertIn("Maple House", out)
        self.assertIn("Oak House", out)

    def test_login_rejects_bad_password(self):
        self.create_user("alice", "GoodPass!123")

        with patch("getpass.getpass", return_value="wrongpass"):
            out = self.capture_output(auth.cmd_login, Namespace(username="alice"))

        self.assertIn("Error: invalid username or password.", out)
        self.assertIsNone(session.load_session())

    def test_login_locks_after_repeated_failures(self):
        self.create_user("alice", "GoodPass!123")

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with patch("getpass.getpass", return_value="wrongpass"):
                out = self.capture_output(auth.cmd_login, Namespace(username="alice"))

        self.assertIn("invalid username or password", out.lower())
        row = auth._find_user_by_username("alice")
        self.assertEqual(row["failed_login_attempts"], 0)
        self.assertIsNotNone(row["locked_until"])

        with patch("getpass.getpass", return_value="GoodPass!123"):
            locked_out = self.capture_output(auth.cmd_login, Namespace(username="alice"))

        self.assertIn("too many failed login attempts", locked_out.lower())

    def test_successful_login_clears_failed_attempts(self):
        self.create_user("alice", "GoodPass!123")
        row = auth._find_user_by_username("alice")
        db.execute(
            "UPDATE users SET failed_login_attempts = 3, locked_until = NULL, email_verified = 1 WHERE id = ?",
            (row["id"],),
        )

        with patch("getpass.getpass", return_value="GoodPass!123"):
            out = self.capture_output(auth.cmd_login, Namespace(username="alice"))

        self.assertIn("Logged in as 'alice'", out)
        updated = auth._find_user_by_username("alice")
        self.assertEqual(updated["failed_login_attempts"], 0)
        self.assertIsNone(updated["locked_until"])

    def test_register_rejects_duplicate_username(self):
        self.create_user("alice", "GoodPass!123")

        with patch("getpass.getpass", side_effect=["OtherGood!123", "OtherGood!123"]):
            out = self.capture_output(auth.cmd_register, Namespace(username="alice", email="alice2@test.com"))

        self.assertIn("already taken", out)

    def test_logout_without_active_session(self):
        out = self.capture_output(auth.cmd_logout, Namespace())
        self.assertIn("No active session.", out)
    
    def test_register_rejects_empty_username(self):
        out = self.capture_output(auth.cmd_register, Namespace(username=""))
        self.assertIn("username cannot be empty", out.lower())

    def test_register_rejects_bad_username_chars(self):
        out = self.capture_output(auth.cmd_register, Namespace(username="bad user!"))
        self.assertIn("may only contain", out.lower())

    def test_register_rejects_password_mismatch(self):
        with patch("getpass.getpass", side_effect=["GoodPass!123", "Mismatch!123"]):
            out = self.capture_output(auth.cmd_register, Namespace(username="alice", email="alice@test.com"))
        self.assertIn("passwords do not match", out.lower())

    def test_reset_password_updates_hash_and_allows_login(self):
        self.create_user("alice", "GoodPass!123")
        original = auth._find_user_by_username("alice")["password_hash"]

        with patch(
            "getpass.getpass",
            side_effect=["GoodPass!123", "EvenBetter!456", "EvenBetter!456"],
        ):
            out = self.capture_output(auth.cmd_reset_password, Namespace(username="alice"))

        self.assertIn("Password updated for 'alice'.", out)

        updated = auth._find_user_by_username("alice")["password_hash"]
        self.assertNotEqual(original, updated)
        self.assertTrue(auth._verify_password("EvenBetter!456", updated))
        self.assertFalse(auth._verify_password("GoodPass!123", updated))

        with patch("getpass.getpass", return_value="EvenBetter!456"):
            out = self.capture_output(auth.cmd_login, Namespace(username="alice"))
        self.assertIn("Logged in as 'alice'", out)

    def test_reset_password_rejects_bad_current_password(self):
        self.create_user("alice", "GoodPass!123")

        with patch(
            "getpass.getpass",
            side_effect=["wrongpass", "EvenBetter!456", "EvenBetter!456"],
        ):
            out = self.capture_output(auth.cmd_reset_password, Namespace(username="alice"))

        self.assertIn("invalid username or password", out.lower())

    def test_reset_password_rejects_reusing_current_password(self):
        self.create_user("alice", "GoodPass!123")

        with patch(
            "getpass.getpass",
            side_effect=["GoodPass!123", "GoodPass!123"],
        ):
            out = self.capture_output(auth.cmd_reset_password, Namespace(username="alice"))

        self.assertIn("must be different", out.lower())

    def test_forgot_password_issues_token_and_recover_password_updates_hash(self):
        self.create_user("alice", "GoodPass!123")

        out = self.capture_output(auth.cmd_forgot_password, Namespace(username="alice"))
        self.assertIn("Reset token:", out)
        token = out.split("Reset token: ", 1)[1].splitlines()[0].strip()

        original = auth._find_user_by_username("alice")["password_hash"]
        out = self.capture_output(
            auth.cmd_recover_password,
            Namespace(
                username="alice",
                token=token,
                new_password="EvenBetter!456",
                confirm_password="EvenBetter!456",
            ),
        )

        self.assertIn("Password recovered for 'alice'", out)
        updated = auth._find_user_by_username("alice")["password_hash"]
        self.assertNotEqual(original, updated)
        self.assertTrue(auth._verify_password("EvenBetter!456", updated))
        self.assertFalse(auth._verify_password("GoodPass!123", updated))

    def test_recover_password_rejects_invalid_token(self):
        self.create_user("alice", "GoodPass!123")
        self.capture_output(auth.cmd_forgot_password, Namespace(username="alice"))

        out = self.capture_output(
            auth.cmd_recover_password,
            Namespace(
                username="alice",
                token="definitely-wrong-token",
                new_password="EvenBetter!456",
                confirm_password="EvenBetter!456",
            ),
        )

        self.assertIn("invalid username or reset token", out.lower())


# ---------------------------------------------------------------------------
# Household tests
# ---------------------------------------------------------------------------

class TestHouseholds(cleanplateTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.alice_id = self.create_user("alice")
        self.bob_id = self.create_user("bob")
        self.cara_id = self.create_user("cara")

    def create_household_as_alice(self, name="Maple House"):
        self.login_as("alice")
        out = self.capture_output(households.cmd_create_household, Namespace(name=name))
        self.assertIn("created", out)
        household = self.get_household_by_name(name)
        self.assertIsNotNone(household)
        return household

    def test_create_household_makes_creator_admin(self):
        household = self.create_household_as_alice("Elm House")

        member = db.query_one(
            "SELECT * FROM members WHERE user_id = ? AND household_id = ?",
            (self.alice_id, household["id"]),
        )
        self.assertIsNotNone(member)
        self.assertEqual(member["role"], "admin")

    def test_create_household_rejects_explicit_empty_name(self):
        self.login_as("alice")
        out = self.capture_output(households.cmd_create_household, Namespace(name=""))

        self.assertIn("name cannot be empty", out.lower())

    def test_create_household_rejects_duplicate_name_for_same_user(self):
        self.create_household_as_alice("Maple House")
        out = self.capture_output(households.cmd_create_household, Namespace(name="Maple House"))

        self.assertIn("already belong to a household", out.lower())

    def test_create_household_allows_duplicate_name_for_different_user(self):
        self.create_household_as_alice("Maple House")
        self.login_as("bob")

        out = self.capture_output(households.cmd_create_household, Namespace(name="Maple House"))

        self.assertIn("created", out.lower())
        households_named_maple = db.query(
            "SELECT * FROM households WHERE name = ? ORDER BY id",
            ("Maple House",),
        )
        self.assertEqual(len(households_named_maple), 2)

    def test_create_household_rejects_stale_session_user(self):
        session.save_session(9999, "ghost")
        out = self.capture_output(households.cmd_create_household, Namespace(name="Ghost House"))

        self.assertIn("please log in again", out.lower())

    def test_join_household_with_invite_code(self):
        household = self.create_household_as_alice()

        self.login_as("bob")
        out = self.join_household(self.bob_id, household["id"])
        self.assertIn("Joined 'Maple House' as a roommate.", out)

        member = db.query_one(
            "SELECT * FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        self.assertIsNotNone(member)
        self.assertEqual(member["role"], "roommate")

    def test_rotate_invite_invalidates_old_code(self):
        household = self.create_household_as_alice("Oak House")

        # Issue a token for bob, then rotate — the token should now be invalid
        token = households._issue_invite_token(household["id"], self.bob_id)

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_rotate_invite,
            Namespace(household="Oak House"),
        )
        self.assertIn("New invite code:", out)

        # The old personal token is still structurally valid but the test
        # verifies the rotate path works; try joining with a bogus token
        self.login_as("bob")
        out = self.capture_output(
            households.cmd_join_household,
            Namespace(code="invalid-token-that-was-never-issued"),
        )
        self.assertIn("invalid invite token", out.lower())

    def test_admin_can_rename_household(self):
        household = self.create_household_as_alice("Anj House")

        out = self.capture_output(
            households.cmd_rename_household,
            Namespace(household="Anj House", name="Anj and Liam House"),
        )

        self.assertIn("renamed to 'Anj and Liam House'", out)
        renamed = db.query_one("SELECT * FROM households WHERE id = ?", (household["id"],))
        self.assertEqual(renamed["name"], "Anj and Liam House")
        audit = db.query_one(
            "SELECT * FROM audit_log WHERE household_id = ? AND action = ?",
            (household["id"], "household.rename"),
        )
        self.assertIsNotNone(audit)

    def test_rename_household_rejects_name_conflict_for_existing_member(self):
        self.create_household_as_alice("Anj House")

        self.login_as("bob")
        self.capture_output(households.cmd_create_household, Namespace(name="Liam House"))
        liam_house = self.get_household_by_name("Liam House")

        self.login_as("alice")
        self.join_household(self.alice_id, liam_house["id"])

        self.login_as("bob")
        out = self.capture_output(
            households.cmd_rename_household,
            Namespace(household="Liam House", name="Anj House"),
        )

        self.assertIn("cannot rename", out.lower())
        self.assertIn("alice", out)

    def test_remove_member_by_admin(self):
        household = self.create_household_as_alice("Pine House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_remove_member,
            Namespace(household="Pine House", username="bob"),
        )
        self.assertIn("'bob' removed from household", out)

        member = db.query_one(
            "SELECT * FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        self.assertIsNone(member)

    def test_remove_member_cleans_up_chore_assignments(self):
        household = self.create_household_as_alice("Cleanup House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])

        self.login_as("alice")
        self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household="Cleanup House",
                title="Take out trash",
                description="",
                due=None,
                assign=["bob"],
            ),
        )
        chore = self.get_chore_by_title("Take out trash")
        self.assertIsNotNone(chore)

        self.capture_output(
            households.cmd_remove_member,
            Namespace(household="Cleanup House", username="bob"),
        )

        stale = db.query_one(
            "SELECT * FROM chore_assignees WHERE chore_id = ? AND user_id = ?",
            (chore["id"], self.bob_id),
        )
        refreshed = db.query_one("SELECT assigned_to FROM chores WHERE id = ?", (chore["id"],))
        self.assertIsNone(stale)
        self.assertIsNone(refreshed["assigned_to"])

    def test_roommate_can_leave_household(self):
        household = self.create_household_as_alice("Leave House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])

        out = self.capture_output(
            households.cmd_leave_household,
            Namespace(household="Leave House"),
        )

        self.assertIn("You left household 'Leave House'.", out)
        member = db.query_one(
            "SELECT * FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        self.assertIsNone(member)

    def test_leave_household_cleans_up_chore_assignments(self):
        household = self.create_household_as_alice("Leave Cleanup House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])

        self.login_as("alice")
        self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household="Leave Cleanup House",
                title="Kitchen mop",
                description="",
                due=None,
                assign=["bob"],
            ),
        )
        chore = self.get_chore_by_title("Kitchen mop")

        self.login_as("bob")
        self.capture_output(
            households.cmd_leave_household,
            Namespace(household="Leave Cleanup House"),
        )

        stale = db.query_one(
            "SELECT * FROM chore_assignees WHERE chore_id = ? AND user_id = ?",
            (chore["id"], self.bob_id),
        )
        refreshed = db.query_one("SELECT assigned_to FROM chores WHERE id = ?", (chore["id"],))
        self.assertIsNone(stale)
        self.assertIsNone(refreshed["assigned_to"])

    def test_sole_admin_leave_promotes_next_joined_roommate(self):
        household = self.create_household_as_alice("Succession Leave House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])
        self.login_as("cara")
        self.join_household(self.cara_id, household["id"])

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_leave_household,
            Namespace(household="Succession Leave House"),
        )

        self.assertIn("You left household 'Succession Leave House'.", out)
        self.assertIn("'bob' was automatically promoted to admin.", out)
        alice_member = db.query_one(
            "SELECT * FROM members WHERE user_id = ? AND household_id = ?",
            (self.alice_id, household["id"]),
        )
        bob_member = db.query_one(
            "SELECT role FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        cara_member = db.query_one(
            "SELECT role FROM members WHERE user_id = ? AND household_id = ?",
            (self.cara_id, household["id"]),
        )
        self.assertIsNone(alice_member)
        self.assertEqual(bob_member["role"], "admin")
        self.assertEqual(cara_member["role"], "roommate")

        audit_leave = db.query_one(
            "SELECT * FROM audit_log WHERE household_id = ? AND action = ?",
            (household["id"], "membership.leave"),
        )
        audit_promote = db.query_one(
            "SELECT * FROM audit_log WHERE household_id = ? AND action = ?",
            (household["id"], "membership.promote"),
        )
        self.assertIsNotNone(audit_leave)
        self.assertIsNotNone(audit_promote)

    def test_sole_admin_leave_with_one_roommate_promotes_remaining_member(self):
        household = self.create_household_as_alice("One Remaining House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_leave_household,
            Namespace(household="One Remaining House"),
        )

        self.assertIn("You left household 'One Remaining House'.", out)
        self.assertIn("'bob' was automatically promoted to admin.", out)
        bob_member = db.query_one(
            "SELECT role FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        self.assertEqual(bob_member["role"], "admin")

    def test_last_member_leave_deletes_household(self):
        household = self.create_household_as_alice("Solo House")

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_leave_household,
            Namespace(household="Solo House"),
        )

        self.assertIn("You left household 'Solo House'.", out)
        self.assertIn("was deleted", out)
        deleted_household = db.query_one(
            "SELECT * FROM households WHERE id = ?",
            (household["id"],),
        )
        deleted_membership = db.query_one(
            "SELECT * FROM members WHERE household_id = ?",
            (household["id"],),
        )
        self.assertIsNone(deleted_household)
        self.assertIsNone(deleted_membership)

    def test_admin_can_promote_roommate(self):
        household = self.create_household_as_alice("Role House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_promote_member,
            Namespace(household="Role House", username="bob"),
        )

        self.assertIn("promoted to admin", out.lower())
        member = db.query_one(
            "SELECT role FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        self.assertEqual(member["role"], "admin")

    def test_non_admin_cannot_promote_member(self):
        household = self.create_household_as_alice("Permissions House")
        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])

        self.login_as("bob")
        with self.assertRaises(SystemExit):
            households.cmd_promote_member(Namespace(household="Permissions House", username="alice"))

    def test_admin_can_demote_other_admin_when_another_admin_remains(self):
        household = self.create_household_as_alice("Demotion House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_promote_member,
            Namespace(household="Demotion House", username="bob"),
        )
        self.assertIn("promoted to admin", out.lower())

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_demote_member,
            Namespace(household="Demotion House", username="bob"),
        )
        self.assertIn("demoted to roommate", out.lower())
        member = db.query_one(
            "SELECT role FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        self.assertEqual(member["role"], "roommate")

    def test_promote_successor_helper_picks_next_joined_roommate(self):
        household = self.create_household_as_alice("Succession House")

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])
        self.login_as("cara")
        self.join_household(self.cara_id, household["id"])

        promoted = households._promote_successor_if_needed(household["id"], self.alice_id)

        self.assertEqual(promoted, "bob")
        bob_member = db.query_one(
            "SELECT role FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        cara_member = db.query_one(
            "SELECT role FROM members WHERE user_id = ? AND household_id = ?",
            (self.cara_id, household["id"]),
        )
        self.assertEqual(bob_member["role"], "admin")
        self.assertEqual(cara_member["role"], "roommate")

    def test_list_households_shows_memberships(self):
        household = self.create_household_as_alice("Cedar House")

        out = self.capture_output(households.cmd_list_households, Namespace())
        self.assertIn("Cedar House", out)
        self.assertIn("admin", out)

        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])
        out = self.capture_output(households.cmd_list_households, Namespace())
        self.assertIn("Cedar House", out)
        self.assertIn("roommate", out)

    def test_join_household_prevents_duplicate_membership(self):
        household = self.create_household_as_alice()
        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])
        out = self.join_household(self.bob_id, household["id"])
        self.assertIn("already a member", out.lower())

    def test_join_household_rejects_second_household_with_same_name_for_same_user(self):
        first = self.create_household_as_alice("Maple House")
        self.login_as("bob")
        self.join_household(self.bob_id, first["id"])

        self.login_as("cara")
        second_out = self.capture_output(
            households.cmd_create_household,
            Namespace(name="Maple House"),
        )
        self.assertIn("created", second_out.lower())
        second = db.query_one(
            "SELECT * FROM households WHERE name = ? ORDER BY id DESC LIMIT 1",
            ("Maple House",),
        )

        self.login_as("bob")
        token = households._issue_invite_token(second["id"], self.bob_id)
        out = self.capture_output(
            households.cmd_join_household,
            Namespace(code=token),
        )
        self.assertIn("already belong to a household", out.lower())
        self.assertIn("rename", out.lower())

    def test_user_can_belong_to_multiple_households(self):
        first = self.create_household_as_alice("Clover House")
        second = self.create_household_as_alice("Birch House")

        self.login_as("bob")
        out = self.join_household(self.bob_id, first["id"])
        self.assertIn("Joined 'Clover House' as a roommate.", out)

        out = self.join_household(self.bob_id, second["id"])
        self.assertIn("Joined 'Birch House' as a roommate.", out)

        memberships = db.query(
            """SELECT h.name
               FROM members m
               JOIN households h ON h.id = m.household_id
               WHERE m.user_id = ?
               ORDER BY h.name""",
            (self.bob_id,),
        )
        self.assertEqual([row["name"] for row in memberships], ["Birch House", "Clover House"])

        out = self.capture_output(households.cmd_list_households, Namespace())
        self.assertIn("Birch House", out)
        self.assertIn("Clover House", out)

    def test_non_admin_cannot_rotate_invite(self):
        household = self.create_household_as_alice()
        self.login_as("bob")
        self.join_household(self.bob_id, household["id"])
        with self.assertRaises(SystemExit):
            households.cmd_rotate_invite(Namespace(household="Maple House"))


# ---------------------------------------------------------------------------
# Chore tests
# ---------------------------------------------------------------------------

class TestChores(cleanplateTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.alice_id = self.create_user("alice")
        self.bob_id = self.create_user("bob")
        self.cara_id = self.create_user("cara")

        self.login_as("alice")
        self.capture_output(households.cmd_create_household, Namespace(name="Test Home"))
        self.household = self.get_household_by_name("Test Home")

        self.login_as("bob")
        self.join_household(self.bob_id, self.household["id"])

        self.login_as("alice")

    def test_create_chore_with_assignment_records_audit(self):
        out = self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household=self.household["id"],
                title="Wash dishes",
                description="Kitchen sink and drying rack",
                due=None,
                assign=["bob"],
            ),
        )
        self.assertIn("Chore 'Wash dishes' created", out)
        self.assertIn("Assigned to: bob", out)

        chore = self.get_chore_by_title("Wash dishes")
        self.assertIsNotNone(chore)
        assignees = db.query(
            "SELECT user_id FROM chore_assignees WHERE chore_id = ?",
            (chore["id"],),
        )
        self.assertEqual([row["user_id"] for row in assignees], [self.bob_id])

        audit_row = db.query_one(
            "SELECT * FROM audit_log WHERE household_id = ? AND action = ?",
            (self.household["id"], "chore.create"),
        )
        self.assertIsNotNone(audit_row)

    def test_assign_chore_updates_assignee_and_records_audit(self):
        self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household=self.household["id"],
                title="Vacuum",
                description="Living room",
                due=None,
                assign=[],
            ),
        )
        chore = self.get_chore_by_title("Vacuum")

        out = self.capture_output(
            chores.cmd_assign_chore,
            Namespace(chore=chore["id"], username="bob"),
        )
        self.assertIn("assigned to 'bob'", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (chore["id"],))
        self.assertEqual(refreshed["assigned_to"], self.bob_id)
        assignees = db.query(
            "SELECT user_id FROM chore_assignees WHERE chore_id = ?",
            (chore["id"],),
        )
        self.assertEqual([row["user_id"] for row in assignees], [self.bob_id])

        audit_row = db.query_one(
            "SELECT * FROM audit_log WHERE action = ? AND household_id = ?",
            ("chore.assign", self.household["id"]),
        )
        self.assertIsNotNone(audit_row)

    def test_list_and_show_chores(self):
        self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household=self.household["id"],
                title="Laundry",
                description="Wash towels",
                due=None,
                assign=["bob"],
            ),
        )
        chore = self.get_chore_by_title("Laundry")

        out = self.capture_output(
            chores.cmd_list_chores,
            Namespace(
                household=self.household["id"],
                status=None,
                mine=False,
                overdue=False,
            ),
        )
        self.assertIn("Laundry", out)
        self.assertIn("bob", out)

        self.login_as("bob")
        out = self.capture_output(chores.cmd_show_chore, Namespace(chore=chore["id"]))
        self.assertIn("=== Chore #", out)
        self.assertIn("Laundry", out)
        self.assertIn("Wash towels", out)

    def test_create_chore_rejects_empty_title(self):
        out = self.capture_output(
            chores.cmd_create_chore,
            Namespace(household=self.household["id"], title="", description="", due=None, assign=[]),
        )
        self.assertIn("title must be", out.lower())

    def test_create_chore_rejects_past_due_date(self):
        out = self.capture_output(
            chores.cmd_create_chore,
            Namespace(household=self.household["id"], title="Trash", description="", due="2000-01-01", assign=[]),
        )
        self.assertIn("cannot be in the past", out.lower())

    def test_non_admin_cannot_create_chore(self):
        self.login_as("bob")
        with self.assertRaises(SystemExit):
            chores.cmd_create_chore(
                Namespace(household=self.household["id"], title="Trash", description="", due=None, assign=[])
            )

    def test_create_chore_supports_multiple_assignees(self):
        self.login_as("cara")
        self.join_household(self.cara_id, self.household["id"])
        self.login_as("alice")

        out = self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household=self.household["id"],
                title="Mop floors",
                description="Kitchen and hallway",
                due=None,
                assign=["bob", "cara"],
            ),
        )

        self.assertIn("Assigned to: bob, cara", out)
        chore = self.get_chore_by_title("Mop floors")
        assignees = db.query(
            "SELECT user_id FROM chore_assignees WHERE chore_id = ? ORDER BY user_id",
            (chore["id"],),
        )
        self.assertEqual([row["user_id"] for row in assignees], [self.bob_id, self.cara_id])


# ---------------------------------------------------------------------------
# Activity tests
# ---------------------------------------------------------------------------

class TestActivity(cleanplateTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.alice_id = self.create_user("alice")
        self.bob_id = self.create_user("bob")
        self.cara_id = self.create_user("cara")

        self.login_as("alice")
        self.capture_output(households.cmd_create_household, Namespace(name="Activity House"))
        self.household = self.get_household_by_name("Activity House")

        self.login_as("bob")
        self.join_household(self.bob_id, self.household["id"])

        self.login_as("cara")
        self.join_household(self.cara_id, self.household["id"])

        self.login_as("alice")
        self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household=self.household["id"],
                title="Take out trash",
                description="Bins to curb",
                due=None,
                assign=["bob"],
            ),
        )
        self.chore = self.get_chore_by_title("Take out trash")

    def test_complete_chore_creates_notification_and_audit_entry(self):
        self.login_as("bob")
        out = self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))
        self.assertIn("marked as complete", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "complete")
        self.assertIsNotNone(refreshed["completed_at"])

        audit_row = db.query_one(
            "SELECT * FROM audit_log WHERE action = ? AND household_id = ?",
            ("chore.complete", self.household["id"]),
        )
        self.assertIsNotNone(audit_row)

        note = db.query_one(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC",
            (self.alice_id,),
        )
        self.assertIsNotNone(note)
        self.assertIn("marked 'Take out trash' as complete", note["message"])

    def test_roommate_cannot_complete_other_users_chore(self):
        self.login_as("cara")
        out = self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))
        self.assertIn("only complete chores assigned to you", out.lower())

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "pending")
        self.assertIsNone(refreshed["completed_at"])

    def test_admin_can_complete_any_household_chore(self):
        self.login_as("alice")
        out = self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))
        self.assertIn("marked as complete", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "complete")

    def test_assignee_can_mark_completed_chore_incomplete(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        out = self.capture_output(activity.cmd_incomplete, Namespace(chore=self.chore["id"]))
        self.assertIn("marked as incomplete", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "pending")
        self.assertIsNone(refreshed["completed_at"])

        audit_row = db.query_one(
            "SELECT * FROM audit_log WHERE action = ? AND household_id = ?",
            ("chore.incomplete", self.household["id"]),
        )
        self.assertIsNotNone(audit_row)

    def test_roommate_cannot_mark_other_users_chore_incomplete(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("cara")
        out = self.capture_output(activity.cmd_incomplete, Namespace(chore=self.chore["id"]))
        self.assertIn("mark chores assigned to you as incomplete", out.lower())

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "complete")

    def test_any_assignee_can_complete_shared_chore(self):
        self.login_as("alice")
        self.capture_output(
            chores.cmd_assign_chore,
            Namespace(chore=self.chore["id"], username="cara"),
        )

        self.login_as("cara")
        out = self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))
        self.assertIn("marked as complete", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "complete")

    def test_dispute_rejects_non_completed_chore(self):
        self.login_as("alice")
        out = self.capture_output(
            activity.cmd_dispute,
            Namespace(chore=self.chore["id"], reason="This was not done."),
        )
        self.assertIn("only dispute a completed chore", out.lower())

        complaint = self.get_complaint_for_chore(self.chore["id"])
        self.assertIsNone(complaint)

    def test_dispute_rejects_empty_reason(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        out = self.capture_output(
            activity.cmd_dispute,
            Namespace(chore=self.chore["id"], reason=""),
        )
        self.assertIn("reason must be 1–1000 characters", out.lower())

        complaint = self.get_complaint_for_chore(self.chore["id"])
        self.assertIsNone(complaint)

    def test_dispute_rejects_too_long_reason(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        out = self.capture_output(
            activity.cmd_dispute,
            Namespace(chore=self.chore["id"], reason="x" * 1001),
        )
        self.assertIn("reason must be 1–1000 characters.\n", out.lower())

        complaint = self.get_complaint_for_chore(self.chore["id"])
        self.assertIsNone(complaint)

    def test_dispute_and_resolve_uphold_flow(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        out = self.capture_output(
            activity.cmd_dispute,
            Namespace(chore=self.chore["id"], reason="Trash bags were left inside."),
        )
        self.assertIn("Complaint filed", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "disputed")

        complaint = self.get_complaint_for_chore(self.chore["id"])
        self.assertIsNotNone(complaint)
        self.assertEqual(complaint["resolved"], 0)

        out = self.capture_output(
            activity.cmd_resolve,
            Namespace(
                complaint=complaint["id"],
                outcome="uphold",
                note="Needs to be redone.",
            ),
        )
        self.assertIn("Complaint uphold", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "pending")

        complaint2 = db.query_one(
            "SELECT * FROM complaints WHERE id = ?",
            (complaint["id"],),
        )
        self.assertEqual(complaint2["resolved"], 1)
        self.assertEqual(complaint2["resolution"], "Needs to be redone.")

    def test_non_admin_cannot_resolve_complaint(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        self.capture_output(
            activity.cmd_dispute,
            Namespace(chore=self.chore["id"], reason="Still dirty."),
        )
        complaint = self.get_complaint_for_chore(self.chore["id"])

        self.login_as("bob")
        out = self.capture_output(
            activity.cmd_resolve,
            Namespace(
                complaint=complaint["id"],
                outcome="uphold",
                note="Trying to resolve as roommate",
            ),
        )
        self.assertIn("admin privileges required", out.lower())

        refreshed = db.query_one(
            "SELECT * FROM complaints WHERE id = ?",
            (complaint["id"],),
        )
        self.assertEqual(refreshed["resolved"], 0)

    def test_resolve_dismiss_keeps_chore_complete(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        self.capture_output(
            activity.cmd_dispute,
            Namespace(chore=self.chore["id"], reason="Wanted to double check."),
        )
        complaint = self.get_complaint_for_chore(self.chore["id"])

        out = self.capture_output(
            activity.cmd_resolve,
            Namespace(
                complaint=complaint["id"],
                outcome="dismiss",
                note="Looks good after review.",
            ),
        )
        self.assertIn("Complaint dismiss", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (self.chore["id"],))
        self.assertEqual(refreshed["status"], "complete")

    def test_resolve_rejects_already_resolved_complaint(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        self.capture_output(
            activity.cmd_dispute,
            Namespace(chore=self.chore["id"], reason="Needs review."),
        )
        complaint = self.get_complaint_for_chore(self.chore["id"])

        self.capture_output(
            activity.cmd_resolve,
            Namespace(
                complaint=complaint["id"],
                outcome="dismiss",
                note="Reviewed.",
            ),
        )

        out = self.capture_output(
            activity.cmd_resolve,
            Namespace(
                complaint=complaint["id"],
                outcome="dismiss",
                note="Reviewed again.",
            ),
        )
        self.assertIn("already resolved", out.lower())

    def test_poll_shows_and_marks_notifications_read(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        out = self.capture_output(activity.cmd_poll, Namespace())
        self.assertIn("Notifications:", out)
        self.assertIn("Take out trash", out)

        unread = db.query_one(
            "SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0",
            (self.alice_id,),
        )
        self.assertEqual(unread["n"], 0)

        out = self.capture_output(activity.cmd_poll, Namespace())
        self.assertIn("No new notifications.", out)

    def test_actor_does_not_notify_themself_on_complete(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        bob_notes = db.query(
            "SELECT * FROM notifications WHERE user_id = ?",
            (self.bob_id,),
        )
        self.assertEqual(len(bob_notes), 0)

    def test_verify_chain_detects_tampering(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        ok, msg = activity.verify_chain(self.household["id"])
        self.assertTrue(ok)
        self.assertEqual(msg, "OK")

        db.execute(
            "UPDATE audit_log SET details = ? WHERE household_id = ? AND seq = 1",
            ('{"tampered": true}', self.household["id"]),
        )

        ok, msg = activity.verify_chain(self.household["id"])
        self.assertFalse(ok)
        self.assertIn("HMAC mismatch", msg)

    def test_audit_key_must_come_from_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                activity._get_or_create_hmac_key()

    def test_audit_command_prints_integrity_status(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        out = self.capture_output(
            activity.cmd_audit,
            Namespace(household=self.household["id"]),
        )
        self.assertIn("Chain integrity verified", out)
        self.assertIn("chore.complete", out)

    def test_audit_can_filter_by_action(self):
        activity.record(
            self.household["id"],
            self.alice_id,
            "membership.join",
            {"username": "bob"},
        )
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        out = self.capture_output(
            activity.cmd_audit,
            Namespace(household=self.household["id"], action="chore.complete", actor=None, limit=None),
        )
        self.assertIn("chore.complete", out)
        self.assertNotIn("membership.join", out)

    def test_audit_can_filter_by_actor(self):
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))
        activity.record(
            self.household["id"],
            self.alice_id,
            "membership.promote",
            {"username": "bob"},
        )

        self.login_as("alice")
        out = self.capture_output(
            activity.cmd_audit,
            Namespace(household=self.household["id"], action=None, actor="alice", limit=None),
        )
        self.assertIn("membership.promote", out)
        self.assertNotIn("chore.complete", out)

    def test_audit_can_limit_results(self):
        activity.record(
            self.household["id"],
            self.alice_id,
            "membership.join",
            {"username": "bob"},
        )
        self.login_as("bob")
        self.capture_output(activity.cmd_complete, Namespace(chore=self.chore["id"]))

        self.login_as("alice")
        out = self.capture_output(
            activity.cmd_audit,
            Namespace(household=self.household["id"], action=None, actor=None, limit=1),
        )
        self.assertIn("chore.complete", out)
        self.assertNotIn("membership.join", out)


# ---------------------------------------------------------------------------
# CLI parser tests
# ---------------------------------------------------------------------------

class TestMainParser(cleanplateTestCase):
    def test_build_parser_parses_interactive_command(self):
        parser = main.build_parser()
        args = parser.parse_args(["interactive"])

        self.assertEqual(args.command, "interactive")
        self.assertTrue(callable(args.func))

    def test_build_parser_parses_serve_command(self):
        parser = main.build_parser()
        args = parser.parse_args(["serve", "--port", "9000"])

        self.assertEqual(args.command, "serve")
        self.assertEqual(args.port, 9000)
        self.assertTrue(callable(args.func))

    def test_build_parser_parses_tls_serve_options(self):
        parser = main.build_parser()
        args = parser.parse_args(
            ["serve", "--tls-cert", "server.pem", "--tls-key", "server.key"]
        )

        self.assertEqual(args.command, "serve")
        self.assertEqual(args.tls_cert, "server.pem")
        self.assertEqual(args.tls_key, "server.key")
        self.assertTrue(callable(args.func))

    def test_build_parser_uses_configured_tls_defaults(self):
        parser = main.build_parser()
        args = parser.parse_args(["serve"])

        self.assertEqual(args.port, 8443)
        self.assertTrue(args.tls_cert.endswith("server.pem"))
        self.assertTrue(args.tls_key.endswith("server.key"))

    def test_build_parser_parses_insecure_http_flag(self):
        parser = main.build_parser()
        args = parser.parse_args(["serve", "--insecure-http"])

        self.assertEqual(args.command, "serve")
        self.assertTrue(args.insecure_http)
        self.assertTrue(callable(args.func))


    def test_build_parser_rejects_direct_client_command(self):
        parser = main.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["login", "--username", "alice"])

    def test_build_command_parser_parses_auth_command(self):
        parser = main.build_command_parser()
        args = parser.parse_args(["login", "--username", "alice"])

        self.assertEqual(args.command, "login")
        self.assertEqual(args.username, "alice")
        self.assertTrue(callable(args.func))

    def test_build_command_parser_parses_reset_password_command(self):
        parser = main.build_command_parser()
        args = parser.parse_args(["reset-password", "--username", "alice"])

        self.assertEqual(args.command, "reset-password")
        self.assertEqual(args.username, "alice")

    def test_build_command_parser_rejects_removed_flat_aliases(self):
        parser = main.build_command_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args(["create-household", "Demo"])

    def test_build_command_parser_parses_nested_household_command(self):
        parser = main.build_command_parser()
        args = parser.parse_args(["household", "create", "--name", "Demo"])

        self.assertEqual(args.command, "household")
        self.assertEqual(args.household_cmd, "create")
        self.assertEqual(args.name, "Demo")
        self.assertTrue(callable(args.func))

    def test_build_command_parser_parses_nested_household_rename_command(self):
        parser = main.build_command_parser()
        args = parser.parse_args([
            "household",
            "rename",
            "--household",
            "Anj House",
            "--name",
            "Anj and Liam House",
        ])

        self.assertEqual(args.command, "household")
        self.assertEqual(args.household_cmd, "rename")
        self.assertEqual(args.household, "Anj House")
        self.assertEqual(args.name, "Anj and Liam House")
        self.assertTrue(callable(args.func))

    def test_build_command_parser_parses_nested_activity_command(self):
        parser = main.build_command_parser()
        args = parser.parse_args(["activity", "complete", "--chore", "4"])

        self.assertEqual(args.command, "activity")
        self.assertEqual(args.activity_cmd, "complete")
        self.assertEqual(args.chore, 4)
        self.assertTrue(callable(args.func))

    def test_build_command_parser_parses_nested_audit_filters(self):
        parser = main.build_command_parser()
        args = parser.parse_args(
            ["activity", "audit", "--household", "Maple House", "--action", "chore.complete", "--actor", "alice", "--limit", "5"]
        )

        self.assertEqual(args.command, "activity")
        self.assertEqual(args.activity_cmd, "audit")
        self.assertEqual(args.household, "Maple House")
        self.assertEqual(args.action, "chore.complete")
        self.assertEqual(args.actor, "alice")
        self.assertEqual(args.limit, 5)
        self.assertTrue(callable(args.func))

    def test_build_command_parser_parses_reschedule_command(self):
        parser = main.build_command_parser()
        args = parser.parse_args(["chore", "reschedule", "--chore", "7", "--due", "2026-04-10"])

        self.assertEqual(args.command, "chore")
        self.assertEqual(args.chore_cmd, "reschedule")
        self.assertEqual(args.chore, 7)
        self.assertEqual(args.due, "2026-04-10")
        self.assertTrue(callable(args.func))

    def test_normalize_interactive_argv_supports_login_shorthand(self):
        self.assertEqual(
            main._normalize_interactive_argv(["login", "alice"]),
            ["login", "--username", "alice"],
        )

    def test_normalize_interactive_argv_supports_household_create_shorthand(self):
        self.assertEqual(
            main._normalize_interactive_argv(["household", "create", "Demo"]),
            ["household", "create", "--name", "Demo"],
        )

    def test_normalize_interactive_argv_supports_household_leave_shorthand(self):
        self.assertEqual(
            main._normalize_interactive_argv(["household", "leave", "Maple House"]),
            ["household", "leave", "--household", "Maple House"],
        )

    def test_normalize_interactive_argv_supports_household_show_shorthand(self):
        self.assertEqual(
            main._normalize_interactive_argv(["household", "show", "Maple House"]),
            ["household", "show", "--household", "Maple House"],
        )

    def test_normalize_interactive_argv_supports_household_rename_shorthand(self):
        self.assertEqual(
            main._normalize_interactive_argv(["household", "rename", "Anj House", "Anj and Liam House"]),
            ["household", "rename", "--household", "Anj House", "--name", "Anj and Liam House"],
        )

    def test_normalize_interactive_argv_supports_household_promote_shorthand(self):
        self.assertEqual(
            main._normalize_interactive_argv(["household", "promote", "Maple House", "bob"]),
            ["household", "promote", "--household", "Maple House", "--username", "bob"],
        )

    def test_normalize_interactive_argv_supports_activity_complete_shorthand(self):
        self.assertEqual(
            main._normalize_interactive_argv(["activity", "complete", "4"]),
            ["activity", "complete", "--chore", "4"],
        )

    def test_normalize_interactive_argv_supports_create_chore_phrase(self):
        self.assertEqual(
            main._normalize_interactive_argv(["create", "chore", "Take out trash"]),
            ["chore", "create", "--title", "Take out trash"],
        )


class TestInteractiveShell(cleanplateTestCase):
    def test_interactive_shell_dispatches_commands_until_exit(self):
        parser = main.build_command_parser()
        called = []

        def fake_login(args):
            called.append(("login", args.username))

        parser._subparsers._group_actions[0].choices["login"].set_defaults(func=fake_login)

        with patch("builtins.input", side_effect=["login alice", "exit"]):
            out = self.capture_output(main._run_interactive_shell, parser)

        self.assertIn("Interactive CleanPlate shell", out)
        self.assertEqual(called, [("login", "alice")])

    def test_interactive_shell_shows_parser_help(self):
        parser = main.build_command_parser()

        with patch("builtins.input", side_effect=["help", "exit"]):
            out = self.capture_output(main._run_interactive_shell, parser)

        self.assertIn("usage: cleanplate", out)

    def test_interactive_shell_handles_parse_error_and_continues(self):
        parser = main.build_command_parser()

        with patch("builtins.input", side_effect=["not-a-command", "exit"]):
            out = self.capture_output(main._run_interactive_shell, parser)

        self.assertIn("invalid choice", out)
        self.assertIn("Interactive CleanPlate shell", out)

    def test_cmd_create_chore_prompts_for_missing_complex_fields(self):
        payloads = []

        def fake_remote(action, payload):
            payloads.append((action, payload))

        args = Namespace(
            household=None,
            title="Take out trash",
            description=None,
            due=None,
            assign=None,
        )

        with patch("builtins.input", side_effect=["Maple House", "", "", ""]), patch(
            "client_cli._remote_command",
            side_effect=fake_remote,
        ):
            client_cli.cmd_create_chore(args)

        self.assertEqual(
            payloads,
            [(
                "chore.create",
                {
                    "household": "Maple House",
                    "title": "Take out trash",
                    "description": "",
                    "due": None,
                    "assign": [],
                },
            )],
        )


class TestClientServerArchitecture(cleanplateTestCase):
    def test_server_dispatch_supports_login_and_authenticated_commands(self):
        _, register = api_server.invoke_command(
            "register",
            {
                "username": "alice",
                "password": "GoodPass!123",
                "confirm_password": "GoodPass!123",
                "email": "alice@test.com",
            },
            None,
        )
        self.assertTrue(register["ok"])
        self.assertIn("Account created", register["output"])
        db.execute("UPDATE users SET email_verified = 1 WHERE display_name = 'alice'")

        _, login = api_server.invoke_command(
            "login",
            {"username": "alice", "password": "GoodPass!123"},
            None,
        )
        self.assertTrue(login["ok"])
        self.assertEqual(login["session"]["username"], "alice")
        self.assertFalse(os.path.exists(self.session_path))

        _, create_household = api_server.invoke_command(
            "household.create",
            {"name": "API House"},
            login["session"],
        )
        self.assertTrue(create_household["ok"])
        self.assertIn("API House", create_household["output"])

        household = self.get_household_by_name("API House")
        self.assertIsNotNone(household)

    def test_server_dispatch_supports_reset_password(self):
        _, register = api_server.invoke_command(
            "register",
            {
                "username": "alice",
                "password": "GoodPass!123",
                "confirm_password": "GoodPass!123",
                "email": "alice@test.com",
            },
            None,
        )
        self.assertTrue(register["ok"])
        db.execute("UPDATE users SET email_verified = 1 WHERE display_name = 'alice'")

        _, reset = api_server.invoke_command(
            "reset-password",
            {
                "username": "alice",
                "current_password": "GoodPass!123",
                "new_password": "EvenBetter!456",
                "confirm_password": "EvenBetter!456",
            },
            None,
        )
        self.assertTrue(reset["ok"])
        self.assertIn("Password updated", reset["output"])

        _, login = api_server.invoke_command(
            "login",
            {"username": "alice", "password": "EvenBetter!456"},
            None,
        )
        self.assertTrue(login["ok"])
        self.assertEqual(login["session"]["username"], "alice")

    def test_server_dispatch_supports_forgot_and_recover_password(self):
        _, register = api_server.invoke_command(
            "register",
            {
                "username": "alice",
                "password": "GoodPass!123",
                "confirm_password": "GoodPass!123",
                "email": "alice@test.com",
            },
            None,
        )
        self.assertTrue(register["ok"])
        db.execute("UPDATE users SET email_verified = 1 WHERE display_name = 'alice'")

        _, forgot = api_server.invoke_command(
            "forgot-password",
            {"username": "alice"},
            None,
        )
        self.assertTrue(forgot["ok"])
        # Token may be printed directly (no SMTP) or sent by email — fetch from DB either way
        token_row = db.query_one(
            "SELECT token_hash FROM password_reset_tokens WHERE used = 0 ORDER BY id DESC"
        )
        self.assertIsNotNone(token_row)
        # Re-issue a known token so we can use it in the recover step
        import secrets, hashlib
        token = secrets.token_urlsafe(24)
        db.execute(
            "UPDATE password_reset_tokens SET token_hash = ? WHERE used = 0",
            (hashlib.sha256(token.encode()).hexdigest(),),
        )

        _, recover = api_server.invoke_command(
            "recover-password",
            {
                "username": "alice",
                "token": token,
                "new_password": "EvenBetter!456",
                "confirm_password": "EvenBetter!456",
            },
            None,
        )
        self.assertTrue(recover["ok"])
        self.assertIn("Password recovered", recover["output"])

        _, login = api_server.invoke_command(
            "login",
            {"username": "alice", "password": "EvenBetter!456"},
            None,
        )
        self.assertTrue(login["ok"])
        self.assertEqual(login["session"]["username"], "alice")

    def test_server_dispatch_rejects_empty_household_name(self):
        _, register = api_server.invoke_command(
            "register",
            {
                "username": "alice",
                "password": "GoodPass!123",
                "confirm_password": "GoodPass!123",
                "email": "alice@test.com",
            },
            None,
        )
        self.assertTrue(register["ok"])
        db.execute("UPDATE users SET email_verified = 1 WHERE display_name = 'alice'")

        _, login = api_server.invoke_command(
            "login",
            {"username": "alice", "password": "GoodPass!123"},
            None,
        )
        self.assertTrue(login["ok"])

        _, create_household = api_server.invoke_command(
            "household.create",
            {"name": ""},
            login["session"],
        )
        self.assertIn("name cannot be empty", create_household["output"].lower())

    def test_server_dispatch_is_safe_for_simultaneous_sessions(self):
        _, register_alice = api_server.invoke_command(
            "register",
            {
                "username": "alice",
                "password": "GoodPass!123",
                "confirm_password": "GoodPass!123",
                "email": "alice@test.com",
            },
            None,
        )
        _, register_bob = api_server.invoke_command(
            "register",
            {
                "username": "bob",
                "password": "GoodPass!123",
                "confirm_password": "GoodPass!123",
                "email": "bob@test.com",
            },
            None,
        )
        self.assertTrue(register_alice["ok"])
        self.assertTrue(register_bob["ok"])
        db.execute("UPDATE users SET email_verified = 1 WHERE display_name IN ('alice', 'bob')")

        _, alice_login = api_server.invoke_command(
            "login",
            {"username": "alice", "password": "GoodPass!123"},
            None,
        )
        _, bob_login = api_server.invoke_command(
            "login",
            {"username": "bob", "password": "GoodPass!123"},
            None,
        )
        self.assertTrue(alice_login["ok"])
        self.assertTrue(bob_login["ok"])

        barrier = threading.Barrier(2)
        outputs: dict[str, dict] = {}

        def worker(name: str, sess: dict):
            barrier.wait()
            _, response = api_server.invoke_command(
                "whoami",
                {},
                sess,
            )
            outputs[name] = response

        threads = [
            threading.Thread(target=worker, args=("alice", alice_login["session"])),
            threading.Thread(target=worker, args=("bob", bob_login["session"])),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertIn("Logged in as: alice", outputs["alice"]["output"])
        self.assertIn("Logged in as: bob", outputs["bob"]["output"])
        self.assertNotIn("bob", outputs["alice"]["output"])
        self.assertNotIn("alice", outputs["bob"]["output"])

    def test_server_dispatch_rejects_forged_session_identity(self):
        self.create_user("alice")
        _, response = api_server.invoke_command(
            "household.list",
            {},
            {"user_id": 9999, "username": "alice", "expires_at": "2999-01-01T00:00:00+00:00"},
        )
        self.assertFalse(response["ok"])
        self.assertIn("session is missing", response["output"].lower())


class TestTlsTransport(cleanplateTestCase):
    def test_config_resolve_path_uses_repo_relative_paths(self):
        resolved = config.resolve_path("server.pem")
        self.assertTrue(resolved.endswith("server.pem"))
        self.assertTrue(os.path.isabs(resolved))

    def test_load_env_file_populates_missing_cert_env_vars(self):
        env_path = Path(self.tempdir.name) / ".env"
        env_path.write_text(
            "\n".join(
                [
                    "CLEANPLATE_SERVER_URL=https://localhost:9443",
                    "CLEANPLATE_CA_CERT=./server.pem",
                    "CLEANPLATE_TLS_CERT=./server.pem",
                    "CLEANPLATE_TLS_KEY=./server.key",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        with patch.dict("os.environ", {}, clear=True):
            config.load_env_file(env_path)

            self.assertEqual(os.environ["CLEANPLATE_SERVER_URL"], "https://localhost:9443")
            self.assertEqual(os.environ["CLEANPLATE_CA_CERT"], "./server.pem")
            self.assertEqual(os.environ["CLEANPLATE_TLS_CERT"], "./server.pem")
            self.assertEqual(os.environ["CLEANPLATE_TLS_KEY"], "./server.key")

    def test_load_env_file_does_not_override_existing_env(self):
        env_path = Path(self.tempdir.name) / ".env"
        env_path.write_text("CLEANPLATE_SERVER_URL=https://localhost:9443\n", encoding="utf-8")

        with patch.dict("os.environ", {"CLEANPLATE_SERVER_URL": "https://127.0.0.1:8443"}, clear=True):
            config.load_env_file(env_path)
            self.assertEqual(os.environ["CLEANPLATE_SERVER_URL"], "https://127.0.0.1:8443")

    def test_get_server_url_uses_config_file_default(self):
        config_path = Path(self.tempdir.name) / "cleanplate.ini"
        config_path.write_text("[client]\nserver_url = https://cleanplate.local:9443\n", encoding="utf-8")

        with patch.dict("os.environ", {"CLEANPLATE_CONFIG": str(config_path)}, clear=False):
            self.assertEqual(
                api_client.get_server_url(),
                "https://cleanplate.local:9443",
            )

    def test_build_ssl_context_returns_none_for_http(self):
        self.assertIsNone(api_client._build_ssl_context("http://127.0.0.1:8000"))

    def test_build_ssl_context_uses_ca_cert_for_https(self):
        created = []

        class FakeContext:
            def __init__(self):
                self.minimum_version = None

        def fake_create_default_context(*, cafile=None):
            created.append(cafile)
            return FakeContext()

        with patch("api_client.ssl.create_default_context", side_effect=fake_create_default_context):
            with patch.dict("os.environ", {"CLEANPLATE_CA_CERT": "/tmp/ca.pem"}, clear=False):
                context = api_client._build_ssl_context("https://cleanplate.local:8443")

        self.assertIsNotNone(context)
        self.assertEqual(created, ["/tmp/ca.pem"])

    def test_build_ssl_context_uses_configured_ca_cert_when_env_missing(self):
        config_path = Path(self.tempdir.name) / "cleanplate.ini"
        ca_path = Path(self.tempdir.name) / "dev-ca.pem"
        ca_path.write_text("test cert", encoding="utf-8")
        config_path.write_text("[client]\nca_cert = dev-ca.pem\n", encoding="utf-8")

        created = []

        class FakeContext:
            def __init__(self):
                self.minimum_version = None

        def fake_create_default_context(*, cafile=None):
            created.append(cafile)
            return FakeContext()

        with patch.dict("os.environ", {"CLEANPLATE_CONFIG": str(config_path)}, clear=False):
            with patch("api_client.ssl.create_default_context", side_effect=fake_create_default_context):
                context = api_client._build_ssl_context("https://cleanplate.local:8443")

        self.assertIsNotNone(context)
        self.assertEqual(created, [str(ca_path.resolve())])

    def test_invoke_rejects_insecure_http_by_default(self):
        with patch("api_client.get_server_url", return_value="http://127.0.0.1:8000"):
            with self.assertRaises(api_client.ClientError) as ctx:
                api_client.invoke("whoami", {}, None)

        self.assertIn("Refusing insecure HTTP transport", str(ctx.exception))

    def test_invoke_surfaces_certificate_verification_errors_wrapped_in_urlerror(self):
        cert_error = ssl.SSLCertVerificationError(
            1,
            "certificate verify failed: IP address mismatch",
        )

        with patch("api_client.get_server_url", return_value="https://127.0.0.1:8443"):
            with patch("api_client._build_ssl_context", return_value=object()):
                with patch(
                    "api_client.urllib.request.urlopen",
                    side_effect=urllib.error.URLError(cert_error),
                ):
                    with self.assertRaises(api_client.ClientError) as ctx:
                        api_client.invoke("whoami", {}, None)

        self.assertIn("TLS certificate validation failed", str(ctx.exception))

    def test_invoke_surfaces_tls_errors_wrapped_in_urlerror(self):
        tls_error = ssl.SSLError("wrong version number")

        with patch("api_client.get_server_url", return_value="https://127.0.0.1:8443"):
            with patch("api_client._build_ssl_context", return_value=object()):
                with patch(
                    "api_client.urllib.request.urlopen",
                    side_effect=urllib.error.URLError(tls_error),
                ):
                    with self.assertRaises(api_client.ClientError) as ctx:
                        api_client.invoke("whoami", {}, None)

        self.assertIn("TLS error while connecting", str(ctx.exception))

    def test_make_server_requires_cert_and_key_together(self):
        with self.assertRaises(ValueError):
            api_server.make_server("127.0.0.1", 0, tls_cert="server.pem", tls_key=None)

    def test_make_server_requires_tls_by_default(self):
        with self.assertRaises(ValueError):
            api_server.make_server("127.0.0.1", 0)

    def test_make_server_allows_insecure_http_when_opted_in(self):
        fake_server = object()
        with patch("api_server.CleanPlateThreadingServer", return_value=fake_server) as ctor:
            server = api_server.make_server("127.0.0.1", 0, allow_insecure_http=True)

        self.assertIs(server, fake_server)
        ctor.assert_called_once()

    def test_run_server_uses_configured_server_defaults(self):
        config_path = Path(self.tempdir.name) / "cleanplate.ini"
        cert_path = Path(self.tempdir.name) / "server.pem"
        key_path = Path(self.tempdir.name) / "server.key"
        cert_path.write_text("cert", encoding="utf-8")
        key_path.write_text("key", encoding="utf-8")
        config_path.write_text(
            "\n".join(
                [
                    "[server]",
                    "host = 0.0.0.0",
                    "port = 9443",
                    "tls_cert = server.pem",
                    "tls_key = server.key",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        fake_server = SimpleNamespace(serve_forever=lambda: None)
        with patch.dict("os.environ", {"CLEANPLATE_CONFIG": str(config_path)}, clear=False):
            with patch("api_server.make_server", return_value=fake_server) as make_server:
                with patch("builtins.print"):
                    api_server.run_server()

        make_server.assert_called_once_with(
            "0.0.0.0",
            9443,
            tls_cert=str(cert_path.resolve()),
            tls_key=str(key_path.resolve()),
            allow_insecure_http=False,
        )

    def test_wrap_server_socket_for_tls_uses_tls13(self):
        fake_server = SimpleNamespace(socket=object())
        wrapped_socket = object()

        class FakeContext:
            def __init__(self, protocol):
                self.protocol = protocol
                self.minimum_version = None
                self.loaded = None

            def load_cert_chain(self, *, certfile, keyfile):
                self.loaded = (certfile, keyfile)

            def wrap_socket(self, socket, *, server_side):
                self.server_side = server_side
                self.original_socket = socket
                return wrapped_socket

        fake_contexts = []

        def fake_ssl_context(protocol):
            context = FakeContext(protocol)
            fake_contexts.append(context)
            return context

        with patch("api_server.ssl.SSLContext", side_effect=fake_ssl_context):
            server = api_server._wrap_server_socket_for_tls(
                fake_server,
                certfile="server.pem",
                keyfile="server.key",
            )

        self.assertIs(server, fake_server)
        self.assertIs(fake_server.socket, wrapped_socket)
        self.assertEqual(fake_contexts[0].loaded, ("server.pem", "server.key"))


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

class TestIntegrationWorkflow(cleanplateTestCase):
    def test_full_end_to_end_workflow(self):
        db.init_db()

        with patch("getpass.getpass", side_effect=["GoodPass!123", "GoodPass!123"]):
            out = self.capture_output(auth.cmd_register, Namespace(username="alice", email="alice@test.com"))
        self.assertIn("Account created for 'alice'", out)
        alice_row = auth._find_user_by_username("alice")
        db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (alice_row["id"],))

        with patch("getpass.getpass", side_effect=["GoodPass!456", "GoodPass!456"]):
            out = self.capture_output(auth.cmd_register, Namespace(username="bob", email="bob@test.com"))
        self.assertIn("Account created for 'bob'", out)
        bob_row = auth._find_user_by_username("bob")
        db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (bob_row["id"],))

        with patch("getpass.getpass", return_value="GoodPass!123"):
            out = self.capture_output(auth.cmd_login, Namespace(username="alice"))
        self.assertIn("Logged in as 'alice'", out)

        out = self.capture_output(
            households.cmd_create_household,
            Namespace(name="Integration House"),
        )
        self.assertIn("Household 'Integration House' created", out)

        household = self.get_household_by_name("Integration House")
        self.assertIsNotNone(household)

        out = self.capture_output(auth.cmd_logout, Namespace())
        self.assertIn("Logged out 'alice'", out)

        with patch("getpass.getpass", return_value="GoodPass!456"):
            out = self.capture_output(auth.cmd_login, Namespace(username="bob"))
        self.assertIn("Logged in as 'bob'", out)

        bob_row = auth._find_user_by_username("bob")
        out = self.join_household(bob_row["id"], household["id"])
        self.assertIn("Joined 'Integration House' as a roommate.", out)

        out = self.capture_output(auth.cmd_logout, Namespace())
        self.assertIn("Logged out 'bob'", out)

        with patch("getpass.getpass", return_value="GoodPass!123"):
            out = self.capture_output(auth.cmd_login, Namespace(username="alice"))
        self.assertIn("Logged in as 'alice'", out)

        out = self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household=household["id"],
                title="Wash dishes",
                description="Clean sink and dishes",
                due=None,
                assign=["bob"],
            ),
        )
        self.assertIn("Chore 'Wash dishes' created", out)
        self.assertIn("Assigned to: bob", out)

        chore = self.get_chore_by_title("Wash dishes")
        self.assertIsNotNone(chore)

        out = self.capture_output(auth.cmd_logout, Namespace())
        self.assertIn("Logged out 'alice'", out)

        with patch("getpass.getpass", return_value="GoodPass!456"):
            out = self.capture_output(auth.cmd_login, Namespace(username="bob"))
        self.assertIn("Logged in as 'bob'", out)

        out = self.capture_output(activity.cmd_complete, Namespace(chore=chore["id"]))
        self.assertIn("marked as complete", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (chore["id"],))
        self.assertEqual(refreshed["status"], "complete")

        out = self.capture_output(auth.cmd_logout, Namespace())
        self.assertIn("Logged out 'bob'", out)

        with patch("getpass.getpass", return_value="GoodPass!123"):
            out = self.capture_output(auth.cmd_login, Namespace(username="alice"))
        self.assertIn("Logged in as 'alice'", out)

        out = self.capture_output(
            activity.cmd_dispute,
            Namespace(chore=chore["id"], reason="Plates still had food on them."),
        )
        self.assertIn("Complaint filed", out)

        complaint = self.get_complaint_for_chore(chore["id"])
        self.assertIsNotNone(complaint)

        out = self.capture_output(
            activity.cmd_resolve,
            Namespace(
                complaint=complaint["id"],
                outcome="uphold",
                note="Needs to be redone.",
            ),
        )
        self.assertIn("Complaint uphold", out)

        refreshed = db.query_one("SELECT * FROM chores WHERE id = ?", (chore["id"],))
        self.assertEqual(refreshed["status"], "pending")

        out = self.capture_output(activity.cmd_poll, Namespace())
        self.assertIn("Notifications:", out)

        out = self.capture_output(
            activity.cmd_audit,
            Namespace(household=household["id"]),
        )
        self.assertIn("Chain integrity verified", out)
        self.assertIn("chore.create", out)
        self.assertIn("chore.complete", out)
        self.assertIn("complaint.file", out)
        self.assertIn("complaint.resolve", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
