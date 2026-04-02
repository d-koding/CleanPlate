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
import os
import sys
import tempfile
import threading
import unittest
from argparse import Namespace
from pathlib import Path
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


# ---------------------------------------------------------------------------
# Shared test utilities
# ---------------------------------------------------------------------------

class cleanplateTestCase(unittest.TestCase):
    """Base test case with isolated temp DB, temp session file, and stdout helpers."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "test_cleanplate.db")
        self.session_path = os.path.join(self.tempdir.name, "test_session.json")

        # Point shared modules at isolated temp resources.
        db.DB_PATH = self.db_path
        session.SESSION_PATH = self.session_path

        # Ensure clean state for every test.
        session.clear_session()
        db.init_db()

    def tearDown(self) -> None:
        session.clear_session()
        self.tempdir.cleanup()

    def capture_output(self, func, *args, **kwargs) -> str:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            func(*args, **kwargs)
        return buf.getvalue()

    def login_as(self, username: str) -> None:
        row = db.query_one("SELECT id FROM users WHERE username = ?", (username,))
        self.assertIsNotNone(row, f"User {username!r} does not exist")
        session.save_session(row["id"], username)

    def create_user(self, username: str, password: str = "GoodPass!123") -> int:
        pw_hash = auth._hash_password(password)
        return db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )

    def get_household_by_name(self, name: str):
        return db.query_one("SELECT * FROM households WHERE name = ?", (name,))

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
            "audit_key",
            "audit_log",
            "chores",
            "complaints",
            "households",
            "members",
            "notifications",
            "users",
        }
        self.assertTrue(expected.issubset(names))

    def test_execute_query_and_query_one_work(self):
        user_id = db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("alice", "hash"),
        )
        self.assertIsInstance(user_id, int)

        row = db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        self.assertEqual(row["username"], "alice")

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

    def test_password_strength_checker_flags_common_password(self):
        errors = auth._check_password_strength("password")
        joined = " | ".join(errors).lower()
        self.assertTrue("common" in joined or "breach" in joined)

    def test_password_strength_checker_flags_sequential_password(self):
        errors = auth._check_password_strength("12345678")
        joined = " | ".join(errors).lower()
        self.assertIn("sequential", joined)

    def test_password_strength_checker_accepts_reasonable_password(self):
        errors = auth._check_password_strength("ValidPass!482")
        self.assertEqual(errors, [])

    def test_register_login_logout_and_whoami(self):
        args = Namespace(username="alice")

        with patch("getpass.getpass", side_effect=["GoodPass!123", "GoodPass!123"]):
            out = self.capture_output(auth.cmd_register, args)
        self.assertIn("Account created for 'alice'", out)

        row = db.query_one("SELECT * FROM users WHERE username = ?", ("alice",))
        self.assertIsNotNone(row)

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

    def test_login_rejects_bad_password(self):
        self.create_user("alice", "GoodPass!123")

        with patch("getpass.getpass", return_value="wrongpass"):
            out = self.capture_output(auth.cmd_login, Namespace(username="alice"))

        self.assertIn("Error: invalid username or password.", out)
        self.assertIsNone(session.load_session())

    def test_register_rejects_duplicate_username(self):
        self.create_user("alice", "GoodPass!123")

        with patch("getpass.getpass", side_effect=["OtherGood!123", "OtherGood!123"]):
            out = self.capture_output(auth.cmd_register, Namespace(username="alice"))

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
            out = self.capture_output(auth.cmd_register, Namespace(username="alice"))
        self.assertIn("passwords do not match", out.lower())

    def test_reset_password_updates_hash_and_allows_login(self):
        self.create_user("alice", "GoodPass!123")
        original = db.query_one(
            "SELECT password_hash FROM users WHERE username = ?",
            ("alice",),
        )["password_hash"]

        with patch(
            "getpass.getpass",
            side_effect=["GoodPass!123", "EvenBetter!456", "EvenBetter!456"],
        ):
            out = self.capture_output(auth.cmd_reset_password, Namespace(username="alice"))

        self.assertIn("Password updated for 'alice'.", out)

        updated = db.query_one(
            "SELECT password_hash FROM users WHERE username = ?",
            ("alice",),
        )["password_hash"]
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

    def test_join_household_with_invite_code(self):
        household = self.create_household_as_alice()

        self.login_as("bob")
        out = self.capture_output(
            households.cmd_join_household,
            Namespace(code=household["invite_code"]),
        )
        self.assertIn("Joined 'Maple House' as a roommate.", out)

        member = db.query_one(
            "SELECT * FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        self.assertIsNotNone(member)
        self.assertEqual(member["role"], "roommate")

    def test_rotate_invite_invalidates_old_code(self):
        household = self.create_household_as_alice("Oak House")
        old_code = household["invite_code"]

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_rotate_invite,
            Namespace(id=household["id"]),
        )
        self.assertIn("New invite code:", out)

        refreshed = db.query_one(
            "SELECT * FROM households WHERE id = ?",
            (household["id"],),
        )
        self.assertNotEqual(old_code, refreshed["invite_code"])

        self.login_as("bob")
        out = self.capture_output(
            households.cmd_join_household,
            Namespace(code=old_code),
        )
        self.assertIn("invalid invite code", out.lower())

    def test_remove_member_by_admin(self):
        household = self.create_household_as_alice("Pine House")

        self.login_as("bob")
        self.capture_output(
            households.cmd_join_household,
            Namespace(code=household["invite_code"]),
        )

        self.login_as("alice")
        out = self.capture_output(
            households.cmd_remove_member,
            Namespace(id=household["id"], username="bob"),
        )
        self.assertIn("'bob' removed from household", out)

        member = db.query_one(
            "SELECT * FROM members WHERE user_id = ? AND household_id = ?",
            (self.bob_id, household["id"]),
        )
        self.assertIsNone(member)

    def test_list_households_shows_memberships(self):
        household = self.create_household_as_alice("Cedar House")

        out = self.capture_output(households.cmd_list_households, Namespace())
        self.assertIn("Cedar House", out)
        self.assertIn("admin", out)

        self.login_as("bob")
        self.capture_output(
            households.cmd_join_household,
            Namespace(code=household["invite_code"]),
        )
        out = self.capture_output(households.cmd_list_households, Namespace())
        self.assertIn("Cedar House", out)
        self.assertIn("roommate", out)

    def test_join_household_prevents_duplicate_membership(self):
        household = self.create_household_as_alice()
        self.login_as("bob")
        self.capture_output(households.cmd_join_household, Namespace(code=household["invite_code"]))
        out = self.capture_output(households.cmd_join_household, Namespace(code=household["invite_code"]))
        self.assertIn("already a member", out.lower())

    def test_non_admin_cannot_rotate_invite(self):
        household = self.create_household_as_alice()
        self.login_as("bob")
        self.capture_output(households.cmd_join_household, Namespace(code=household["invite_code"]))
        with self.assertRaises(SystemExit):
            households.cmd_rotate_invite(Namespace(id=household["id"]))


# ---------------------------------------------------------------------------
# Chore tests
# ---------------------------------------------------------------------------

class TestChores(cleanplateTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.alice_id = self.create_user("alice")
        self.bob_id = self.create_user("bob")

        self.login_as("alice")
        self.capture_output(households.cmd_create_household, Namespace(name="Test Home"))
        self.household = self.get_household_by_name("Test Home")

        self.login_as("bob")
        self.capture_output(
            households.cmd_join_household,
            Namespace(code=self.household["invite_code"]),
        )

        self.login_as("alice")

    def test_create_chore_with_assignment_records_audit(self):
        out = self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household=self.household["id"],
                title="Wash dishes",
                description="Kitchen sink and drying rack",
                due=None,
                assign="bob",
            ),
        )
        self.assertIn("Chore 'Wash dishes' created", out)
        self.assertIn("Assigned to: bob", out)

        chore = self.get_chore_by_title("Wash dishes")
        self.assertIsNotNone(chore)
        self.assertEqual(chore["assigned_to"], self.bob_id)

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
                assign=None,
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
                assign="bob",
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
            Namespace(household=self.household["id"], title="", description="", due=None, assign=None),
        )
        self.assertIn("title must be", out.lower())

    def test_create_chore_rejects_past_due_date(self):
        out = self.capture_output(
            chores.cmd_create_chore,
            Namespace(household=self.household["id"], title="Trash", description="", due="2000-01-01", assign=None),
        )
        self.assertIn("cannot be in the past", out.lower())

    def test_non_admin_cannot_create_chore(self):
        self.login_as("bob")
        with self.assertRaises(SystemExit):
            chores.cmd_create_chore(
                Namespace(household=self.household["id"], title="Trash", description="", due=None, assign=None)
            )


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
        self.capture_output(
            households.cmd_join_household,
            Namespace(code=self.household["invite_code"]),
        )

        self.login_as("cara")
        self.capture_output(
            households.cmd_join_household,
            Namespace(code=self.household["invite_code"]),
        )

        self.login_as("alice")
        self.capture_output(
            chores.cmd_create_chore,
            Namespace(
                household=self.household["id"],
                title="Take out trash",
                description="Bins to curb",
                due=None,
                assign="bob",
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


# ---------------------------------------------------------------------------
# CLI parser tests
# ---------------------------------------------------------------------------

class TestMainParser(cleanplateTestCase):
    def test_build_parser_parses_auth_command(self):
        parser = main.build_parser()
        args = parser.parse_args(["login", "--username", "alice"])

        self.assertEqual(args.command, "login")
        self.assertEqual(args.username, "alice")
        self.assertTrue(callable(args.func))

    def test_build_parser_parses_reset_password_command(self):
        parser = main.build_parser()
        args = parser.parse_args(["reset-password", "--username", "alice"])

        self.assertEqual(args.command, "reset-password")
        self.assertEqual(args.username, "alice")
        self.assertTrue(callable(args.func))

    def test_build_parser_parses_nested_household_command(self):
        parser = main.build_parser()
        args = parser.parse_args(["household", "create", "--name", "Demo"])

        self.assertEqual(args.command, "household")
        self.assertEqual(args.household_cmd, "create")
        self.assertEqual(args.name, "Demo")
        self.assertTrue(callable(args.func))

    def test_build_parser_parses_nested_activity_command(self):
        parser = main.build_parser()
        args = parser.parse_args(["activity", "complete", "--chore", "4"])

        self.assertEqual(args.command, "activity")
        self.assertEqual(args.activity_cmd, "complete")
        self.assertEqual(args.chore, 4)
        self.assertTrue(callable(args.func))


class TestClientServerArchitecture(cleanplateTestCase):
    def test_server_dispatch_supports_login_and_authenticated_commands(self):
        _, register = api_server.invoke_command(
            "register",
            {
                "username": "alice",
                "password": "GoodPass!123",
                "confirm_password": "GoodPass!123",
            },
            None,
        )
        self.assertTrue(register["ok"])
        self.assertIn("Account created", register["output"])

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
            },
            None,
        )
        self.assertTrue(register["ok"])

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

    def test_server_dispatch_is_safe_for_simultaneous_sessions(self):
        self.create_user("alice")
        self.create_user("bob")

        barrier = threading.Barrier(2)
        outputs: dict[str, dict] = {}

        def worker(name: str):
            barrier.wait()
            _, response = api_server.invoke_command(
                "whoami",
                {},
                {"user_id": 1 if name == "alice" else 2, "username": name},
            )
            outputs[name] = response

        threads = [
            threading.Thread(target=worker, args=("alice",)),
            threading.Thread(target=worker, args=("bob",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertIn("Logged in as: alice", outputs["alice"]["output"])
        self.assertIn("Logged in as: bob", outputs["bob"]["output"])
        self.assertNotIn("bob", outputs["alice"]["output"])
        self.assertNotIn("alice", outputs["bob"]["output"])


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

class TestIntegrationWorkflow(cleanplateTestCase):
    def test_full_end_to_end_workflow(self):
        db.init_db()

        with patch("getpass.getpass", side_effect=["GoodPass!123", "GoodPass!123"]):
            out = self.capture_output(auth.cmd_register, Namespace(username="alice"))
        self.assertIn("Account created for 'alice'", out)

        with patch("getpass.getpass", side_effect=["GoodPass!456", "GoodPass!456"]):
            out = self.capture_output(auth.cmd_register, Namespace(username="bob"))
        self.assertIn("Account created for 'bob'", out)

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

        out = self.capture_output(
            households.cmd_join_household,
            Namespace(code=household["invite_code"]),
        )
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
                assign="bob",
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
