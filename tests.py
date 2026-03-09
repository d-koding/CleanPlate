"""
tests.py — ChoreHouse prototype test suite

Run:  python -m pytest tests.py -v

Coverage areas:
  - Authentication: registration, login, bad-password rejection, session isolation
  - Authorization: role enforcement (admin-only routes, member-only routes,
    cross-household access prevention)
  - Audit: chain creation, chain verification, tamper detection
  - Core features: household CRUD, chore lifecycle, complaint workflow
"""

import json
import hmac
import hashlib
import os
import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

from app import app as flask_app, db as _db
from models import (AuditEntry, AuditHMACKey, Chore, Complaint,
                    Household, HouseholdMember, User)
from auth import hash_password, check_password


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    flask_app.config["TESTING"]                  = True
    flask_app.config["SQLALCHEMY_DATABASE_URI"]  = "sqlite:///:memory:"
    flask_app.config["WTF_CSRF_ENABLED"]         = False
    with flask_app.app_context():
        _db.create_all()
        if AuditHMACKey.query.first() is None:
            _db.session.add(AuditHMACKey())
            _db.session.commit()
        yield flask_app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def register_and_login(client, username="alice", password="password123"):
    client.post("/register", data={"username": username, "password": password,
                                    "confirm": password})
    client.post("/login",    data={"username": username, "password": password})
    return username


def make_household(client, name="Test House"):
    rv = client.post("/households/create", data={"name": name},
                     follow_redirects=True)
    with client.application.app_context():
        return Household.query.filter_by(name=name).first()


# ---------------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------------

class TestAuth:
    def test_password_hashing_is_not_plaintext(self, app):
        h = hash_password("supersecret")
        assert "supersecret" not in h
        assert h.startswith("$2b$")

    def test_correct_password_accepted(self, app):
        h = hash_password("mypassword")
        assert check_password("mypassword", h) is True

    def test_wrong_password_rejected(self, app):
        h = hash_password("mypassword")
        assert check_password("wrongpassword", h) is False

    def test_register_creates_user(self, client):
        rv = client.post("/register",
                         data={"username": "alice", "password": "password123",
                               "confirm": "password123"},
                         follow_redirects=True)
        assert rv.status_code == 200
        with client.application.app_context():
            u = User.query.filter_by(username="alice").first()
            assert u is not None
            assert u.password_hash != "password123"

    def test_register_rejects_short_password(self, client):
        rv = client.post("/register",
                         data={"username": "alice", "password": "short",
                               "confirm": "short"},
                         follow_redirects=True)
        assert b"8 characters" in rv.data

    def test_register_rejects_mismatched_passwords(self, client):
        rv = client.post("/register",
                         data={"username": "alice", "password": "password123",
                               "confirm": "different"},
                         follow_redirects=True)
        assert b"do not match" in rv.data

    def test_register_rejects_duplicate_username(self, client):
        client.post("/register", data={"username": "alice", "password": "password123",
                                        "confirm": "password123"})
        rv = client.post("/register",
                         data={"username": "alice", "password": "password456",
                               "confirm": "password456"},
                         follow_redirects=True)
        assert b"already taken" in rv.data

    def test_login_with_wrong_password_rejected(self, client):
        register_and_login(client, "alice", "password123")
        client.post("/logout")
        rv = client.post("/login",
                         data={"username": "alice", "password": "wrongpassword"},
                         follow_redirects=True)
        assert b"Invalid" in rv.data

    def test_login_with_unknown_user_rejected(self, client):
        rv = client.post("/login",
                         data={"username": "nobody", "password": "password123"},
                         follow_redirects=True)
        assert b"Invalid" in rv.data

    def test_logout_clears_session(self, client):
        register_and_login(client, "alice", "password123")
        client.post("/logout")
        rv = client.get("/", follow_redirects=True)
        assert b"Log in" in rv.data


# ---------------------------------------------------------------------------
# Authorization tests
# ---------------------------------------------------------------------------

class TestAuthorization:
    def test_unauthenticated_redirected_to_login(self, client):
        rv = client.get("/", follow_redirects=True)
        assert b"Log in" in rv.data

    def test_non_member_cannot_view_household(self, client):
        register_and_login(client, "alice")
        h = make_household(client)

        # Login as bob (not a member)
        client.post("/logout")
        client.post("/register", data={"username": "bob", "password": "password123",
                                        "confirm": "password123"})
        client.post("/login", data={"username": "bob", "password": "password123"})

        rv = client.get(f"/households/{h.id}")
        assert rv.status_code == 403

    def test_roommate_cannot_create_chore(self, client, app):
        register_and_login(client, "alice")
        h = make_household(client)
        client.post("/logout")

        # Bob joins as roommate
        client.post("/register", data={"username": "bob", "password": "password123",
                                        "confirm": "password123"})
        client.post("/login", data={"username": "bob", "password": "password123"})
        client.post("/households/join", data={"invite_code": h.invite_code})

        rv = client.post(f"/households/{h.id}/chores/new",
                         data={"title": "Sweep floor"})
        assert rv.status_code == 403

    def test_roommate_cannot_remove_member(self, client, app):
        register_and_login(client, "alice")
        h = make_household(client)

        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            alice_id = alice.id

        client.post("/logout")
        client.post("/register", data={"username": "bob", "password": "password123",
                                        "confirm": "password123"})
        client.post("/login", data={"username": "bob", "password": "password123"})
        client.post("/households/join", data={"invite_code": h.invite_code})

        rv = client.post(f"/households/{h.id}/members/{alice_id}/remove")
        assert rv.status_code == 403

    def test_roommate_cannot_complete_others_chore(self, client, app):
        """A roommate assigned to no chore should not be able to mark it done."""
        register_and_login(client, "alice")
        h = make_household(client)

        with app.app_context():
            alice = User.query.filter_by(username="alice").first()

        client.post("/logout")
        client.post("/register", data={"username": "bob", "password": "password123",
                                        "confirm": "password123"})
        client.post("/login", data={"username": "bob", "password": "password123"})
        client.post("/households/join", data={"invite_code": h.invite_code})

        with app.app_context():
            bob = User.query.filter_by(username="bob").first()
            household = Household.query.filter_by(name="Test House").first()
            chore = Chore(
                household_id=household.id,
                title="Vacuum",
                assigned_to=alice.id,   # assigned to alice, not bob
                created_by=alice.id,
            )
            _db.session.add(chore)
            _db.session.commit()
            chore_id = chore.id

        rv = client.post(f"/households/{h.id}/chores/{chore_id}/complete")
        assert rv.status_code == 403

    def test_cross_household_audit_log_blocked(self, client, app):
        register_and_login(client, "alice")
        h1 = make_household(client, "House 1")
        client.post("/logout")

        client.post("/register", data={"username": "bob", "password": "password123",
                                        "confirm": "password123"})
        client.post("/login", data={"username": "bob", "password": "password123"})
        client.post("/households/create", data={"name": "House 2"})

        # Bob tries to read Alice's audit log
        rv = client.get(f"/households/{h1.id}/audit")
        assert rv.status_code == 403


# ---------------------------------------------------------------------------
# Audit chain tests
# ---------------------------------------------------------------------------

class TestAuditChain:
    def test_chain_starts_with_genesis_sentinel(self, client, app):
        register_and_login(client, "alice")
        make_household(client)
        with app.app_context():
            h = Household.query.first()
            first = (AuditEntry.query
                     .filter_by(household_id=h.id)
                     .order_by(AuditEntry.sequence_num)
                     .first())
            assert first.prev_hash == "0" * 64
            assert first.sequence_num == 1

    def test_chain_verifies_after_normal_operations(self, client, app):
        register_and_login(client, "alice")
        h = make_household(client)

        with app.app_context():
            household = Household.query.filter_by(name="Test House").first()
            alice = User.query.filter_by(username="alice").first()
            # Add a couple more entries
            AuditEntry.append(household_id=household.id, actor_id=alice.id,
                              action="chore.create", details={"title": "Dishes"})
            AuditEntry.append(household_id=household.id, actor_id=alice.id,
                              action="chore.complete", details={"title": "Dishes"})
            _db.session.commit()

            ok, msg = AuditEntry.verify_chain(household.id)
            assert ok is True, msg

    def test_chain_detects_field_tampering(self, client, app):
        register_and_login(client, "alice")
        make_household(client)
        with app.app_context():
            h = Household.query.first()
            entry = AuditEntry.query.filter_by(household_id=h.id).first()
            # Silently mutate the action field — simulates DB tampering
            entry.action = "membership.remove"
            _db.session.commit()

            ok, msg = AuditEntry.verify_chain(h.id)
            assert ok is False
            assert "HMAC mismatch" in msg

    def test_chain_detects_insertion(self, client, app):
        register_and_login(client, "alice")
        make_household(client)
        with app.app_context():
            h = Household.query.first()
            alice = User.query.filter_by(username="alice").first()
            key_row = AuditHMACKey.query.first()
            key_bytes = bytes.fromhex(key_row.key)

            entries = (AuditEntry.query.filter_by(household_id=h.id)
                       .order_by(AuditEntry.sequence_num).all())
            last = entries[-1]

            # Insert a forged entry with sequence_num 0 to disrupt the chain
            from datetime import datetime, timezone
            fake_hash = hmac.new(key_bytes, b"forged", hashlib.sha256).hexdigest()
            bad_entry = AuditEntry(
                household_id=h.id,
                sequence_num=0,        # out-of-sequence
                timestamp=datetime.now(timezone.utc),
                actor_id=alice.id,
                action="forged.action",
                details_json="{}",
                prev_hash="0" * 64,
                entry_hash=fake_hash,
            )
            _db.session.add(bad_entry)
            _db.session.commit()

            ok, msg = AuditEntry.verify_chain(h.id)
            assert ok is False

    def test_sequential_entries_link_correctly(self, client, app):
        register_and_login(client, "alice")
        make_household(client)
        with app.app_context():
            h = Household.query.first()
            alice = User.query.filter_by(username="alice").first()
            for i in range(5):
                AuditEntry.append(household_id=h.id, actor_id=alice.id,
                                  action=f"test.action.{i}", details={"i": i})
            _db.session.commit()

            entries = (AuditEntry.query
                       .filter_by(household_id=h.id)
                       .order_by(AuditEntry.sequence_num).all())
            for i in range(1, len(entries)):
                assert entries[i].prev_hash == entries[i-1].entry_hash


# ---------------------------------------------------------------------------
# Core feature tests
# ---------------------------------------------------------------------------

class TestCoreFeatures:
    def test_household_creation(self, client, app):
        register_and_login(client, "alice")
        h = make_household(client)
        assert h is not None
        assert h.invite_code is not None and len(h.invite_code) > 10

    def test_join_household(self, client, app):
        register_and_login(client, "alice")
        h = make_household(client)
        client.post("/logout")

        client.post("/register", data={"username": "bob", "password": "password123",
                                        "confirm": "password123"})
        client.post("/login", data={"username": "bob", "password": "password123"})
        rv = client.post("/households/join",
                         data={"invite_code": h.invite_code},
                         follow_redirects=True)
        assert rv.status_code == 200

        with app.app_context():
            bob = User.query.filter_by(username="bob").first()
            m = get_m = HouseholdMember.query.filter_by(
                user_id=bob.id, household_id=h.id).first()
            assert m is not None
            assert m.role == "roommate"

    def test_invalid_invite_code_rejected(self, client):
        register_and_login(client)
        rv = client.post("/households/join",
                         data={"invite_code": "INVALID_CODE_XYZ"},
                         follow_redirects=True)
        assert b"Invalid invite code" in rv.data

    def test_chore_lifecycle(self, client, app):
        register_and_login(client, "alice")
        h = make_household(client)

        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            hh = Household.query.filter_by(name="Test House").first()

        rv = client.post(f"/households/{h.id}/chores/new",
                         data={"title": "Do dishes", "assigned_to": alice.id},
                         follow_redirects=True)
        assert rv.status_code == 200

        with app.app_context():
            chore = Chore.query.filter_by(title="Do dishes").first()
            assert chore is not None
            assert chore.status == "pending"
            chore_id = chore.id

        client.post(f"/households/{h.id}/chores/{chore_id}/complete")
        with app.app_context():
            chore = _db.session.get(Chore, chore_id)
            assert chore.status == "complete"
            assert chore.completed_at is not None

    def test_invite_rotation_invalidates_old_code(self, client, app):
        register_and_login(client, "alice")
        h = make_household(client)
        old_code = h.invite_code

        client.post(f"/households/{h.id}/rotate-invite")
        with app.app_context():
            h_fresh = _db.session.get(Household, h.id)
            assert h_fresh.invite_code != old_code

    def test_complaint_and_resolution(self, client, app):
        register_and_login(client, "alice")
        h = make_household(client)

        with app.app_context():
            alice = User.query.filter_by(username="alice").first()

        # Admin creates and completes chore
        rv = client.post(f"/households/{h.id}/chores/new",
                         data={"title": "Sweep", "assigned_to": alice.id},
                         follow_redirects=True)
        with app.app_context():
            chore = Chore.query.filter_by(title="Sweep").first()
            chore_id = chore.id

        client.post(f"/households/{h.id}/chores/{chore_id}/complete")

        # File complaint
        client.post(f"/households/{h.id}/chores/{chore_id}/complaint",
                    data={"description": "Floor is still dirty!"})

        with app.app_context():
            chore = _db.session.get(Chore, chore_id)
            assert chore.status == "disputed"
            c = Complaint.query.filter_by(chore_id=chore_id).first()
            assert c is not None
            complaint_id = c.id

        # Admin upholds complaint
        client.post(f"/households/{h.id}/complaints/{complaint_id}/resolve",
                    data={"resolution": "Sweep again please", "outcome": "uphold"})

        with app.app_context():
            chore = _db.session.get(Chore, chore_id)
            assert chore.status == "pending"   # reverted
            c = _db.session.get(Complaint, complaint_id)
            assert c.resolved is True
