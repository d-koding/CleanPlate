"""
activity.py — Activity & Completion
Owner: Person 4

Responsibilities:
  - Mark a chore as complete
  - File and resolve complaints (disputes)
  - Audit log: appending entries and verifying the chain
  - Notification logic (stub — expand as needed)

Standard library only: hashlib, hmac, json, os, datetime
"""

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone

from db import execute, execute_tx, query, query_one, query_one_tx, query_tx, transaction
from households import get_membership, require_membership, _resolve_household_id
from session import require_session


_AUDIT_LOCK = threading.RLock()


# ---------------------------------------------------------------------------
# AUDIT LOG — Person 4 owns this section
# ---------------------------------------------------------------------------

def _get_or_create_hmac_key() -> bytes:
    """
    Return the server-side HMAC key from the environment.

    Supported variables:
      - CLEANPLATE_AUDIT_HMAC_KEY
      - AUDIT_HMAC_KEY

    If the value starts with ``hex:``, the remainder is parsed as hex bytes.
    Otherwise the raw UTF-8 bytes of the environment variable are used.
    """
    for env_name in ("CLEANPLATE_AUDIT_HMAC_KEY", "AUDIT_HMAC_KEY"):
        value = os.environ.get(env_name)
        if not value:
            continue
        if value.startswith("hex:"):
            try:
                return bytes.fromhex(value[4:])
            except ValueError as exc:
                raise RuntimeError(f"{env_name} must contain valid hex after 'hex:'") from exc
        return value.encode("utf-8", errors="strict")

    raise RuntimeError(
        "Audit HMAC key is not configured. Set CLEANPLATE_AUDIT_HMAC_KEY "
        "(or AUDIT_HMAC_KEY) before starting the server."
    )


def _compute_entry_hash(key: bytes, household_id: int, seq: int,
                        timestamp: str, actor_id: int, action: str,
                        details: str, prev_hash: str) -> str:
    """
    HMAC-SHA256 over all fields of a single audit entry.

    The payload is a pipe-separated string of all fields so that changing
    any single field produces a completely different hash.

    TODO (Person 4): If you change the canonical format here, you must also
    update verify_chain — they must agree on the exact byte representation.
    """
    payload = "|".join([
        str(household_id), str(seq), timestamp,
        str(actor_id), action, details, prev_hash
    ]).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def record(
    household_id: int,
    actor_id: int,
    action: str,
    details: dict,
    *,
    conn=None,
) -> None:
    """
    Append a tamper-evident entry to the audit log.

    This is the one function the other three team members will call.
    They do NOT need to understand the internals — just call:

        from activity import record
        record(household_id, session["user_id"], "chore.complete", {"chore_id": 7})

    Call this INSIDE the same logical operation as the DB change it describes
    so both either succeed or fail together.
    """
    with _AUDIT_LOCK:
        key = _get_or_create_hmac_key()

        # Serialize sequence assignment so concurrent requests cannot create
        # duplicate seq numbers or broken prev_hash chains for a household.
        if conn is None:
            last = query_one(
                "SELECT seq, entry_hash FROM audit_log WHERE household_id = ? ORDER BY seq DESC LIMIT 1",
                (household_id,)
            )
        else:
            last = query_one_tx(
                conn,
                "SELECT seq, entry_hash FROM audit_log WHERE household_id = ? ORDER BY seq DESC LIMIT 1",
                (household_id,),
            )
        seq = (last["seq"] + 1) if last else 1
        prev_hash = last["entry_hash"] if last else ("0" * 64)

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        details_json = json.dumps(details, sort_keys=True)
        entry_hash = _compute_entry_hash(
            key, household_id, seq, timestamp,
            actor_id, action, details_json, prev_hash
        )

        if conn is None:
            execute(
                """INSERT INTO audit_log
                   (household_id, seq, timestamp, actor_id, action, details, prev_hash, entry_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (household_id, seq, timestamp, actor_id, action, details_json, prev_hash, entry_hash)
            )
        else:
            execute_tx(
                conn,
                """INSERT INTO audit_log
                   (household_id, seq, timestamp, actor_id, action, details, prev_hash, entry_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (household_id, seq, timestamp, actor_id, action, details_json, prev_hash, entry_hash),
            )


def verify_chain(household_id: int) -> tuple[bool, str]:
    """
    Walk every audit entry for the household and recompute its HMAC.
    Returns (True, "OK") or (False, "<description of first violation>").

    TODO (Person 4): Call this automatically before displaying the log
    so admins always see the chain status without having to ask.
    """
    key = _get_or_create_hmac_key()
    entries = query(
        "SELECT * FROM audit_log WHERE household_id = ? ORDER BY seq",
        (household_id,)
    )

    expected_prev = "0" * 64
    for e in entries:
        if e["prev_hash"] != expected_prev:
            return False, (f"Entry #{e['seq']}: prev_hash mismatch — "
                           "an entry may have been inserted or deleted")
        recomputed = _compute_entry_hash(
            key, e["household_id"], e["seq"], e["timestamp"],
            e["actor_id"], e["action"], e["details"], e["prev_hash"]
        )
        if not hmac.compare_digest(recomputed, e["entry_hash"]):
            return False, f"Entry #{e['seq']}: HMAC mismatch — entry data has been altered"
        expected_prev = e["entry_hash"]

    return True, "OK"


# ---------------------------------------------------------------------------
# NOTIFICATIONS — Person 4 owns this stub
# ---------------------------------------------------------------------------

def notify(
    household_id: int,
    message: str,
    exclude_user_id: int | None = None,
    *,
    conn=None,
) -> None:
    """
    Store a notification for each member of the household.

    Members will see unread notifications when they run:
        python main.py activity poll
    """
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    if conn is None:
        members = query(
            "SELECT user_id FROM members WHERE household_id = ?",
            (household_id,)
        )
    else:
        members = query_tx(
            conn,
            "SELECT user_id FROM members WHERE household_id = ?",
            (household_id,),
        )

    for member in members:
        user_id = member["user_id"]

        if exclude_user_id is not None and user_id == exclude_user_id:
            continue

        if conn is None:
            execute(
                """INSERT INTO notifications (user_id, household_id, message, created_at, read)
                   VALUES (?, ?, ?, ?, 0)""",
                (user_id, household_id, message, created_at)
            )
        else:
            execute_tx(
                conn,
                """INSERT INTO notifications (user_id, household_id, message, created_at, read)
                   VALUES (?, ?, ?, ?, 0)""",
                (user_id, household_id, message, created_at),
            )


# ---------------------------------------------------------------------------
# COMMANDS
# ---------------------------------------------------------------------------

def cmd_complete(args) -> None:
    """
    Mark a chore as complete.
    Roommates can only complete chores assigned to them.
    Admins can complete any chore in their household.
    Usage: python main.py activity complete --chore <id>
    """
    session = require_session()

    chore = query_one("SELECT * FROM chores WHERE id = ?", (args.chore,))
    if not chore:
        print(f"Error: chore {args.chore} not found.")
        return

    membership = require_membership(session["user_id"], chore["household_id"])

    if chore["status"] == "complete":
        print("Chore is already marked complete.")
        return

    is_assigned = query_one(
        "SELECT 1 FROM chore_assignees WHERE chore_id = ? AND user_id = ?",
        (args.chore, session["user_id"]),
    )

    # Authorization: roommates may only complete their own assigned chores
    if membership["role"] != "admin" and not is_assigned:
        print("Error: you can only complete chores assigned to you.")
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    with transaction() as conn:
        execute_tx(
            conn,
            "UPDATE chores SET status = 'complete', completed_at = ? WHERE id = ?",
            (now, args.chore)
        )

        record(
            chore["household_id"],
            session["user_id"],
            "chore.complete",
            {"chore_id": args.chore, "title": chore["title"]},
            conn=conn,
        )

        notify(
            chore["household_id"],
            f"{session['username']} marked '{chore['title']}' as complete.",
            exclude_user_id=session["user_id"],
            conn=conn,
        )
    print(f"Chore '{chore['title']}' marked as complete.")


def cmd_incomplete(args) -> None:
    """
    Mark a chore as incomplete.
    Roommates can only mark assigned chores incomplete.
    Admins can mark any chore in their household incomplete.
    Usage: python main.py activity incomplete --chore <id>
    """
    session = require_session()

    chore = query_one("SELECT * FROM chores WHERE id = ?", (args.chore,))
    if not chore:
        print(f"Error: chore {args.chore} not found.")
        return

    membership = require_membership(session["user_id"], chore["household_id"])

    if chore["status"] == "pending":
        print("Chore is already marked incomplete.")
        return

    is_assigned = query_one(
        "SELECT 1 FROM chore_assignees WHERE chore_id = ? AND user_id = ?",
        (args.chore, session["user_id"]),
    )

    if membership["role"] != "admin" and not is_assigned:
        print("Error: you can only mark chores assigned to you as incomplete.")
        return

    with transaction() as conn:
        execute_tx(
            conn,
            "UPDATE chores SET status = 'pending', completed_at = NULL WHERE id = ?",
            (args.chore,),
        )

        record(
            chore["household_id"],
            session["user_id"],
            "chore.incomplete",
            {"chore_id": args.chore, "title": chore["title"]},
            conn=conn,
        )

        notify(
            chore["household_id"],
            f"{session['username']} marked '{chore['title']}' as incomplete.",
            exclude_user_id=session["user_id"],
            conn=conn,
        )
    print(f"Chore '{chore['title']}' marked as incomplete.")


def cmd_dispute(args) -> None:
    """
    File a complaint against a completed chore.
    Usage: python main.py activity dispute --chore <id> --reason "Floor still dirty"
    """
    session = require_session()

    chore = query_one("SELECT * FROM chores WHERE id = ?", (args.chore,))
    if not chore:
        print(f"Error: chore {args.chore} not found.")
        return

    require_membership(session["user_id"], chore["household_id"])

    if chore["status"] != "complete":
        print("Error: you can only dispute a completed chore.")
        return

    reason = args.reason
    if reason is None:
        reason = input("Reason for dispute: ").strip()
    if not reason or len(reason) > 1000:
        print("Error: reason must be 1–1000 characters.")
        return

    with transaction() as conn:
        complaint_id = execute_tx(
            conn,
            "INSERT INTO complaints (chore_id, submitted_by, description) VALUES (?, ?, ?)",
            (args.chore, session["user_id"], reason)
        )
        execute_tx(conn, "UPDATE chores SET status = 'disputed' WHERE id = ?", (args.chore,))

        record(
            chore["household_id"],
            session["user_id"],
            "complaint.file",
            {"chore_id": args.chore, "complaint_id": complaint_id},
            conn=conn,
        )

        notify(
            chore["household_id"],
            f"{session['username']} disputed '{chore['title']}'.",
            exclude_user_id=session["user_id"],
            conn=conn,
        )
    print(f"Complaint filed (id={complaint_id}). An admin will review it.")


def cmd_resolve(args) -> None:
    """
    Resolve a complaint (admin only).
    Usage: python main.py activity resolve --complaint <id>
                          --outcome uphold|dismiss --note "Needs to be redone"
    """
    session = require_session()

    complaint = query_one("SELECT * FROM complaints WHERE id = ?", (args.complaint,))
    if not complaint:
        print(f"Error: complaint {args.complaint} not found.")
        return

    chore = query_one("SELECT * FROM chores WHERE id = ?", (complaint["chore_id"],))
    membership = get_membership(session["user_id"], chore["household_id"])
    if not membership or membership["role"] != "admin":
        print("Error: admin privileges required to resolve complaints.")
        return

    if complaint["resolved"]:
        print("Complaint is already resolved.")
        return

    if args.outcome not in ("uphold", "dismiss"):
        print("Error: --outcome must be 'uphold' or 'dismiss'.")
        return

    note = args.note
    if note is None:
        note = input("Resolution note: ").strip()
    new_status = "pending" if args.outcome == "uphold" else "complete"

    with transaction() as conn:
        execute_tx(
            conn,
            """UPDATE complaints
               SET resolved = 1, resolution = ?, resolved_by = ?
               WHERE id = ?""",
            (note, session["user_id"], args.complaint)
        )
        execute_tx(
            conn,
            "UPDATE chores SET status = ? WHERE id = ?",
            (new_status, chore["id"]),
        )

        record(
            chore["household_id"],
            session["user_id"],
            "complaint.resolve",
            {"complaint_id": args.complaint, "outcome": args.outcome},
            conn=conn,
        )

        notify(
            chore["household_id"],
            f"Complaint on '{chore['title']}' was {args.outcome} by {session['username']}.",
            exclude_user_id=session["user_id"],
            conn=conn,
        )
    print(f"Complaint {args.outcome}. Chore status is now '{new_status}'.")


def cmd_audit(args) -> None:
    """
    Display the audit log for a household, with chain integrity check.
    Usage: python main.py activity audit --household "Maple House"
    """
    session = require_session()
    household_id = _resolve_household_id(session, args.household)
    if household_id is None:
        return
    require_membership(session["user_id"], household_id)
    membership = get_membership(session["user_id"], household_id)

    ok, msg = verify_chain(household_id)
    if ok:
        print("✓ Chain integrity verified — log has not been tampered with.\n")
    else:
        print(f"⚠ CHAIN INTEGRITY FAILED: {msg}\n")

    entries = query(
        """SELECT a.seq, a.timestamp, u.display_name AS username, a.action, a.details, a.entry_hash
           FROM audit_log a JOIN users u ON u.id = a.actor_id
           WHERE a.household_id = ?
           ORDER BY a.seq DESC""",
        (household_id,)
    )

    if not entries:
        print("No audit entries yet.")
        return

    for e in entries:
        details = json.loads(e["details"])
        detail_str = "  ".join(f"{k}={v}" for k, v in details.items())
        hash_preview = e["entry_hash"][:12] + "…"
        print(f"#{e['seq']:<4} {e['timestamp']}  {e['username']:<16} "
              f"{e['action']:<22} {detail_str}")
        # Only show hash previews to admins
        if membership["role"] == "admin":
            print(f"       hash={hash_preview}")


def cmd_poll(args) -> None:
    """
    Display unread notifications for the logged-in user.
    Usage: python main.py activity poll
    """
    session = require_session()

    notifications = query(
        """SELECT id, household_id, message, created_at
           FROM notifications
           WHERE user_id = ? AND read = 0
           ORDER BY created_at ASC, id ASC""",
        (session["user_id"],)
    )

    if not notifications:
        print("No new notifications.")
        return

    print("Notifications:\n")
    for n in notifications:
        print(f"[{n['created_at']}] {n['message']}")

    execute(
        "UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0",
        (session["user_id"],)
    )


# ---------------------------------------------------------------------------
# Subparser registration
# ---------------------------------------------------------------------------

def register_subparsers(subparsers) -> None:
    p = subparsers.add_parser("activity", help="Completion, disputes, and audit log")
    sub = p.add_subparsers(dest="activity_cmd", required=True)

    # complete
    c = sub.add_parser("complete", help="Mark a chore as complete")
    c.add_argument("--chore", type=int, required=True, metavar="CHORE_ID")
    c.set_defaults(func=cmd_complete)

    # incomplete
    c = sub.add_parser("incomplete", help="Mark a chore as incomplete")
    c.add_argument("--chore", type=int, required=True, metavar="CHORE_ID")
    c.set_defaults(func=cmd_incomplete)

    # dispute
    c = sub.add_parser("dispute", help="Dispute a completed chore")
    c.add_argument("--chore",  type=int, required=True, metavar="CHORE_ID")
    c.add_argument("--reason", default=None)
    c.set_defaults(func=cmd_dispute)

    # resolve
    c = sub.add_parser("resolve", help="Resolve a complaint (admin only)")
    c.add_argument("--complaint", type=int, required=True, metavar="COMPLAINT_ID")
    c.add_argument("--outcome",   required=True, choices=["uphold", "dismiss"])
    c.add_argument("--note",      default=None)
    c.set_defaults(func=cmd_resolve)

    # audit
    c = sub.add_parser("audit", help="View audit log for a household")
    c.add_argument("--household", required=True, metavar="HOUSEHOLD_NAME")
    c.set_defaults(func=cmd_audit)

    # poll
    c = sub.add_parser("poll", help="View unread notifications")
    c.set_defaults(func=cmd_poll)
