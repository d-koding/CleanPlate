"""
households.py — Household Management
Owner: Person 2

Responsibilities:
  - Create a household (creator becomes admin)
  - Generate and rotate invite codes
  - Join a household using an invite code
  - List members, show household info
  - Remove a member (admin only)

Standard library only: secrets
"""

import secrets
import sqlite3

from auth import _find_user_by_username, _send_email
from db import execute, query, query_one
from session import require_session


def _new_invite_code() -> str:
    """
    Generates a random invite code
    (16 hex chars)
    """
    return secrets.token_hex(8)


def _normalize_household_name(name: str) -> str:
    return name.strip()


# ---------------------------------------------------------------------------
# Auth helpers (used by other modules too)
# ---------------------------------------------------------------------------

def get_membership(user_id: int, household_id: int) -> sqlite3.Row | None:
    """
    Return the member row if user belongs to household, else None.
    """
    return query_one(
        "SELECT * FROM members WHERE user_id = ? AND household_id = ?",
        (user_id, household_id)
    )


def require_membership(user_id: int, household_id: int):
    """
    Exit with error if the user is not in the household.
    """
    m = get_membership(user_id, household_id)
    if m is None:
        print("Error: you are not a member of that household.")
        raise SystemExit(1)
    return m


def require_admin(user_id: int, household_id: int):
    """
    Exit with error if the user is not an admin of the household.
    """
    m = require_membership(user_id, household_id)
    if m["role"] != "admin":
        print("Error: admin privileges required.")
        raise SystemExit(1)
    return m


def _count_admins(household_id: int) -> int:
    row = query_one(
        "SELECT COUNT(*) AS count FROM members WHERE household_id = ? AND role = 'admin'",
        (household_id,),
    )
    return row["count"] if row is not None else 0


def _next_roommate_to_promote(household_id: int, exclude_user_id: int) -> sqlite3.Row | None:
    return query_one(
        """SELECT user_id
           FROM members
           WHERE household_id = ? AND user_id != ? AND role = 'roommate'
           ORDER BY joined_at ASC, id ASC
           LIMIT 1""",
        (household_id, exclude_user_id),
    )


def _promote_successor_if_needed(household_id: int, departing_user_id: int) -> str | None:
    departing_membership = get_membership(departing_user_id, household_id)
    if departing_membership is None or departing_membership["role"] != "admin":
        return None

    if _count_admins(household_id) > 1:
        return None

    successor = _next_roommate_to_promote(household_id, departing_user_id)
    if successor is None:
        return None

    execute(
        "UPDATE members SET role = 'admin' WHERE user_id = ? AND household_id = ?",
        (successor["user_id"], household_id),
    )
    promoted_user = query_one("SELECT display_name FROM users WHERE id = ?", (successor["user_id"],))
    return promoted_user["display_name"] if promoted_user is not None else None


def _count_members(household_id: int) -> int:
    row = query_one(
        "SELECT COUNT(*) AS count FROM members WHERE household_id = ?",
        (household_id,),
    )
    return row["count"] if row is not None else 0


def _delete_household_if_empty(household_id: int) -> bool:
    if _count_members(household_id) != 0:
        return False

    execute(
        """DELETE FROM complaints
           WHERE chore_id IN (SELECT id FROM chores WHERE household_id = ?)""",
        (household_id,),
    )
    execute("DELETE FROM notifications WHERE household_id = ?", (household_id,))
    execute("DELETE FROM audit_log WHERE household_id = ?", (household_id,))
    execute("DELETE FROM chores WHERE household_id = ?", (household_id,))
    execute("DELETE FROM households WHERE id = ?", (household_id,))
    return True


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_create_household(args) -> None:
    """
    Create a new household. The current user becomes its admin.
    Usage: python main.py household create --name "42 Elm St"
    """
    session = require_session()
    name = args.name
    if name is None:
        name = input("Household name: ").strip()
    else:
        name = name.strip()
    if not name:
        print("Error: name cannot be empty.")
        return
    if len(name) > 64:
        print("Error: household name must be 64 characters or fewer.")
        return
    if any(ord(c) < 32 for c in name):
        print("Error: household name must not contain control characters.")
        return
    if query_one("SELECT id FROM households WHERE name = ?", (name,)):
        print(f"Error: a household named '{name}' already exists.")
        return
    user_row = query_one("SELECT id FROM users WHERE id = ?", (session["user_id"],))
    if user_row is None:
        print("Error: current session user does not exist. Please log in again.")
        return

    invite_code  = _new_invite_code()
    household_id = execute(
        "INSERT INTO households (name, invite_code) VALUES (?, ?)",
        (name, invite_code)
    )
    execute(
        "INSERT INTO members (user_id, household_id, role) VALUES (?, ?, 'admin')",
        (session["user_id"], household_id)
    )

    from activity import record
    record(household_id, session["user_id"], "household.create", {"name": name})

    print(f"Household '{name}' created.")
    print(f"Invite code: {invite_code}")
    print("Share this code with your roommates so they can join.")


def cmd_join_household(args) -> None:
    """
    Join a household using its invite code.
    Usage: python main.py household join --code <invite_code>
    """
    session = require_session()
    code = args.code or input("Invite code: ").strip()

    row = query_one("SELECT * FROM households WHERE invite_code = ?", (code,))
    if row is None:
        print("Error: invalid invite code.")
        return

    existing = get_membership(session["user_id"], row["id"])
    if existing:
        print(f"You are already a member of '{row['name']}'.")
        return

    execute(
        "INSERT INTO members (user_id, household_id, role) VALUES (?, ?, 'roommate')",
        (session["user_id"], row["id"])
    )

    from activity import record
    record(row["id"], session["user_id"], "membership.join",
           {"username": session["username"]})

    print(f"Joined '{row['name']}' as a roommate.")


def cmd_show_household(args) -> None:
    """
    Show household details: name, invite code (admin only), members.
    Usage: python main.py household show --household "Maple House"
    """
    session = require_session()
    household_ref = getattr(args, "household", getattr(args, "id", None))
    household_id = _resolve_household_id(session, household_ref)
    if household_id is None:
        return
    membership = require_membership(session["user_id"], household_id)
    row = query_one("SELECT * FROM households WHERE id = ?", (household_id,))

    print(f"\n=== {row['name']} ===")
    if membership["role"] == "admin":
        print(f"Invite code : {row['invite_code']}")
    print(f"Created     : {row['created_at']}")

    members = query(
        """SELECT u.display_name AS username, m.role, m.joined_at
           FROM members m JOIN users u ON u.id = m.user_id
           WHERE m.household_id = ?
           ORDER BY m.joined_at""",
        (household_id,)
    )
    print(f"\nMembers ({len(members)}):")
    for m in members:
        print(f"  {m['username']:<20} {m['role']:<10} joined {m['joined_at']}")


def cmd_rotate_invite(args) -> None:
    """
    Generate a new invite code (admin only). Old code stops working immediately.
    Usage: python main.py household rotate-invite --household "Maple House"
    """
    session = require_session()
    household_ref = getattr(args, "household", getattr(args, "id", None))
    household_id = _resolve_household_id(session, household_ref)
    if household_id is None:
        return
    require_admin(session["user_id"], household_id)

    new_code = _new_invite_code()
    execute("UPDATE households SET invite_code = ? WHERE id = ?",
            (new_code, household_id))

    from activity import record
    record(household_id, session["user_id"], "invite.rotate", {})

    print(f"New invite code: {new_code}")
    print("The previous invite code is now invalid.")


def cmd_remove_member(args) -> None:
    """
    Remove a member from the household (admin only).
    Usage: python main.py household remove-member --household "Maple House" --username bob
    """
    session = require_session()
    household_ref = getattr(args, "household", getattr(args, "id", None))
    household_id = _resolve_household_id(session, household_ref)
    if household_id is None:
        return
    require_admin(session["user_id"], household_id)

    if args.username == query_one("SELECT display_name FROM users WHERE id = ?",
                                  (session["user_id"],))["display_name"]:
        print("Error: you cannot remove yourself.")
        return

    target = _find_user_by_username(args.username)
    if not target:
        print(f"Error: user '{args.username}' not found.")
        return

    m = get_membership(target["id"], household_id)
    if not m:
        print(f"Error: '{args.username}' is not in this household.")
        return

    promoted_username = _promote_successor_if_needed(household_id, target["id"])

    execute("DELETE FROM members WHERE user_id = ? AND household_id = ?",
            (target["id"], household_id))

    from activity import record
    record(household_id, session["user_id"], "membership.remove",
           {"removed_username": args.username})
    if promoted_username is not None:
        record(household_id, session["user_id"], "membership.promote",
               {"username": promoted_username, "reason": "admin_departure"})

    household_name = query_one("SELECT name FROM households WHERE id = ?", (household_id,))["name"]
    print(f"'{args.username}' removed from household '{household_name}'.")
    if promoted_username is not None:
        print(f"'{promoted_username}' was automatically promoted to admin.")


def cmd_leave_household(args) -> None:
    """
    Leave a household yourself.
    Usage: python main.py household leave --household "Maple House"
           python main.py leave-household "Maple House"
    """
    session = require_session()
    household_ref = getattr(args, "household", getattr(args, "id", None))
    household_id = _resolve_household_id(session, household_ref)
    if household_id is None:
        return

    membership = require_membership(session["user_id"], household_id)
    household_row = query_one("SELECT name FROM households WHERE id = ?", (household_id,))
    household_name = household_row["name"]
    promoted_username = _promote_successor_if_needed(household_id, session["user_id"])

    execute(
        "DELETE FROM members WHERE user_id = ? AND household_id = ?",
        (session["user_id"], household_id),
    )
    household_deleted = _delete_household_if_empty(household_id)

    from activity import record
    if not household_deleted:
        record(
            household_id,
            session["user_id"],
            "membership.leave",
            {"username": session["username"]},
        )
        if promoted_username is not None and membership["role"] == "admin":
            record(
                household_id,
                session["user_id"],
                "membership.promote",
                {"username": promoted_username, "reason": "admin_departure"},
            )

    print(f"You left household '{household_name}'.")
    if household_deleted:
        print(f"Household '{household_name}' had no remaining members and was deleted.")
    if promoted_username is not None:
        print(f"'{promoted_username}' was automatically promoted to admin.")


def cmd_send_invite(args) -> None:
    """
    Email the household invite code to a recipient (admin only).
    Accepts an email address or a username (looks up their registered email).
    Usage: python main.py household send-invite --household "Maple House" --email <email|username>
           python main.py invite bob@example.com
           python main.py invite bob
    Requires env vars: CLEANPLATE_SMTP_HOST, CLEANPLATE_SMTP_PORT,
                       CLEANPLATE_SMTP_USER, CLEANPLATE_SMTP_PASS
    """
    session = require_session()
    household_ref = getattr(args, "household", getattr(args, "id", None))
    household_id = _resolve_household_id(session, household_ref)
    if household_id is None:
        return
    require_admin(session["user_id"], household_id)

    recipient = getattr(args, "email", None) or input("Recipient (email or username): ").strip()
    if not recipient:
        print("Error: recipient cannot be empty.")
        return

    # If not an email address, look up the user's registered email
    if "@" not in recipient:
        target = _find_user_by_username(recipient)
        if not target:
            print(f"Error: user '{recipient}' not found.")
            raise SystemExit(1)
        user_row = query_one("SELECT email FROM users WHERE id = ?", (target["id"],))
        if not user_row or not user_row["email"]:
            print(f"Error: '{recipient}' has no email address on file.")
            raise SystemExit(1)
        email = user_row["email"]
    else:
        email = recipient.strip().lower()

    row = query_one("SELECT * FROM households WHERE id = ?", (household_id,))
    if row is None:
        print("Error: household not found.")
        return

    subject = f"You're invited to join '{row['name']}' on CleanPlate"
    body = (
        f"Hi,\n\n"
        f"You've been invited to join the '{row['name']}' household on CleanPlate.\n\n"
        f"Use this invite code to join:\n\n"
        f"    {row['invite_code']}\n\n"
        f"Run this command to join:\n\n"
        f"    join-household {row['invite_code']}\n\n"
        f"Welcome aboard!\n"
    )

    try:
        _send_email(email, subject, body)
    except Exception as e:
        print(f"Error: could not send email: {e}")
        return

    from activity import record
    record(household_id, session["user_id"], "invite.sent", {"email": email})

    print(f"Invite email sent to {email}.")


def _resolve_household_id(session: dict, given_id: int | str | None) -> int | None:
    """
    Return the household ID to use for a command.
    If given_id is an int, use it directly.
    If given_id is a name, resolve it within the caller's memberships.
    If the user is in exactly one household, use that.
    Otherwise print an error and return None.
    """
    if given_id is not None:
        if isinstance(given_id, int):
            return given_id
        given_name = _normalize_household_name(str(given_id))
        row = query_one(
            """SELECT h.id
               FROM members m
               JOIN households h ON h.id = m.household_id
               WHERE m.user_id = ? AND h.name = ?""",
            (session["user_id"], given_name),
        )
        if row is None:
            print(f"Error: you are not a member of a household named '{given_name}'.")
            return None
        return row["id"]
    rows = query(
        """SELECT household_id, h.name
           FROM members m
           JOIN households h ON h.id = m.household_id
           WHERE m.user_id = ?""",
        (session["user_id"],)
    )
    if not rows:
        print("Error: you are not a member of any household.")
        return None
    if len(rows) > 1:
        print("Error: you belong to multiple households — specify one with --household \"<name>\".")
        return None
    return rows[0]["household_id"]


def cmd_promote_member(args) -> None:
    """
    Promote a roommate to admin (admin only).
    Usage: python main.py household promote --household "Maple House" --username <username>
           python main.py promote <username>   (when in exactly one household)
    """
    session = require_session()
    household_ref = getattr(args, "household", getattr(args, "id", None))
    household_id = _resolve_household_id(session, household_ref)
    if household_id is None:
        return
    require_admin(session["user_id"], household_id)

    target = _find_user_by_username(args.username)
    if not target:
        print(f"Error: user '{args.username}' not found.")
        return

    m = get_membership(target["id"], household_id)
    if not m:
        print(f"Error: '{args.username}' is not in this household.")
        return

    if m["role"] == "admin":
        print(f"'{args.username}' is already an admin.")
        return

    execute(
        "UPDATE members SET role = 'admin' WHERE user_id = ? AND household_id = ?",
        (target["id"], household_id)
    )

    from activity import record
    record(household_id, session["user_id"], "membership.promote", {"username": args.username})

    print(f"'{args.username}' promoted to admin.")


def cmd_demote_member(args) -> None:
    """
    Demote an admin to roommate (admin only). Cannot demote yourself.
    Usage: python main.py household demote --household "Maple House" --username <username>
           python main.py demote <username>   (when in exactly one household)
    """
    session = require_session()
    household_ref = getattr(args, "household", getattr(args, "id", None))
    household_id = _resolve_household_id(session, household_ref)
    if household_id is None:
        return
    require_admin(session["user_id"], household_id)

    self_row = query_one("SELECT display_name FROM users WHERE id = ?", (session["user_id"],))
    if args.username == self_row["display_name"]:
        print("Error: you cannot demote yourself.")
        return

    target = _find_user_by_username(args.username)
    if not target:
        print(f"Error: user '{args.username}' not found.")
        return

    m = get_membership(target["id"], household_id)
    if not m:
        print(f"Error: '{args.username}' is not in this household.")
        return

    if m["role"] == "roommate":
        print(f"'{args.username}' is already a roommate.")
        return

    if _count_admins(household_id) == 1:
        print("Error: you cannot demote the last admin.")
        return

    execute(
        "UPDATE members SET role = 'roommate' WHERE user_id = ? AND household_id = ?",
        (target["id"], household_id)
    )

    from activity import record
    record(household_id, session["user_id"], "membership.demote", {"username": args.username})

    print(f"'{args.username}' demoted to roommate.")


def cmd_list_households(args) -> None:
    """
    List all households the current user belongs to.
    Usage: python main.py household list
    """
    session = require_session()
    rows = query(
        """SELECT h.id, h.name, m.role, m.joined_at
           FROM members m JOIN households h ON h.id = m.household_id
           WHERE m.user_id = ?
           ORDER BY m.joined_at""",
        (session["user_id"],)
    )
    if not rows:
        print("You are not a member of any households.")
        return
    print(f"\n{'Name':<25} {'Role':<12} {'Joined'}")
    print("-" * 52)
    for r in rows:
        print(f"{r['name']:<25} {r['role']:<12} {r['joined_at']}")


# ---------------------------------------------------------------------------
# Subparser registration
# ---------------------------------------------------------------------------

def register_subparsers(subparsers) -> None:
    p = subparsers.add_parser("household", help="Household management commands")
    sub = p.add_subparsers(dest="household_cmd", required=True)

    # create
    c = sub.add_parser("create", help="Create a new household")
    c.add_argument("--name", default=None)
    c.set_defaults(func=cmd_create_household)

    # join
    c = sub.add_parser("join", help="Join a household via invite code")
    c.add_argument("--code", default=None)
    c.set_defaults(func=cmd_join_household)

    # show
    c = sub.add_parser("show", help="Show household info and members")
    c.add_argument("--household", "--id", dest="household", default=None, metavar="HOUSEHOLD_NAME")
    c.set_defaults(func=cmd_show_household)

    # rotate-invite
    c = sub.add_parser("rotate-invite", help="Generate a new invite code (admin)")
    c.add_argument("--household", "--id", dest="household", default=None, metavar="HOUSEHOLD_NAME")
    c.set_defaults(func=cmd_rotate_invite)

    # remove-member
    c = sub.add_parser("remove-member", help="Remove a member (admin)")
    c.add_argument("--household", "--id", dest="household", default=None, metavar="HOUSEHOLD_NAME")
    c.add_argument("--username", required=True)
    c.set_defaults(func=cmd_remove_member)

    # list
    c = sub.add_parser("list", help="List your households")
    c.set_defaults(func=cmd_list_households)

    # leave
    c = sub.add_parser("leave", help="Leave a household")
    c.add_argument("--household", "--id", dest="household", default=None, metavar="HOUSEHOLD_NAME")
    c.set_defaults(func=cmd_leave_household)

    # promote
    c = sub.add_parser("promote", help="Promote a roommate to admin (admin only)")
    c.add_argument("--household", "--id", dest="household", default=None, metavar="HOUSEHOLD_NAME")
    c.add_argument("--username", required=True)
    c.set_defaults(func=cmd_promote_member)

    # demote
    c = sub.add_parser("demote", help="Demote an admin to roommate (admin only)")
    c.add_argument("--household", "--id", dest="household", default=None, metavar="HOUSEHOLD_NAME")
    c.add_argument("--username", required=True)
    c.set_defaults(func=cmd_demote_member)

    # send-invite
    c = sub.add_parser("send-invite", help="Email the invite code to a recipient (admin only)")
    c.add_argument("--household", "--id", dest="household", default=None, metavar="HOUSEHOLD_NAME")
    c.add_argument("--email", default=None)
    c.set_defaults(func=cmd_send_invite)
