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

from auth import _find_user_by_username
from db import execute, query, query_one
from session import require_session


def _new_invite_code() -> str:
    """
    Generates a random invite code
    (16 hex chars)
    """
    return secrets.token_hex(8)


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


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_create_household(args) -> None:
    """
    Create a new household. The current user becomes its admin.
    Usage: python main.py household create --name "42 Elm St"
    """
    session = require_session()
    name = args.name or input("Household name: ").strip()
    if not name:
        print("Error: name cannot be empty.")
        return
    if len(name) > 64:
        print("Error: household name must be 64 characters or fewer.")
        return
    if any(ord(c) < 32 for c in name):
        print("Error: household name must not contain control characters.")
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

    print(f"Household '{name}' created (id={household_id}).")
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
    Usage: python main.py household show --id <household_id>
    """
    session = require_session()
    membership = require_membership(session["user_id"], args.id)
    row = query_one("SELECT * FROM households WHERE id = ?", (args.id,))

    print(f"\n=== {row['name']} (id={row['id']}) ===")
    if membership["role"] == "admin":
        print(f"Invite code : {row['invite_code']}")
    print(f"Created     : {row['created_at']}")

    members = query(
        """SELECT u.display_name AS username, m.role, m.joined_at
           FROM members m JOIN users u ON u.id = m.user_id
           WHERE m.household_id = ?
           ORDER BY m.joined_at""",
        (args.id,)
    )
    print(f"\nMembers ({len(members)}):")
    for m in members:
        print(f"  {m['username']:<20} {m['role']:<10} joined {m['joined_at']}")


def cmd_rotate_invite(args) -> None:
    """
    Generate a new invite code (admin only). Old code stops working immediately.
    Usage: python main.py household rotate-invite --id <household_id>
    """
    session = require_session()
    require_admin(session["user_id"], args.id)

    new_code = _new_invite_code()
    execute("UPDATE households SET invite_code = ? WHERE id = ?",
            (new_code, args.id))

    from activity import record
    record(args.id, session["user_id"], "invite.rotate", {})

    print(f"New invite code: {new_code}")
    print("The previous invite code is now invalid.")


def cmd_remove_member(args) -> None:
    """
    Remove a member from the household (admin only).
    Usage: python main.py household remove-member --id <household_id> --username bob
    """
    session = require_session()
    require_admin(session["user_id"], args.id)

    if args.username == query_one("SELECT display_name FROM users WHERE id = ?",
                                  (session["user_id"],))["display_name"]:
        print("Error: you cannot remove yourself.")
        return

    target = _find_user_by_username(args.username)
    if not target:
        print(f"Error: user '{args.username}' not found.")
        return

    m = get_membership(target["id"], args.id)
    if not m:
        print(f"Error: '{args.username}' is not in this household.")
        return

    execute("DELETE FROM members WHERE user_id = ? AND household_id = ?",
            (target["id"], args.id))

    from activity import record
    record(args.id, session["user_id"], "membership.remove",
           {"removed_username": args.username})

    print(f"'{args.username}' removed from household {args.id}.")


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
    print(f"\n{'ID':<6} {'Name':<25} {'Role':<12} {'Joined'}")
    print("-" * 60)
    for r in rows:
        print(f"{r['id']:<6} {r['name']:<25} {r['role']:<12} {r['joined_at']}")


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
    c.add_argument("--id", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.set_defaults(func=cmd_show_household)

    # rotate-invite
    c = sub.add_parser("rotate-invite", help="Generate a new invite code (admin)")
    c.add_argument("--id", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.set_defaults(func=cmd_rotate_invite)

    # remove-member
    c = sub.add_parser("remove-member", help="Remove a member (admin)")
    c.add_argument("--id",       type=int, required=True, metavar="HOUSEHOLD_ID")
    c.add_argument("--username", required=True)
    c.set_defaults(func=cmd_remove_member)

    # list
    c = sub.add_parser("list", help="List your households")
    c.set_defaults(func=cmd_list_households)
