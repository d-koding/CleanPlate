"""
chores.py — Chore Management
Owner: Person 3

Responsibilities:
  - Create a chore (admin only)
  - Assign a chore to a roommate (admin only)
  - View chores (filtered by household, status, or assignee)

Standard library only.
"""

from db import execute, query, query_one
from households import require_admin, require_membership
from session import require_session
from datetime import datetime, timezone
from activity import record


# ---------------------------------------------------------------------------
# COMMANDS
# ---------------------------------------------------------------------------

def cmd_create_chore(args) -> None:
    """
    Create a new chore in a household (admin only).
    Usage: python main.py chore create --household <id> --title "Take out trash"
                          [--description "..."] [--due 2025-04-01] [--assign <username>]
    """
    session  = require_session()
    require_admin(session["user_id"], args.household)



    title = args.title or input("Chore title: ").strip()
    if not title or len(title) > 128:
        print("Error: title must be 1–128 characters.")
        return

    # Prevent duplicate chore names within the same household
    existing = query_one(
        "SELECT id FROM chores WHERE household_id = ? AND title = ?",
        (args.household, title)
    )

    if existing:
        print(f"Error: a chore named '{title}' already exists in this household.")
        return

    # TODO (Person 3): validate due_date format more thoroughly
    due_date = args.due or None

    if due_date:
        try:
            parsed_date = datetime.strptime(due_date, "%Y-%m-%d").date()
        except ValueError:
            print("Error: due date must be in YYYY-MM-DD format.")
            return

        if parsed_date < datetime.now(timezone.utc).date():
            print("Error: due date cannot be in the past.")
            return

    description = args.description or ""
    assigned_to = None

    if args.assign:
        target = query_one("SELECT id FROM users WHERE username = ?", (args.assign,))
        if not target:
            print(f"Error: user '{args.assign}' not found.")
            return
        # Verify the assignee is in the household
        if not query_one("SELECT id FROM members WHERE user_id = ? AND household_id = ?",
                         (target["id"], args.household)):
            print(f"Error: '{args.assign}' is not a member of this household.")
            return
        assigned_to = target["id"]

    chore_id = execute(
        """INSERT INTO chores
           (household_id, title, description, assigned_to, due_date, created_by)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (args.household, title, description, assigned_to, due_date, session["user_id"])
    )

    record(
        args.household,
        session["user_id"],
        "chore.create",
        {"chore_id": chore_id, "title": title}
    )

    print(f"Chore '{title}' created (id={chore_id}).")
    if assigned_to:
        print(f"Assigned to: {args.assign}")


def cmd_assign_chore(args) -> None:
    """
    Assign (or reassign) a chore to a household member (admin only).
    Usage: python main.py chore assign --chore <id> --username bob
    """
    session = require_session()

    chore = query_one("SELECT * FROM chores WHERE id = ?", (args.chore,))
    if not chore:
        print(f"Error: chore {args.chore} not found.")
        return

    require_admin(session["user_id"], chore["household_id"])

    target = query_one("SELECT id FROM users WHERE username = ?", (args.username,))
    if not target:
        print(f"Error: user '{args.username}' not found.")
        return
    if not query_one("SELECT id FROM members WHERE user_id = ? AND household_id = ?",
                     (target["id"], chore["household_id"])):
        print(f"Error: '{args.username}' is not in this household.")
        return

    execute("UPDATE chores SET assigned_to = ? WHERE id = ?",
            (target["id"], args.chore))

    record(
        chore["household_id"],
        session["user_id"],
        "chore.assign",
        {"chore_id": args.chore, "assigned_to": args.username}
    )

    print(f"Chore {args.chore} assigned to '{args.username}'.")


def cmd_list_chores(args) -> None:
    """
    List chores in a household. Optionally filter by status or assignee.
    Usage: python main.py chore list --household <id>
                          [--status pending|complete|disputed]
                          [--mine]
    """
    session    = require_session()
    membership = require_membership(session["user_id"], args.household)

    conditions = ["c.household_id = ?"]
    params     = [args.household]

    if args.status:
        conditions.append("c.status = ?")
        params.append(args.status)

    if args.mine:
        conditions.append("c.assigned_to = ?")
        params.append(session["user_id"])

    if args.overdue:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conditions.append("c.due_date < ? AND c.status != 'complete'")
        params.append(today)

    where = " AND ".join(conditions)
    rows = query(
        f"""SELECT c.id, c.title, c.status, c.due_date,
                   u.username AS assignee, c.created_at
            FROM chores c
            LEFT JOIN users u ON u.id = c.assigned_to
            WHERE {where}
            ORDER BY c.due_date NULLS LAST, c.created_at""",
        tuple(params)
    )

    if not rows:
        print("No chores found.")
        return

    print(f"\n{'ID':<5} {'Title':<28} {'Status':<10} {'Assigned To':<16} {'Due'}")
    print("-" * 75)
    for r in rows:
        assignee = r["assignee"] or "(unassigned)"
        due      = r["due_date"] or "—"
        print(f"{r['id']:<5} {r['title']:<28} {r['status']:<10} {assignee:<16} {due}")


def cmd_show_chore(args) -> None:
    """
    Show full details of a single chore.
    Usage: python main.py chore show --chore <id>
    """
    session = require_session()

    chore = query_one("SELECT * FROM chores WHERE id = ?", (args.chore,))
    if not chore:
        print(f"Error: chore {args.chore} not found.")
        return

    require_membership(session["user_id"], chore["household_id"])

    assignee = "(unassigned)"
    if chore["assigned_to"]:
        u = query_one("SELECT username FROM users WHERE id = ?", (chore["assigned_to"],))
        assignee = u["username"] if u else "unknown"

    creator = query_one("SELECT username FROM users WHERE id = ?", (chore["created_by"],))

    print(f"\n=== Chore #{chore['id']}: {chore['title']} ===")
    print(f"Status      : {chore['status']}")
    print(f"Assigned to : {assignee}")
    print(f"Due date    : {chore['due_date'] or '—'}")
    print(f"Description : {chore['description'] or '(none)'}")
    print(f"Created by  : {creator['username'] if creator else 'unknown'}")
    print(f"Created at  : {chore['created_at']}")
    if chore["completed_at"]:
        print(f"Completed at: {chore['completed_at']}")

    # Show any complaints
    complaints = query(
        """SELECT c.description, c.resolved, u.username AS submitter, c.created_at
           FROM complaints c JOIN users u ON u.id = c.submitted_by
           WHERE c.chore_id = ?""",
        (args.chore,)
    )
    if complaints:
        print(f"\nComplaints ({len(complaints)}):")
        for c in complaints:
            status = "resolved" if c["resolved"] else "open"
            print(f"  [{status}] {c['submitter']}: {c['description']}")


# ---------------------------------------------------------------------------
# Subparser registration
# ---------------------------------------------------------------------------

def register_subparsers(subparsers) -> None:
    p = subparsers.add_parser("chore", help="Chore management commands")
    sub = p.add_subparsers(dest="chore_cmd", required=True)

    # create
    c = sub.add_parser("create", help="Create a chore (admin only)")
    c.add_argument("--household",   type=int, required=True, metavar="HOUSEHOLD_ID")
    c.add_argument("--title",       default=None)
    c.add_argument("--description", default="")
    c.add_argument("--due",         default=None, metavar="YYYY-MM-DD")
    c.add_argument("--assign",      default=None, metavar="USERNAME")
    c.set_defaults(func=cmd_create_chore)

    # assign
    c = sub.add_parser("assign", help="Assign a chore to a member (admin only)")
    c.add_argument("--chore",    type=int, required=True, metavar="CHORE_ID")
    c.add_argument("--username", required=True)
    c.set_defaults(func=cmd_assign_chore)

    # list
    c = sub.add_parser("list", help="List chores in a household")
    c.add_argument("--household", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.add_argument("--status",    default=None, choices=["pending", "complete", "disputed"])
    c.add_argument("--mine",      action="store_true", help="Only show chores assigned to you")
    c.add_argument("--overdue", action="store_true", help="Show overdue chores")
    c.set_defaults(func=cmd_list_chores)

    # show
    c = sub.add_parser("show", help="Show full details of a chore")
    c.add_argument("--chore", type=int, required=True, metavar="CHORE_ID")
    c.set_defaults(func=cmd_show_chore)
