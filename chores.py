"""
chores.py — Chore Management
Owner: Person 3

Responsibilities:
  - Create a chore (admin only)
  - Assign a chore to a roommate (admin only)
  - View chores (filtered by household, status, or assignee)

Standard library only.
"""

from auth import _find_user_by_username
from db import execute, query, query_one
from households import require_admin, require_membership
from session import require_session
from datetime import datetime, timezone
from activity import record


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _resolve_assignees(household_id: int, usernames: list[str]) -> tuple[list[tuple[int, str]], str | None]:
    assignees: list[tuple[int, str]] = []
    seen: set[int] = set()

    for username in usernames:
        target = _find_user_by_username(username)
        if not target:
            return [], f"Error: user '{username}' not found."
        if not query_one(
            "SELECT id FROM members WHERE user_id = ? AND household_id = ?",
            (target["id"], household_id),
        ):
            return [], f"Error: '{username}' is not a member of this household."
        if target["id"] in seen:
            continue
        seen.add(target["id"])
        assignees.append((target["id"], username))

    return assignees, None


def _set_chore_assignees(chore_id: int, assignees: list[tuple[int, str]]) -> None:
    execute("DELETE FROM chore_assignees WHERE chore_id = ?", (chore_id,))
    for user_id, _ in assignees:
        execute(
            "INSERT OR IGNORE INTO chore_assignees (chore_id, user_id) VALUES (?, ?)",
            (chore_id, user_id),
        )


def _get_chore_assignees(chore_id: int) -> list[str]:
    rows = query(
        """SELECT u.display_name
           FROM chore_assignees ca
           JOIN users u ON u.id = ca.user_id
           WHERE ca.chore_id = ?
           ORDER BY u.display_name""",
        (chore_id,),
    )
    return [row["display_name"] for row in rows]


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

    title = args.title
    if title is None:
        title = input("Chore title: ")
    title = title.strip()
    if not title or len(title) > 128:
        print("Error: title must be 1–128 characters.")
        return

    existing = query_one(
        """SELECT id
        FROM chores
        WHERE household_id = ?
            AND title = ?
            AND status != 'complete'""",
        (args.household, title)
    )

    if existing:
        print(f"Error: an active chore named '{title}' already exists in this household.")
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
    if isinstance(args.assign, str):
        assign_usernames = [args.assign]
    else:
        assign_usernames = args.assign or []
    assignees, error = _resolve_assignees(args.household, assign_usernames)
    if error:
        print(error)
        return
    assigned_to = assignees[0][0] if assignees else None

    chore_id = execute(
        """INSERT INTO chores
           (household_id, title, description, assigned_to, due_date, created_by)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (args.household, title, description, assigned_to, due_date, session["user_id"])
    )
    _set_chore_assignees(chore_id, assignees)

    record(
        args.household,
        session["user_id"],
        "chore.create",
        {"chore_id": chore_id, "title": title}
    )

    print(f"Chore '{title}' created (id={chore_id}).")
    if assignees:
        print(f"Assigned to: {', '.join(username for _, username in assignees)}")


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

    assignees, error = _resolve_assignees(chore["household_id"], [args.username])
    if error:
        print(error)
        return
    target_id, target_name = assignees[0]

    if query_one(
        "SELECT id FROM chore_assignees WHERE chore_id = ? AND user_id = ?",
        (args.chore, target_id),
    ):
        print(f"'{target_name}' is already assigned to chore {args.chore}.")
        return

    execute(
        "INSERT INTO chore_assignees (chore_id, user_id) VALUES (?, ?)",
        (args.chore, target_id),
    )
    if chore["assigned_to"] is None:
        execute("UPDATE chores SET assigned_to = ? WHERE id = ?", (target_id, args.chore))

    record(
        chore["household_id"],
        session["user_id"],
        "chore.assign",
        {"chore_id": args.chore, "assigned_to": target_name}
    )

    print(f"Chore {args.chore} assigned to '{target_name}'.")


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
        conditions.append(
            "EXISTS (SELECT 1 FROM chore_assignees ca WHERE ca.chore_id = c.id AND ca.user_id = ?)"
        )
        params.append(session["user_id"])

    if args.overdue:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conditions.append("c.due_date < ? AND c.status != 'complete'")
        params.append(today)

    where = " AND ".join(conditions)
    rows = query(
        f"""SELECT c.id, c.title, c.status, c.due_date,
                   GROUP_CONCAT(u.display_name, ', ') AS assignees,
                   c.created_at
            FROM chores c
            LEFT JOIN chore_assignees ca ON ca.chore_id = c.id
            LEFT JOIN users u ON u.id = ca.user_id
            WHERE {where}
            GROUP BY c.id, c.title, c.status, c.due_date, c.created_at
            ORDER BY c.due_date NULLS LAST, c.created_at""",
        tuple(params)
    )

    if not rows:
        print("No chores found.")
        return

    print(f"\n{'ID':<5} {'Title':<28} {'Status':<10} {'Assigned To':<16} {'Due'}")
    print("-" * 75)
    for r in rows:
        assignee = r["assignees"] or "(unassigned)"
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

    assignees = _get_chore_assignees(args.chore)
    assignee = ", ".join(assignees) if assignees else "(unassigned)"

    creator = query_one("SELECT display_name AS username FROM users WHERE id = ?", (chore["created_by"],))

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
        """SELECT c.description, c.resolved, u.display_name AS submitter, c.created_at
           FROM complaints c JOIN users u ON u.id = c.submitted_by
           WHERE c.chore_id = ?""",
        (args.chore,)
    )
    if complaints:
        print(f"\nComplaints ({len(complaints)}):")
        for c in complaints:
            status = "resolved" if c["resolved"] else "open"
            print(f"  [{status}] {c['submitter']}: {c['description']}")

def cmd_reschedule_chore(args) -> None:
    session = require_session()

    chore = query_one("SELECT * FROM chores WHERE id = ?", (args.chore,))
    if not chore:
        print(f"Error: chore {args.chore} not found.")
        return

    require_admin(session["user_id"], chore["household_id"])

    due_date = args.due
    if due_date is None:
        due_date = input("New due date (YYYY-MM-DD): ").strip()

    try:
        parsed_date = datetime.strptime(due_date, "%Y-%m-%d").date()
    except ValueError:
        print("Error: due date must be in YYYY-MM-DD format.")
        return

    if parsed_date < datetime.now(timezone.utc).date():
        print("Error: due date cannot be in the past.")
        return

    execute(
        "UPDATE chores SET due_date = ? WHERE id = ?",
        (due_date, args.chore)
    )

    record(
        chore["household_id"],
        session["user_id"],
        "chore.reschedule",
        {"chore_id": args.chore, "due_date": due_date}
    )

    print(f"Chore {args.chore} due date updated to {due_date}.")



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
    c.add_argument("--assign", action="append", default=[], metavar="USERNAME")
    c.set_defaults(func=cmd_create_chore)

    # assign
    c = sub.add_parser("assign", help="Assign a chore to a member (admin only)")
    c.add_argument("--chore",    type=int, required=True, metavar="CHORE_ID")
    c.add_argument("--username", required=True)
    c.set_defaults(func=cmd_assign_chore)
    

    c = sub.add_parser("reschedule", help="Update a chore due date (admin only)")
    c.add_argument("--chore", type=int, required=True, metavar="CHORE_ID")
    c.add_argument("--due", required=True, metavar="YYYY-MM-DD")
    c.set_defaults(func=cmd_reschedule_chore)


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
