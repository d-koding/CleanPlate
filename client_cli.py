"""
client_cli.py — CLI handlers that talk to the CleanPlate HTTP server.
"""

from __future__ import annotations

import argparse
import getpass

from api_client import ClientError, get_server_url, invoke
from session import clear_session, load_session, require_session, save_session


def _print_output(output: str) -> None:
    if output:
        print(output, end="" if output.endswith("\n") else "\n")


def _handle_response(response: dict, *, persist_session: bool = False, clear_local_session: bool = False) -> None:
    _print_output(response.get("output", ""))

    if not response.get("ok"):
        error = response.get("error")
        if error and error not in response.get("output", ""):
            print(error)
        raise SystemExit(response.get("exit_code", 1))

    if persist_session:
        session_data = response.get("session")
        if session_data:
            save_session(session_data["user_id"], session_data["username"])
    if clear_local_session:
        clear_session()


def _server_session() -> dict:
    return require_session()


def cmd_register(args) -> None:
    username = (args.username or input("Username: ").strip()).strip()
    password = getpass.getpass("Password (min 8 chars): ")
    confirm_password = getpass.getpass("Confirm password: ")

    try:
        response = invoke(
            "register",
            {
                "username": username,
                "password": password,
                "confirm_password": confirm_password,
            },
            None,
        )
    except ClientError as exc:
        print(exc)
        raise SystemExit(1)
    _handle_response(response)


def cmd_login(args) -> None:
    username = (args.username or input("Username: ").strip()).strip()
    password = getpass.getpass("Password: ")

    try:
        response = invoke(
            "login",
            {"username": username, "password": password},
            None,
        )
    except ClientError as exc:
        print(exc)
        raise SystemExit(1)
    _handle_response(response, persist_session=True)


def cmd_logout(args) -> None:
    session = load_session()
    if session:
        clear_session()
        print(f"Logged out '{session['username']}'.")
    else:
        print("No active session.")


def cmd_whoami(args) -> None:
    session = load_session()
    if session:
        print(f"Logged in as: {session['username']}  (user_id={session['user_id']})")
    else:
        print("Not logged in.")


def _remote_command(action: str, payload: dict) -> None:
    try:
        response = invoke(action, payload, _server_session())
    except ClientError as exc:
        print(exc)
        raise SystemExit(1)
    _handle_response(response)


def cmd_create_household(args) -> None:
    name = args.name or input("Household name: ").strip()
    _remote_command("household.create", {"name": name})


def cmd_join_household(args) -> None:
    code = args.code or input("Invite code: ").strip()
    _remote_command("household.join", {"code": code})


def cmd_show_household(args) -> None:
    _remote_command("household.show", {"id": args.id})


def cmd_rotate_invite(args) -> None:
    _remote_command("household.rotate-invite", {"id": args.id})


def cmd_remove_member(args) -> None:
    _remote_command("household.remove-member", {"id": args.id, "username": args.username})


def cmd_list_households(args) -> None:
    _remote_command("household.list", {})


def cmd_create_chore(args) -> None:
    title = args.title or input("Chore title: ").strip()
    _remote_command(
        "chore.create",
        {
            "household": args.household,
            "title": title,
            "description": args.description,
            "due": args.due,
            "assign": args.assign,
        },
    )


def cmd_assign_chore(args) -> None:
    _remote_command("chore.assign", {"chore": args.chore, "username": args.username})


def cmd_list_chores(args) -> None:
    _remote_command(
        "chore.list",
        {
            "household": args.household,
            "status": args.status,
            "mine": args.mine,
            "overdue": args.overdue,
        },
    )


def cmd_show_chore(args) -> None:
    _remote_command("chore.show", {"chore": args.chore})


def cmd_complete(args) -> None:
    _remote_command("activity.complete", {"chore": args.chore})


def cmd_dispute(args) -> None:
    reason = args.reason or input("Reason for dispute: ").strip()
    _remote_command("activity.dispute", {"chore": args.chore, "reason": reason})


def cmd_resolve(args) -> None:
    note = args.note or input("Resolution note: ").strip()
    _remote_command(
        "activity.resolve",
        {"complaint": args.complaint, "outcome": args.outcome, "note": note},
    )


def cmd_audit(args) -> None:
    _remote_command("activity.audit", {"household": args.household})


def cmd_poll(args) -> None:
    _remote_command("activity.poll", {})


def register_subparsers(subparsers) -> None:
    p = subparsers.add_parser("register", help="Create a new user account")
    p.add_argument("--username", default=None, help="Desired username")
    p.set_defaults(func=cmd_register)

    p = subparsers.add_parser("login", help=f"Log in via server at {get_server_url()}")
    p.add_argument("--username", default=None, help="Your username")
    p.set_defaults(func=cmd_login)

    p = subparsers.add_parser("logout", help="Log out locally")
    p.set_defaults(func=cmd_logout)

    p = subparsers.add_parser("whoami", help="Show who is currently logged in")
    p.set_defaults(func=cmd_whoami)

    p = subparsers.add_parser("household", help="Household management commands")
    sub = p.add_subparsers(dest="household_cmd", required=True)

    c = sub.add_parser("create", help="Create a new household")
    c.add_argument("--name", default=None)
    c.set_defaults(func=cmd_create_household)

    c = sub.add_parser("join", help="Join a household via invite code")
    c.add_argument("--code", default=None)
    c.set_defaults(func=cmd_join_household)

    c = sub.add_parser("show", help="Show household info and members")
    c.add_argument("--id", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.set_defaults(func=cmd_show_household)

    c = sub.add_parser("list", help="List your households")
    c.set_defaults(func=cmd_list_households)

    c = sub.add_parser("rotate-invite", help="Generate a new invite code (admin)")
    c.add_argument("--id", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.set_defaults(func=cmd_rotate_invite)

    c = sub.add_parser("remove-member", help="Remove a member (admin)")
    c.add_argument("--id", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.add_argument("--username", required=True)
    c.set_defaults(func=cmd_remove_member)

    p = subparsers.add_parser("chore", help="Chore management commands")
    sub = p.add_subparsers(dest="chore_cmd", required=True)

    c = sub.add_parser("create", help="Create a chore (admin only)")
    c.add_argument("--household", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.add_argument("--title", default=None)
    c.add_argument("--description", default="")
    c.add_argument("--due", default=None, metavar="YYYY-MM-DD")
    c.add_argument("--assign", default=None, metavar="USERNAME")
    c.set_defaults(func=cmd_create_chore)

    c = sub.add_parser("assign", help="Assign a chore to a member (admin only)")
    c.add_argument("--chore", type=int, required=True, metavar="CHORE_ID")
    c.add_argument("--username", required=True)
    c.set_defaults(func=cmd_assign_chore)

    c = sub.add_parser("list", help="List chores in a household")
    c.add_argument("--household", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.add_argument("--status", default=None, choices=["pending", "complete", "disputed"])
    c.add_argument("--mine", action="store_true", help="Only show chores assigned to you")
    c.add_argument("--overdue", action="store_true", help="Show overdue chores")
    c.set_defaults(func=cmd_list_chores)

    c = sub.add_parser("show", help="Show full details of a chore")
    c.add_argument("--chore", type=int, required=True, metavar="CHORE_ID")
    c.set_defaults(func=cmd_show_chore)

    p = subparsers.add_parser("activity", help="Completion, disputes, and audit log")
    sub = p.add_subparsers(dest="activity_cmd", required=True)

    c = sub.add_parser("complete", help="Mark a chore as complete")
    c.add_argument("--chore", type=int, required=True, metavar="CHORE_ID")
    c.set_defaults(func=cmd_complete)

    c = sub.add_parser("dispute", help="Dispute a completed chore")
    c.add_argument("--chore", type=int, required=True, metavar="CHORE_ID")
    c.add_argument("--reason", default=None)
    c.set_defaults(func=cmd_dispute)

    c = sub.add_parser("resolve", help="Resolve a complaint (admin only)")
    c.add_argument("--complaint", type=int, required=True, metavar="COMPLAINT_ID")
    c.add_argument("--outcome", required=True, choices=["uphold", "dismiss"])
    c.add_argument("--note", default=None)
    c.set_defaults(func=cmd_resolve)

    c = sub.add_parser("audit", help="View audit log for a household")
    c.add_argument("--household", type=int, required=True, metavar="HOUSEHOLD_ID")
    c.set_defaults(func=cmd_audit)

    c = sub.add_parser("poll", help="View unread notifications")
    c.set_defaults(func=cmd_poll)
