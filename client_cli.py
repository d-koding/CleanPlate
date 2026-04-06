"""
client_cli.py — CLI handlers that talk to the CleanPlate HTTP server.
"""

from __future__ import annotations

import argparse
import getpass

from api_client import ClientError, get_server_url, invoke
from session import clear_session, load_session, require_session, save_session


def _prompt_text(prompt: str) -> str:
    return input(prompt).strip()


def _prompt_int(prompt: str) -> int | None:
    raw = input(prompt).strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        print("Error: please enter a number.")
        return None


def _prompt_optional_text(prompt: str) -> str | None:
    raw = input(prompt).strip()
    return raw or None


def _prompt_assign_list(prompt: str) -> list[str]:
    raw = input(prompt).strip()
    return [raw] if raw else []


def _validate_username_format(username: str) -> bool:
    """Client-side format check — mirrors server-side validation in auth.py."""
    if not username:
        print("Error: username cannot be empty.")
        return False
    if len(username) < 3 or len(username) > 32:
        print("Error: username must be between 3 and 32 characters.")
        return False
    if not all(c.isalnum() or c in "-_" for c in username):
        print("Error: username may only contain letters, numbers, hyphens, and underscores.")
        return False
    return True


def _arg(args, primary: str, fallback: str | None = None):
    value = getattr(args, primary, None)
    if value is not None:
        return value
    if fallback is not None:
        return getattr(args, fallback, None)
    return None


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
    username = (getattr(args, "username", None) or _prompt_text("Username: ")).strip()
    if not _validate_username_format(username):
        return

    email = (getattr(args, "email", None) or _prompt_text("Email address: ")).strip()

    from auth import _check_password_strength
    password = getpass.getpass("Password (min 8 chars): ")
    errors = _check_password_strength(password)
    if errors:
        print("Password does not meet requirements:")
        for e in errors:
            print(f"  • {e}")
        return

    confirm_password = getpass.getpass("Confirm password: ")

    try:
        response = invoke(
            "register",
            {
                "username": username,
                "email": email,
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
    username = (getattr(args, "username", None) or _prompt_text("Username or email: ")).strip()
    if "@" not in username and not _validate_username_format(username):
        return
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


def cmd_verify_email(args) -> None:
    code = (_arg(args, "code", "code_pos") or input("Verification code: ").strip()).strip()
    try:
        response = invoke("verify", {"code": code}, None)
    except ClientError as exc:
        print(exc)
        raise SystemExit(1)
    _handle_response(response)


def cmd_resend_verification(args) -> None:
    username = (_arg(args, "username", "username_pos") or input("Username or email: ").strip()).strip()
    try:
        response = invoke("resend-verification", {"username": username}, None)
    except ClientError as exc:
        print(exc)
        raise SystemExit(1)
    _handle_response(response)


def cmd_reset_password(args) -> None:
    username = (args.username or _prompt_text("Username: ")).strip()
    current_password = getpass.getpass("Current password: ")
    new_password = getpass.getpass("New password (min 8 chars): ")
    confirm_password = getpass.getpass("Confirm new password: ")

    try:
        response = invoke(
            "reset-password",
            {
                "username": username,
                "current_password": current_password,
                "new_password": new_password,
                "confirm_password": confirm_password,
            },
            None,
        )
    except ClientError as exc:
        print(exc)
        raise SystemExit(1)
    _handle_response(response)


def cmd_forgot_password(args) -> None:
    username = (_arg(args, "username", "username_pos") or input("Username: ").strip()).strip()

    try:
        response = invoke(
            "forgot-password",
            {"username": username},
            None,
        )
    except ClientError as exc:
        print(exc)
        raise SystemExit(1)
    _handle_response(response)


def cmd_recover_password(args) -> None:
    username = (_arg(args, "username", "username_pos") or input("Username: ").strip()).strip()
    token = (_arg(args, "token", "token_pos") or input("Reset token: ").strip()).strip()
    new_password = getpass.getpass("New password (min 8 chars): ")
    confirm_password = getpass.getpass("Confirm new password: ")

    try:
        response = invoke(
            "recover-password",
            {
                "username": username,
                "token": token,
                "new_password": new_password,
                "confirm_password": confirm_password,
            },
            None,
        )
    except ClientError as exc:
        print(exc)
        raise SystemExit(1)
    _handle_response(response)


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
    name = args.name
    if name is None:
        name = _prompt_text("Household name: ")
    _remote_command("household.create", {"name": name})


def cmd_join_household(args) -> None:
    code = args.code or _prompt_text("Invite code: ")
    _remote_command("household.join", {"code": code})


def cmd_show_household(args) -> None:
    household_id = args.id if args.id is not None else _prompt_int("Household ID: ")
    _remote_command("household.show", {"id": household_id})


def cmd_rotate_invite(args) -> None:
    household_id = args.id if args.id is not None else _prompt_int("Household ID: ")
    _remote_command("household.rotate-invite", {"id": household_id})


def cmd_remove_member(args) -> None:
    household_id = args.id if args.id is not None else _prompt_int("Household ID: ")
    username = args.username or _prompt_text("Username to remove: ")
    _remote_command("household.remove-member", {"id": household_id, "username": username})


def cmd_list_households(args) -> None:
    _remote_command("household.list", {})


def cmd_promote_member(args) -> None:
    household_id = _arg(args, "id", "id_pos")
    username = _arg(args, "username", "username_pos")
    _remote_command("household.promote", {"id": household_id, "username": username})


def cmd_demote_member(args) -> None:
    household_id = _arg(args, "id", "id_pos")
    username = _arg(args, "username", "username_pos")
    _remote_command("household.demote", {"id": household_id, "username": username})


def cmd_send_invite(args) -> None:
    household_id = _arg(args, "id", "id_pos")
    email = _arg(args, "email", "email_pos") or input("Recipient (email or username): ").strip()
    _remote_command("household.send-invite", {"id": household_id, "email": email})


def cmd_create_chore(args) -> None:
    household_id = args.household if args.household is not None else _prompt_int("Household ID: ")
    title = args.title or _prompt_text("Chore title: ")
    description = args.description if args.description is not None else (_prompt_optional_text("Description (blank for none): ") or "")
    due = args.due if args.due is not None else _prompt_optional_text("Due date YYYY-MM-DD (blank for none): ")
    assign = args.assign if args.assign is not None else _prompt_assign_list("Assign to username (blank for none): ")
    _remote_command(
        "chore.create",
        {
            "household": household_id,
            "title": title,
            "description": description,
            "due": due,
            "assign": assign,
        },
    )


def cmd_assign_chore(args) -> None:
    chore_id = args.chore if args.chore is not None else _prompt_int("Chore ID: ")
    username = args.username or _prompt_text("Assign to username: ")
    _remote_command("chore.assign", {"chore": chore_id, "username": username})


def cmd_list_chores(args) -> None:
    household_id = args.household if args.household is not None else _prompt_int("Household ID: ")
    _remote_command(
        "chore.list",
        {
            "household": household_id,
            "status": args.status,
            "mine": args.mine,
            "overdue": args.overdue,
        },
    )


def cmd_show_chore(args) -> None:
    chore_id = args.chore if args.chore is not None else _prompt_int("Chore ID: ")
    _remote_command("chore.show", {"chore": chore_id})


def cmd_complete(args) -> None:
    chore_id = args.chore if args.chore is not None else _prompt_int("Chore ID: ")
    _remote_command("activity.complete", {"chore": chore_id})


def cmd_incomplete(args) -> None:
    chore_id = args.chore if args.chore is not None else _prompt_int("Chore ID: ")
    _remote_command("activity.incomplete", {"chore": chore_id})


def cmd_dispute(args) -> None:
    chore_id = args.chore if args.chore is not None else _prompt_int("Chore ID: ")
    reason = args.reason or _prompt_text("Reason for dispute: ")
    _remote_command("activity.dispute", {"chore": chore_id, "reason": reason})


def cmd_resolve(args) -> None:
    complaint_id = args.complaint if args.complaint is not None else _prompt_int("Complaint ID: ")
    outcome = args.outcome or _prompt_text("Outcome (uphold/dismiss): ")
    note = args.note or _prompt_text("Resolution note: ")
    _remote_command(
        "activity.resolve",
        {"complaint": complaint_id, "outcome": outcome, "note": note},
    )


def cmd_audit(args) -> None:
    household_id = args.household if args.household is not None else _prompt_int("Household ID: ")
    _remote_command("activity.audit", {"household": household_id})


def cmd_poll(args) -> None:
    _remote_command("activity.poll", {})


def cmd_reschedule_chore(args) -> None:
    chore_id = args.chore if args.chore is not None else _prompt_int("Chore ID: ")
    _remote_command(
        "chore.reschedule",
        {"chore": chore_id, "due": args.due or _prompt_text("New due date YYYY-MM-DD: ")},
    )


def register_subparsers(subparsers) -> None:
    p = subparsers.add_parser("register", help="Create a new user account")
    p.add_argument("--username", default=None, help="Desired username")
    p.set_defaults(func=cmd_register)

    p = subparsers.add_parser("login", help=f"Log in via server at {get_server_url()}")
    p.add_argument("--username", default=None, help="Your username")
    p.set_defaults(func=cmd_login)

    p = subparsers.add_parser("reset-password", help=f"Change your password via server at {get_server_url()}")
    p.add_argument("--username", default=None, help="Your username")
    p.set_defaults(func=cmd_reset_password)

    p = subparsers.add_parser(
        "forgot-password",
        help=f"Request a reset token via server at {get_server_url()}",
    )
    p.add_argument("username_pos", nargs="?", help="Your username")
    p.add_argument("--username", dest="username", default=None, help="Your username")
    p.set_defaults(username=None)
    p.set_defaults(func=cmd_forgot_password)

    p = subparsers.add_parser(
        "recover-password",
        help=f"Reset your password with a recovery token via server at {get_server_url()}",
    )
    p.add_argument("username_pos", nargs="?", help="Your username")
    p.add_argument("token_pos", nargs="?", help="One-time reset token")
    p.add_argument("--username", dest="username", default=None, help="Your username")
    p.add_argument("--token", dest="token", default=None, help="One-time reset token")
    p.set_defaults(username=None, token=None)
    p.set_defaults(func=cmd_recover_password)

    p = subparsers.add_parser("verify", help="Verify your email address with the code that was emailed")
    p.add_argument("code_pos", nargs="?", help="Verification code")
    p.add_argument("--code", dest="code", default=None)
    p.set_defaults(func=cmd_verify_email)

    p = subparsers.add_parser("resend-verification", help="Resend email verification code")
    p.add_argument("username_pos", nargs="?", help="Your username or email")
    p.add_argument("--username", dest="username", default=None)
    p.set_defaults(username=None)
    p.set_defaults(func=cmd_resend_verification)

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
    c.add_argument("--id", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.set_defaults(func=cmd_show_household)

    c = sub.add_parser("list", help="List your households")
    c.set_defaults(func=cmd_list_households)

    c = sub.add_parser("rotate-invite", help="Generate a new invite code (admin)")
    c.add_argument("--id", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.set_defaults(func=cmd_rotate_invite)

    c = sub.add_parser("remove-member", help="Remove a member (admin)")
    c.add_argument("--id", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.add_argument("--username", default=None)
    c.set_defaults(func=cmd_remove_member)

    c = sub.add_parser("promote", help="Promote a roommate to admin (admin only)")
    c.add_argument("id_pos", nargs="?", type=int, metavar="HOUSEHOLD_ID")
    c.add_argument("username_pos", nargs="?", help="Member username")
    c.add_argument("--id", dest="id", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.add_argument("--username", dest="username", default=None)
    c.set_defaults(id=None, username=None)
    c.set_defaults(func=cmd_promote_member)

    c = sub.add_parser("demote", help="Demote an admin to roommate (admin only)")
    c.add_argument("id_pos", nargs="?", type=int, metavar="HOUSEHOLD_ID")
    c.add_argument("username_pos", nargs="?", help="Member username")
    c.add_argument("--id", dest="id", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.add_argument("--username", dest="username", default=None)
    c.set_defaults(id=None, username=None)
    c.set_defaults(func=cmd_demote_member)

    c = sub.add_parser("send-invite", help="Email the invite code to a recipient (admin only)")
    c.add_argument("email_pos", nargs="?", metavar="EMAIL_OR_USERNAME")
    c.add_argument("--id", dest="id", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.add_argument("--email", dest="email", default=None, metavar="EMAIL_OR_USERNAME")
    c.set_defaults(id=None, email=None)
    c.set_defaults(func=cmd_send_invite)

    p = subparsers.add_parser("chore", help="Chore management commands")
    sub = p.add_subparsers(dest="chore_cmd", required=True)

    c = sub.add_parser("create", help="Create a chore (admin only)")
    c.add_argument("--household", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.add_argument("--title", default=None)
    c.add_argument("--description", default=None)
    c.add_argument("--due", default=None, metavar="YYYY-MM-DD")
    c.add_argument("--assign", action="append", default=None, metavar="USERNAME")
    c.set_defaults(func=cmd_create_chore)

    c = sub.add_parser("assign", help="Assign a chore to a member (admin only)")
    c.add_argument("--chore", type=int, default=None, metavar="CHORE_ID")
    c.add_argument("--username", default=None)
    c.set_defaults(func=cmd_assign_chore)

    c = sub.add_parser("list", help="List chores in a household")
    c.add_argument("--household", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.add_argument("--status", default=None, choices=["pending", "complete", "disputed"])
    c.add_argument("--mine", action="store_true", help="Only show chores assigned to you")
    c.add_argument("--overdue", action="store_true", help="Show overdue chores")
    c.set_defaults(func=cmd_list_chores)

    c = sub.add_parser("reschedule", help="Update a chore due date (admin only)")
    c.add_argument("--chore", type=int, default=None, metavar="CHORE_ID")
    c.add_argument("--due", default=None, metavar="YYYY-MM-DD")
    c.set_defaults(func=cmd_reschedule_chore)

    c = sub.add_parser("show", help="Show full details of a chore")
    c.add_argument("--chore", type=int, default=None, metavar="CHORE_ID")
    c.set_defaults(func=cmd_show_chore)

    p = subparsers.add_parser("activity", help="Completion, disputes, and audit log")
    sub = p.add_subparsers(dest="activity_cmd", required=True)

    c = sub.add_parser("complete", help="Mark a chore as complete")
    c.add_argument("--chore", type=int, default=None, metavar="CHORE_ID")
    c.set_defaults(func=cmd_complete)

    c = sub.add_parser("incomplete", help="Mark a chore as incomplete")
    c.add_argument("--chore", type=int, default=None, metavar="CHORE_ID")
    c.set_defaults(func=cmd_incomplete)

    c = sub.add_parser("dispute", help="Dispute a completed chore")
    c.add_argument("--chore", type=int, default=None, metavar="CHORE_ID")
    c.add_argument("--reason", default=None)
    c.set_defaults(func=cmd_dispute)

    c = sub.add_parser("resolve", help="Resolve a complaint (admin only)")
    c.add_argument("--complaint", type=int, default=None, metavar="COMPLAINT_ID")
    c.add_argument("--outcome", default=None, choices=["uphold", "dismiss"])
    c.add_argument("--note", default=None)
    c.set_defaults(func=cmd_resolve)

    c = sub.add_parser("audit", help="View audit log for a household")
    c.add_argument("--household", type=int, default=None, metavar="HOUSEHOLD_ID")
    c.set_defaults(func=cmd_audit)

    c = sub.add_parser("poll", help="View unread notifications")
    c.set_defaults(func=cmd_poll)

    p = subparsers.add_parser("create-household", help="Create a household with a flat command")
    p.add_argument("name", nargs="?", help="Household name")
    p.set_defaults(func=cmd_create_household)

    p = subparsers.add_parser("join-household", help="Join a household with a flat command")
    p.add_argument("code", nargs="?", help="Invite code")
    p.set_defaults(func=cmd_join_household)

    p = subparsers.add_parser("promote", help="Promote a roommate to admin")
    p.add_argument("username", metavar="USERNAME")
    p.set_defaults(id=None, func=cmd_promote_member)

    p = subparsers.add_parser("demote", help="Demote an admin to roommate")
    p.add_argument("username", metavar="USERNAME")
    p.set_defaults(id=None, func=cmd_demote_member)

    p = subparsers.add_parser("invite", aliases=["send-invite"], help="Email the invite code to a recipient (email or username)")
    p.add_argument("email_pos", nargs="?", metavar="EMAIL_OR_USERNAME")
    p.set_defaults(id=None, email=None)
    p.set_defaults(func=cmd_send_invite)

    p = subparsers.add_parser("create-chore", help="Create a chore with a flat command")
    p.add_argument("household", type=int, metavar="HOUSEHOLD_ID")
    p.add_argument("title", nargs="?", help="Chore title")
    p.add_argument("--description", default="")
    p.add_argument("--due", default=None, metavar="YYYY-MM-DD")
    p.add_argument("--assign", action="append", default=[], metavar="USERNAME")
    p.set_defaults(func=cmd_create_chore)

    p = subparsers.add_parser("complete", help="Complete a chore with a flat command")
    p.add_argument("chore", type=int, metavar="CHORE_ID")
    p.set_defaults(func=cmd_complete)

    p = subparsers.add_parser("incomplete", help="Mark a chore incomplete with a flat command")
    p.add_argument("chore", type=int, metavar="CHORE_ID")
    p.set_defaults(func=cmd_incomplete)

    p = subparsers.add_parser("audit", help="Audit a household with a flat command")
    p.add_argument("household", type=int, metavar="HOUSEHOLD_ID")
    p.set_defaults(func=cmd_audit)
