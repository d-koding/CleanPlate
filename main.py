"""
main.py — cleanplate client CLI and server launcher.
"""

import argparse
import contextlib
import io
import shlex
import sys

from api_server import run_server
import client_cli
from config import get_bool, get_int, get_option, resolve_path


def _interactive_help() -> None:
    print("Interactive CleanPlate shell")
    print("Use the normal CleanPlate command structure inside the session.")
    print('Examples: login alice, household create "42 Elm Street"')
    print("Type 'help' to show CLI help, or 'exit'/'quit'/'q' to quit.")


def build_command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleanplate",
        description="Commands available inside the CleanPlate interactive shell",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    client_cli.register_subparsers(subparsers)
    return parser


def _normalize_interactive_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv

    command = argv[0]

    if command in {"register", "login", "reset-password"}:
        if len(argv) >= 2 and not argv[1].startswith("-"):
            return [command, "--username", argv[1], *argv[2:]]
        return argv

    if command == "create" and len(argv) >= 3:
        noun = argv[1]
        if noun == "household" and not argv[2].startswith("-"):
            return ["household", "create", "--name", argv[2], *argv[3:]]
        if noun == "chore" and not argv[2].startswith("-"):
            return ["chore", "create", "--title", argv[2], *argv[3:]]

    if len(argv) < 2:
        return argv

    group = argv[0]
    subcommand = argv[1]

    if group == "household":
        if subcommand == "create" and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--name", argv[2], *argv[3:]]
        if subcommand == "join" and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--code", argv[2], *argv[3:]]
        if subcommand == "leave" and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--household", argv[2], *argv[3:]]
        if subcommand in {"show", "rotate-invite"} and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--household", argv[2], *argv[3:]]
        if subcommand == "rename" and len(argv) >= 4 and not argv[2].startswith("-") and not argv[3].startswith("-"):
            return [group, subcommand, "--household", argv[2], "--name", argv[3], *argv[4:]]
        if subcommand == "remove-member" and len(argv) >= 4 and not argv[2].startswith("-") and not argv[3].startswith("-"):
            return [group, subcommand, "--household", argv[2], "--username", argv[3], *argv[4:]]
        if subcommand in {"promote", "demote"} and len(argv) >= 4 and not argv[2].startswith("-") and not argv[3].startswith("-"):
            return [group, subcommand, "--household", argv[2], "--username", argv[3], *argv[4:]]
        if subcommand == "send-invite" and len(argv) >= 4 and not argv[2].startswith("-") and not argv[3].startswith("-"):
            return [group, subcommand, "--household", argv[2], "--email", argv[3], *argv[4:]]

    if command in {"promote", "demote"} and len(argv) >= 2 and not argv[1].startswith("-"):
        return [command, "--username", argv[1], *argv[2:]]

    if group == "chore":
        if subcommand == "create" and len(argv) >= 4 and not argv[2].startswith("-") and not argv[3].startswith("-"):
            return [group, subcommand, "--household", argv[2], "--title", argv[3], *argv[4:]]
        if subcommand == "assign" and len(argv) >= 4 and not argv[2].startswith("-") and not argv[3].startswith("-"):
            return [group, subcommand, "--chore", argv[2], "--username", argv[3], *argv[4:]]
        if subcommand == "list" and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--household", argv[2], *argv[3:]]
        if subcommand in {"show", "reschedule"} and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--chore", argv[2], *argv[3:]]

    if group == "activity":
        if subcommand in {"complete", "incomplete", "dispute"} and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--chore", argv[2], *argv[3:]]
        if subcommand == "resolve" and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--complaint", argv[2], *argv[3:]]
        if subcommand == "audit" and len(argv) >= 3 and not argv[2].startswith("-"):
            return [group, subcommand, "--household", argv[2], *argv[3:]]

    return argv


def _run_interactive_shell(parser: argparse.ArgumentParser | None = None) -> None:
    if parser is None:
        parser = build_command_parser()
    _interactive_help()

    while True:
        try:
            line = input("cleanplate> ").strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        if not line:
            continue
        if line.lower() in {"exit", "quit", "q"}:
            break
        if line.lower() == "help":
            parser.print_help()
            continue

        try:
            argv = shlex.split(line)
        except ValueError as exc:
            print(f"Error: {exc}")
            continue
        argv = _normalize_interactive_argv(argv)

        try:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                args = parser.parse_args(argv)
            args.func(args)
        except SystemExit:
            error_output = stderr.getvalue().strip() if "stderr" in locals() else ""
            if error_output:
                print(error_output)
            # Keep the shell alive after command validation or handler failures.
            continue
        except KeyboardInterrupt:
            print()
            continue


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleanplate",
        description="cleanplate — launcher for the Secure Roommate Chore Coordinator",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the CleanPlate API server")
    serve.add_argument("--host", default=get_option("server", "host", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=get_int("server", "port", 8443))
    serve.add_argument(
        "--tls-cert",
        default=resolve_path(get_option("server", "tls_cert", None)),
        help="Path to the server X.509 certificate (PEM)",
    )
    serve.add_argument(
        "--tls-key",
        default=resolve_path(get_option("server", "tls_key", None)),
        help="Path to the server private key (PEM)",
    )
    serve.add_argument(
        "--insecure-http",
        action="store_true",
        help="Allow plaintext HTTP for local-only development",
    )
    serve.set_defaults(insecure_http=get_bool("server", "allow_insecure_http", False))
    serve.set_defaults(
        func=lambda args: run_server(
            args.host,
            args.port,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
            allow_insecure_http=args.insecure_http,
        )
    )

    shell = subparsers.add_parser("interactive", help="Start an interactive CleanPlate command session")
    shell.set_defaults(func=lambda args: _run_interactive_shell(build_command_parser()))

    leave = subparsers.add_parser("leave-household", help="Leave a household with a flat command")
    leave.add_argument("household", help="Household name")
    leave.set_defaults(func=client_cli.cmd_leave_household)

    promote = subparsers.add_parser("promote", help="Promote a roommate to admin")
    promote.add_argument("username", help="Username to promote")
    promote.add_argument("--household", required=True, help="Household name")
    promote.set_defaults(func=client_cli.cmd_promote_member)

    demote = subparsers.add_parser("demote", help="Demote an admin to roommate")
    demote.add_argument("username", help="Username to demote")
    demote.add_argument("--household", required=True, help="Household name")
    demote.set_defaults(func=client_cli.cmd_demote_member)

    poll = subparsers.add_parser("poll", aliases=["notifications"], help="View unread notifications")
    poll.set_defaults(func=client_cli.cmd_poll)

    return parser


def main() -> None:
    if len(sys.argv) == 1:
        _run_interactive_shell(build_command_parser())
        return
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
