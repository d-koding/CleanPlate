"""
main.py — cleanplate client CLI and server launcher.
"""

from dotenv import load_dotenv
load_dotenv()

import argparse
import contextlib
import io
import shlex
import sys

from api_server import run_server
import client_cli


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
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=lambda args: run_server(args.host, args.port))

    shell = subparsers.add_parser("interactive", help="Start an interactive CleanPlate command session")
    shell.set_defaults(func=lambda args: _run_interactive_shell(build_command_parser()))

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
