"""
main.py — cleanplate client CLI and server launcher.
"""

import argparse
import contextlib
import io
import shlex

from api_server import run_server
import client_cli


def _interactive_help() -> None:
    print("Interactive CleanPlate shell")
    print("Type a command like: login alice")
    print("Type 'help' to show CLI help, or 'exit'/'quit'/'q' to quit.")


def _run_interactive_shell(parser: argparse.ArgumentParser) -> None:
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
        description="cleanplate — client CLI for the Secure Roommate Chore Coordinator",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the CleanPlate API server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=lambda args: run_server(args.host, args.port))

    shell = subparsers.add_parser(
        "interactive",
        aliases=["shell", "repl"],
        help="Start an interactive CleanPlate command session",
    )
    shell.set_defaults(func=lambda args, parser=parser: _run_interactive_shell(parser))

    client_cli.register_subparsers(subparsers)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
