"""
main.py — cleanplate client CLI and server launcher.
"""

import argparse

from api_server import run_server
import client_cli


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

    client_cli.register_subparsers(subparsers)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
