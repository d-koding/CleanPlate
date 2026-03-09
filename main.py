"""
main.py — ChoreHouse CLI entry point
Standard library only: argparse

Run any command with --help to see usage, e.g.:
    python main.py --help
    python main.py login --help
    python main.py chore list --help

Ownership map:
    auth.py       → Person 1  (login, register, logout, whoami)
    households.py → Person 2  (household create/join/show/list/...)
    chores.py     → Person 3  (chore create/assign/list/show)
    activity.py   → Person 4  (activity complete/dispute/resolve/audit)
"""

import argparse

from db import init_db
import auth
import households
import chores
import activity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chorehouse",
        description="ChoreHouse — Secure roommate chore coordinator",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    auth.register_subparsers(subparsers)        # Person 1
    households.register_subparsers(subparsers)  # Person 2
    chores.register_subparsers(subparsers)      # Person 3
    activity.register_subparsers(subparsers)    # Person 4

    return parser


def main() -> None:
    init_db()   # create tables on first run; no-op after that
    parser = build_parser()
    args   = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
