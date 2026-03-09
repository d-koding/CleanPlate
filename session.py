"""
session.py — Lightweight file-based session.

Stores the currently logged-in user_id and username in a small JSON file
in the user's home directory so login persists between commands.

Owned by: Person 1 (Identity & Access)
"""

import json
import os

SESSION_PATH = os.path.join(os.path.expanduser("~"), ".chorehouse_session")


def save_session(user_id: int, username: str) -> None:
    with open(SESSION_PATH, "w") as f:
        json.dump({"user_id": user_id, "username": username}, f)
    os.chmod(SESSION_PATH, 0o600)   # readable only by the owning OS user


def load_session() -> dict | None:
    if not os.path.exists(SESSION_PATH):
        return None
    with open(SESSION_PATH) as f:
        return json.load(f)


def clear_session() -> None:
    if os.path.exists(SESSION_PATH):
        os.remove(SESSION_PATH)


def require_session() -> dict:
    """
    Return the current session or exit with an error.
    Call this at the top of any command that needs a logged-in user.
    """
    session = load_session()
    if session is None:
        print("Error: you are not logged in. Run:  python main.py login")
        raise SystemExit(1)
    return session
