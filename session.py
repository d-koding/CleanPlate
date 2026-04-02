"""
session.py — Lightweight file-based session.

Stores the currently logged-in user_id and username in a small JSON file
in the user's home directory so login persists between commands.

"""

from contextlib import contextmanager
from contextvars import ContextVar
import json
import os

SESSION_PATH = os.path.join(os.path.expanduser("~"), ".cleanplate_session")
_MISSING = object()
_SESSION_OVERRIDE: ContextVar[object] = ContextVar("cleanplate_session_override", default=_MISSING)


@contextmanager
def session_scope(session_data: dict | None):
    """
    Temporarily override session reads/writes for the current request.

    The HTTP server uses this to keep session state request-scoped instead of
    writing a session file on the server host.
    """
    token = _SESSION_OVERRIDE.set(session_data)
    try:
        yield
    finally:
        _SESSION_OVERRIDE.reset(token)


def save_session(user_id: int, username: str) -> None:
    override = _SESSION_OVERRIDE.get()
    if override is not _MISSING:
        _SESSION_OVERRIDE.set({"user_id": user_id, "username": username})
        return
    try:
        with open(SESSION_PATH, "w") as f:
            json.dump({"user_id": user_id, "username": username}, f)
        os.chmod(SESSION_PATH, 0o600)   # readable only by the owning OS user
    except OSError as e:
        print(f"Error: could not save session ({e}).")
        raise SystemExit(1)


def load_session() -> dict | None:
    override = _SESSION_OVERRIDE.get()
    if override is not _MISSING:
        return override
    if not os.path.exists(SESSION_PATH):
        return None
    try:
        with open(SESSION_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def clear_session() -> None:
    override = _SESSION_OVERRIDE.get()
    if override is not _MISSING:
        _SESSION_OVERRIDE.set(None)
        return
    try:
        os.remove(SESSION_PATH)
    except FileNotFoundError:
        pass


def require_session() -> dict:
    """
    Return the current session or exit with an error.
    Call this at the top of any command that needs a logged-in user.
    """
    session = load_session()
    if session is None or "user_id" not in session or "username" not in session:
        print("Error: session is missing or corrupt. Run:  python main.py login")
        raise SystemExit(1)
    return session
