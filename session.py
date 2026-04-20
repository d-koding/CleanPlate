"""
session.py — Lightweight file-based session.

Stores the currently logged-in user_id and username in a small JSON file
in the user's home directory so login persists between commands.

"""

from contextlib import contextmanager
from contextvars import ContextVar
import base64
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone


SESSION_TTL_HOURS = 12
SESSION_PATH: str | None = None
_MISSING = object()
_SESSION_OVERRIDE: ContextVar[object] = ContextVar("cleanplate_session_override", default=_MISSING)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - (len(data) % 4)) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def _get_session_signing_key() -> bytes:
    for env_name in ("CLEANPLATE_SESSION_HMAC_KEY", "SESSION_HMAC_KEY"):
        value = os.environ.get(env_name)
        if not value:
            continue
        if value.startswith("hex:"):
            try:
                return bytes.fromhex(value[4:])
            except ValueError as exc:
                raise RuntimeError(f"{env_name} must contain valid hex after 'hex:'") from exc
        return value.encode("utf-8", errors="strict")

    raise RuntimeError(
        "Session signing key is not configured. Set CLEANPLATE_SESSION_HMAC_KEY "
        "(or SESSION_HMAC_KEY) before starting the server."
    )


def _issue_session_token(user_id: int, username: str, expires_at: str) -> str:
    key = _get_session_signing_key()
    payload_obj = {"user_id": user_id, "username": username, "expires_at": expires_at}
    payload = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(key, payload, hashlib.sha256).digest()
    return f"{_b64url_encode(payload)}.{_b64url_encode(signature)}"


def _verify_session_token(token: str) -> dict | None:
    if not token or "." not in token:
        return None
    try:
        payload_b64, signature_b64 = token.split(".", 1)
        payload = _b64url_decode(payload_b64)
        signature = _b64url_decode(signature_b64)
    except Exception:
        return None

    try:
        key = _get_session_signing_key()
    except RuntimeError:
        return None

    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        session = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(session, dict):
        return None
    if "user_id" not in session or "username" not in session or "expires_at" not in session:
        return None

    try:
        expiry = datetime.fromisoformat(session["expires_at"])
    except ValueError:
        return None
    if expiry <= datetime.now(timezone.utc):
        return None

    session["session_token"] = token
    return session


@contextmanager
def session_scope(session_data: dict | None):
    """
    Temporarily override session reads/writes for the current request.

    The HTTP server uses this to keep session state request-scoped instead of
    writing a session file on the server host.
    """
    trusted_session = None
    if isinstance(session_data, dict):
        trusted_session = _verify_session_token(session_data.get("session_token", ""))
    token = _SESSION_OVERRIDE.set(trusted_session)
    try:
        yield
    finally:
        _SESSION_OVERRIDE.reset(token)


def _slugify_terminal_name(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    return slug or "default"


def get_session_path() -> str:
    """
    Resolve the local session file path.

    Priority:
      1. Explicit SESSION_PATH override (used by tests)
      2. CLEANPLATE_SESSION_PATH env var
      3. CLEANPLATE_SESSION_NAME env var
      4. Current terminal device name, when available
      5. Legacy shared ~/.cleanplate_session fallback
    """
    if SESSION_PATH:
        return SESSION_PATH

    explicit_path = os.environ.get("CLEANPLATE_SESSION_PATH")
    if explicit_path:
        return os.path.expanduser(explicit_path)

    session_name = os.environ.get("CLEANPLATE_SESSION_NAME")
    if session_name:
        slug = _slugify_terminal_name(session_name)
        return os.path.join(os.path.expanduser("~"), f".cleanplate_session_{slug}")

    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            if stream is None:
                continue
            fd = stream.fileno()
            if os.isatty(fd):
                tty_name = os.ttyname(fd)
                slug = _slugify_terminal_name(os.path.basename(tty_name))
                return os.path.join(os.path.expanduser("~"), f".cleanplate_session_{slug}")
        except (AttributeError, OSError, ValueError):
            continue

    return os.path.join(os.path.expanduser("~"), ".cleanplate_session")


def save_session(user_id: int, username: str, session_token: str | None = None) -> None:
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    if session_token is None:
        session_token = _issue_session_token(user_id, username, expires_at)

    override = _SESSION_OVERRIDE.get()
    if override is not _MISSING:
        _SESSION_OVERRIDE.set(
            {
                "user_id": user_id,
                "username": username,
                "expires_at": expires_at,
                "session_token": session_token,
            }
        )
        return

    path = get_session_path()
    try:
        with open(path, "w") as f:
            json.dump(
                {
                    "user_id": user_id,
                    "username": username,
                    "expires_at": expires_at,
                    "session_token": session_token,
                },
                f,
            )
        os.chmod(path, 0o600)
    except OSError as e:
        print(f"Error: could not save session ({e}).")
        raise SystemExit(1)



def load_session() -> dict | None:
    override = _SESSION_OVERRIDE.get()
    if override is not _MISSING:
        session = override
    else:
        path = get_session_path()
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                session = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    if session is None:
        return None

    expires_at = session.get("expires_at")
    if not expires_at:
        return session

    try:
        expiry = datetime.fromisoformat(expires_at)
    except ValueError:
        return None

    if expiry <= datetime.now(timezone.utc):
        clear_session()
        return None

    if "session_token" not in session:
        clear_session()
        return None

    return session



def clear_session() -> None:
    override = _SESSION_OVERRIDE.get()
    if override is not _MISSING:
        _SESSION_OVERRIDE.set(None)
        return
    path = get_session_path()
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def require_session() -> dict:
    session = load_session()
    if session is None or "user_id" not in session or "username" not in session or "session_token" not in session:
        print("Error: session is missing, expired, or corrupt. Run:  python main.py login")
        raise SystemExit(1)
    return session
