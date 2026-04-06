"""
auth.py — Identity & Access
Owner: Dylan O'Connor

Responsibilities:
  - User registration and login
  - Password hashing (all crypto decisions live here)
  - Session management helpers

Standard library only: hashlib, hmac, secrets, getpass

Password strength checker follows these constraints:

blacklisted passwords from:
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt
https://github.com/danielmiessler/SecLists/tree/master/Passwords

minumum chars: 8

TODO:
Password reset / password recovery

Username should be HMAC

"""

import getpass
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from db import execute, query, query_one
from session import clear_session, load_session, save_session

def _load_wordlist(filename: str) -> frozenset[str]:
    """Load a newline-separated wordlist, strip blanks and comments."""
    path = Path(__file__).parent / "wordlists" / filename
    try:
        with path.open(encoding="utf-8", errors="ignore") as f:
            return frozenset(
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            )
    except FileNotFoundError:
        print(f"Warning: wordlist not found: {path}. Some password checks will be skipped.")
        return frozenset()

_COMPROMISED_PASSWORDS = _load_wordlist("10k-most-common.txt")
_DICTIONARY = _load_wordlist("common.txt")


# ---------------------------------------------------------------------------
# CRYPTO
# ---------------------------------------------------------------------------

def _get_or_create_username_hmac_key() -> bytes:
    """Return the server-side HMAC key used to blind usernames at rest."""
    row = query_one("SELECT key FROM username_key WHERE id = 1")
    if row is None:
        key_hex = secrets.token_hex(32)
        execute("INSERT INTO username_key (id, key) VALUES (1, ?)", (key_hex,))
        return bytes.fromhex(key_hex)
    return bytes.fromhex(row["key"])


def _normalize_username(username: str) -> str:
    return username.strip()


def _username_hmac(username: str) -> str:
    key = _get_or_create_username_hmac_key()
    normalized = _normalize_username(username).encode("utf-8", errors="replace")
    return hmac.new(key, normalized, hashlib.sha256).hexdigest()


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", errors="replace")).hexdigest()


def _migrate_legacy_username(row) -> None:
    if row is None:
        return

    display_name = row["display_name"] or row["username"]
    hashed_username = _username_hmac(display_name)
    if row["username"] == hashed_username and row["display_name"] == display_name:
        return

    execute(
        "UPDATE users SET username = ?, display_name = ? WHERE id = ?",
        (hashed_username, display_name, row["id"]),
    )


def _find_user_by_username(username: str):
    row = query_one(
        "SELECT id, username, display_name, password_hash FROM users WHERE username = ?",
        (_username_hmac(username),),
    )
    if row is not None:
        if row["display_name"] is None:
            _migrate_legacy_username(row)
            return query_one(
                "SELECT id, username, display_name, password_hash FROM users WHERE id = ?",
                (row["id"],),
            )
        return row

    legacy_row = query_one(
        """SELECT id, username, display_name, password_hash
           FROM users
           WHERE username = ? OR display_name = ?""",
        (username, username),
    )
    if legacy_row is not None:
        _migrate_legacy_username(legacy_row)
        return query_one(
            "SELECT id, username, display_name, password_hash FROM users WHERE id = ?",
            (legacy_row["id"],),
        )
    return None

def _hash_password(plaintext: str) -> str:
    """
    Hash a password using scrypt (memory-hard, built into Python 3.6+).

    Parameters chosen per OWASP scrypt recommendations:
      N=2^14 (CPU/memory cost), r=8 (block size), p=1 (parallelism)
    Salt: 32 random bytes via secrets.token_bytes (CSPRNG).
    Output: "scrypt:<hex_salt>:<hex_hash>"
    """
    salt = secrets.token_bytes(32)
    dk = hashlib.scrypt(
        plaintext.encode("utf-8", errors="replace"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32
    )
    return f"scrypt:{salt.hex()}:{dk.hex()}"


def _verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored scrypt hash.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    try:
        scheme, salt_hex, dk_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_dk = bytes.fromhex(dk_hex)
    except ValueError:
        return False

    if scheme != "scrypt":
        return False

    actual_dk = hashlib.scrypt(
        plaintext.encode("utf-8", errors="replace"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32
    )
    return hmac.compare_digest(actual_dk, expected_dk)

def _check_password_strength(password: str) -> list[str]:
    errors = []

    if len(password) < 8:
        errors.append("at least 8 characters")
    if len(password) > 64:
        errors.append("no more than 64 characters")

    if any(c for c in password if ord(c) < 32 or ord(c) == 127):
        errors.append("must not contain control characters")

    if password.lower() in _COMPROMISED_PASSWORDS:
        errors.append("password is too common or has appeared in known data breaches")

    if password.lower() in _DICTIONARY:
        errors.append("password is a dictionary word")

    if len(set(password)) < 3:
        errors.append("password is too repetitive")
    if _is_sequential(password):
        errors.append("password must not be a sequential pattern (e.g. 12345678, abcdefgh)")

    CONTEXT = {"clean", "chore", "house", "plate"}  # app name and obvious derivatives
    if any(word in password.lower() for word in CONTEXT):
        errors.append("password must not contain the application name or obvious derivatives")

    return errors


def _is_sequential(password: str) -> bool:
    """Detect monotonically incrementing/decrementing codepoint runs."""
    if len(password) < 4:
        return False
    codes = [ord(c) for c in password]
    diffs = [codes[i+1] - codes[i] for i in range(len(codes) - 1)]
    return all(d == 1 for d in diffs) or all(d == -1 for d in diffs)


def _validate_username(username: str | None) -> str | None:
    if username is None:
        username = input("Username: ").strip()
    username = username.strip()
    if not username:
        print("Error: username cannot be empty.")
        return None

    if len(username) < 3 or len(username) > 32:
        print("Error: username must be between 3 and 32 characters.")
        return None

    if not username.isalnum() and not all(c.isalnum() or c in "-_" for c in username):
        print("Error: username may only contain letters, numbers, hyphens, and underscores.")
        return None

    return username


# ---------------------------------------------------------------------------
# COMMANDS
# ---------------------------------------------------------------------------

def cmd_register(args) -> None:
    """
    Register a new user account.
    Usage: python main.py register --username alice
    """
    username = _validate_username(args.username)
    if username is None:
        return

    password = getattr(args, "password", None)
    if password is None:
        password = getpass.getpass("Password (min 8 chars): ")
    if not password:
        print("Error: password cannot be empty.")
        return

    recipe_errors = _check_password_strength(password)

    if recipe_errors:
        print("Error: ")
        for rule in recipe_errors:
            print(f"  • {rule}")
        return

    confirm = getattr(args, "confirm_password", None)
    if confirm is None:
        confirm = getpass.getpass("Confirm password: ")
    if not confirm:
        print("Error: password cannot be empty.")
        return

    if password != confirm:
        print("Error: passwords do not match.")
        return

    try:
        existing = _find_user_by_username(username)
    except Exception:
        print("Error: database unavailable.")
        return

    if existing:
        print(f"Error: username '{username}' is already taken.")
        return

    try:
        pw_hash = _hash_password(password)
        execute(
            "INSERT INTO users (username, display_name, password_hash) VALUES (?, ?, ?)",
            (_username_hmac(username), username, pw_hash)
        )
    except Exception:
        print("Error: could not create account. Please try again.")
        return

    print(f"Account created for '{username}'. You can now log in.")


def cmd_login(args) -> None:
    """
    Log in to CleanPlate. Saves session to ~/.cleanplate_session.
    Usage: python main.py login --username alice
    """
    username = args.username
    if username is None:
        username = input("Username: ").strip()
    username = _normalize_username(username)
    password = getattr(args, "password", None)
    if password is None:
        password = getpass.getpass("Password: ")
    if not password:
        print("Error: password cannot be empty.")
        return

    try:
        row = _find_user_by_username(username)
    except Exception:
        print("Error: database unavailable.")
        return

    # Always run verify even if user not found, to resist timing attacks.
    # Dummy hash has valid format so scrypt always runs.
    dummy = "scrypt:" + "00" * 32 + ":" + "00" * 32
    stored_hash = row["password_hash"] if row else dummy
    valid = _verify_password(password, stored_hash)

    if row is None or not valid:
        print("Error: invalid username or password.")
        return

    try:
        save_session(row["id"], row["display_name"])
    except Exception:
        print("Error: could not save session.")
        return

    print(f"Logged in as '{row['display_name']}'.")


def cmd_reset_password(args) -> None:
    """
    Reset a user's password after verifying their current password.
    Usage: python main.py reset-password --username alice
    """
    username = _validate_username(getattr(args, "username", None))
    if username is None:
        return

    current_password = getattr(args, "current_password", None)
    if current_password is None:
        current_password = getpass.getpass("Current password: ")
    if not current_password:
        print("Error: current password cannot be empty.")
        return

    try:
        row = _find_user_by_username(username)
    except Exception:
        print("Error: database unavailable.")
        return

    dummy = "scrypt:" + "00" * 32 + ":" + "00" * 32
    stored_hash = row["password_hash"] if row else dummy
    valid = _verify_password(current_password, stored_hash)

    if row is None or not valid:
        print("Error: invalid username or password.")
        return

    new_password = getattr(args, "new_password", None)
    if new_password is None:
        new_password = getpass.getpass("New password (min 8 chars): ")
    if not new_password:
        print("Error: new password cannot be empty.")
        return

    recipe_errors = _check_password_strength(new_password)
    if recipe_errors:
        print("Error: ")
        for rule in recipe_errors:
            print(f"  • {rule}")
        return

    if _verify_password(new_password, stored_hash):
        print("Error: new password must be different from the current password.")
        return

    confirm = getattr(args, "confirm_password", None)
    if confirm is None:
        confirm = getpass.getpass("Confirm new password: ")
    if not confirm:
        print("Error: new password confirmation cannot be empty.")
        return

    if new_password != confirm:
        print("Error: passwords do not match.")
        return

    try:
        execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (_hash_password(new_password), row["id"]),
        )
    except Exception:
        print("Error: could not update password. Please try again.")
        return

    print(f"Password updated for '{username}'.")


def cmd_forgot_password(args) -> None:
    """
    Issue a one-time password reset token for a user account.
    Usage: python main.py forgot-password --username alice
    """
    username = _validate_username(getattr(args, "username", None))
    if username is None:
        return

    try:
        row = _find_user_by_username(username)
    except Exception:
        print("Error: database unavailable.")
        return

    if row is None:
        print("If that account exists, a password reset token has been issued.")
        return

    token = secrets.token_urlsafe(24)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

    try:
        execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0",
            (row["id"],),
        )
        execute(
            """INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
               VALUES (?, ?, ?)""",
            (row["id"], _hash_reset_token(token), expires_at),
        )
    except Exception:
        print("Error: could not create reset token. Please try again.")
        return

    print("If that account exists, a password reset token has been issued.")
    print("Prototype mode: share this token directly with the user.")
    print(f"Reset token: {token}")
    print("This token expires in 15 minutes.")


def cmd_recover_password(args) -> None:
    """
    Reset a user's password using a one-time recovery token.
    Usage: python main.py recover-password --username alice --token <token>
    """
    username = _validate_username(getattr(args, "username", None))
    if username is None:
        return

    token = getattr(args, "token", None)
    if token is None:
        token = input("Reset token: ").strip()
    if not token:
        print("Error: reset token cannot be empty.")
        return

    try:
        row = _find_user_by_username(username)
    except Exception:
        print("Error: database unavailable.")
        return

    if row is None:
        print("Error: invalid username or reset token.")
        return

    token_row = query_one(
        """SELECT id, token_hash, expires_at
           FROM password_reset_tokens
           WHERE user_id = ? AND used = 0
           ORDER BY id DESC""",
        (row["id"],),
    )
    if token_row is None:
        print("Error: invalid username or reset token.")
        return

    try:
        expires_at = datetime.fromisoformat(token_row["expires_at"])
    except ValueError:
        print("Error: reset token is invalid. Request a new one.")
        return

    if expires_at <= datetime.now(timezone.utc):
        execute("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (token_row["id"],))
        print("Error: reset token has expired. Request a new one.")
        return

    if not hmac.compare_digest(token_row["token_hash"], _hash_reset_token(token)):
        print("Error: invalid username or reset token.")
        return

    new_password = getattr(args, "new_password", None)
    if new_password is None:
        new_password = getpass.getpass("New password (min 8 chars): ")
    if not new_password:
        print("Error: new password cannot be empty.")
        return

    recipe_errors = _check_password_strength(new_password)
    if recipe_errors:
        print("Error: ")
        for rule in recipe_errors:
            print(f"  • {rule}")
        return

    if _verify_password(new_password, row["password_hash"]):
        print("Error: new password must be different from the current password.")
        return

    confirm = getattr(args, "confirm_password", None)
    if confirm is None:
        confirm = getpass.getpass("Confirm new password: ")
    if not confirm:
        print("Error: new password confirmation cannot be empty.")
        return

    if new_password != confirm:
        print("Error: passwords do not match.")
        return

    try:
        execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (_hash_password(new_password), row["id"]),
        )
        execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0",
            (row["id"],),
        )
    except Exception:
        print("Error: could not update password. Please try again.")
        return

    print(f"Password recovered for '{username}'. You can now log in.")


def cmd_logout(args) -> None:
    """
    Log out by removing the local session file.
    Usage: python main.py logout
    """
    try:
        session = load_session()
        if session:
            clear_session()
            print(f"Logged out '{session['username']}'.")
        else:
            print("No active session.")
    except Exception:
        print("Error: could not read session.")


def cmd_whoami(args) -> None:
    """
    Print the currently logged-in user.
    Usage: python main.py whoami
    """
    try:
        session = load_session()
        if session:
            print(f"Logged in as: {session['username']}  (user_id={session['user_id']})")
            households = query(
                """SELECT h.id, h.name, m.role
                   FROM members m
                   JOIN households h ON h.id = m.household_id
                   WHERE m.user_id = ?
                   ORDER BY h.name, h.id""",
                (session["user_id"],),
            )
            if households:
                print("Households:")
                for household in households:
                    print(
                        f"  - {household['name']} (id={household['id']}, role={household['role']})"
                    )
            else:
                print("Households: none")
        else:
            print("Not logged in.")
    except Exception:
        print("Error: could not read session.")


# ---------------------------------------------------------------------------
# Subparser registration — called by main.py
# ---------------------------------------------------------------------------

def register_subparsers(subparsers) -> None:
    p = subparsers.add_parser("register", help="Create a new user account")
    p.add_argument("--username", default=None, help="Desired username")
    p.set_defaults(func=cmd_register)

    p = subparsers.add_parser("login", help="Log in to CleanPlate")
    p.add_argument("--username", default=None, help="Your username")
    p.set_defaults(func=cmd_login)

    p = subparsers.add_parser("reset-password", help="Change your password")
    p.add_argument("--username", default=None, help="Your username")
    p.set_defaults(func=cmd_reset_password)

    p = subparsers.add_parser("forgot-password", help="Request a one-time password reset token")
    p.add_argument("--username", default=None, help="Your username")
    p.set_defaults(func=cmd_forgot_password)

    p = subparsers.add_parser("recover-password", help="Reset password using a one-time token")
    p.add_argument("--username", default=None, help="Your username")
    p.add_argument("--token", default=None, help="One-time reset token")
    p.set_defaults(func=cmd_recover_password)

    p = subparsers.add_parser("logout", help="Log out")
    p.set_defaults(func=cmd_logout)

    p = subparsers.add_parser("whoami", help="Show who is currently logged in")
    p.set_defaults(func=cmd_whoami)
