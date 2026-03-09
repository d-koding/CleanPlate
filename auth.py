"""
auth.py — Identity & Access
Owner: Person 1

Responsibilities:
  - User registration and login
  - Password hashing (all crypto decisions live here)
  - Session management helpers

Standard library only: hashlib, hmac, secrets, getpass
"""

import getpass
import hashlib
import hmac
import secrets

from db import execute, query_one
from session import clear_session, load_session, require_session, save_session


# ---------------------------------------------------------------------------
# CRYPTO — Person 1 owns all decisions in this section
# ---------------------------------------------------------------------------

def _hash_password(plaintext: str) -> str:
    """
    Hash a password for storage.

    TODO (Person 1): Replace this stub with a proper algorithm.
    Options to research and pick from:
      - hashlib.scrypt  (built into Python 3.6+, memory-hard)
      - hashlib.pbkdf2_hmac  (simpler, still acceptable)
    For now this is a placeholder SHA-256 with a random salt so the
    rest of the system can be wired up and tested.

    Current stub:
      salt (32 random bytes) + SHA-256(salt + password)
      stored as "sha256:<hex_salt>:<hex_digest>"

    Replace the body of this function and _verify_password below
    before the prototype demo.
    """
    salt = secrets.token_bytes(32)
    digest = hashlib.sha256(salt + plaintext.encode()).hexdigest()
    return f"sha256:{salt.hex()}:{digest}"


def _verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored hash.
    Must stay in sync with _hash_password above.
    Uses hmac.compare_digest to prevent timing attacks.

    TODO (Person 1): Update this when you upgrade _hash_password.
    """
    try:
        scheme, salt_hex, digest_hex = stored_hash.split(":")
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    expected = hashlib.sha256(salt + plaintext.encode()).hexdigest()
    return hmac.compare_digest(expected, digest_hex)


# ---------------------------------------------------------------------------
# COMMANDS — registered in main.py
# ---------------------------------------------------------------------------

def cmd_register(args) -> None:
    """
    Register a new user account.
    Usage: python main.py register --username alice
    """
    username = args.username or input("Username: ").strip()
    if not username:
        print("Error: username cannot be empty.")
        return

    # TODO (Person 1): add any additional username validation rules here

    password = getpass.getpass("Password (min 8 chars): ")
    confirm  = getpass.getpass("Confirm password: ")

    if len(password) < 8:
        print("Error: password must be at least 8 characters.")
        return
    if password != confirm:
        print("Error: passwords do not match.")
        return

    existing = query_one("SELECT id FROM users WHERE username = ?", (username,))
    if existing:
        print(f"Error: username '{username}' is already taken.")
        return

    pw_hash = _hash_password(password)
    user_id = execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, pw_hash)
    )
    print(f"Account created for '{username}'. You can now log in.")


def cmd_login(args) -> None:
    """
    Log in to ChoreHouse. Saves session to ~/.chorehouse_session.
    Usage: python main.py login --username alice
    """
    username = args.username or input("Username: ").strip()
    password = getpass.getpass("Password: ")

    row = query_one("SELECT id, password_hash FROM users WHERE username = ?",
                    (username,))

    # Always run verify even if user not found, to resist timing attacks
    stored_hash = row["password_hash"] if row else "sha256:" + "0" * 64 + ":" + "0" * 64
    if row is None or not _verify_password(password, stored_hash):
        print("Error: invalid username or password.")
        return

    save_session(row["id"], username)
    print(f"Logged in as '{username}'.")


def cmd_logout(args) -> None:
    """
    Log out by removing the local session file.
    Usage: python main.py logout
    """
    session = load_session()
    if session:
        clear_session()
        print(f"Logged out '{session['username']}'.")
    else:
        print("No active session.")


def cmd_whoami(args) -> None:
    """
    Print the currently logged-in user.
    Usage: python main.py whoami
    """
    session = load_session()
    if session:
        print(f"Logged in as: {session['username']}  (user_id={session['user_id']})")
    else:
        print("Not logged in.")


# ---------------------------------------------------------------------------
# Subparser registration — called by main.py
# ---------------------------------------------------------------------------

def register_subparsers(subparsers) -> None:
    # register
    p = subparsers.add_parser("register", help="Create a new user account")
    p.add_argument("--username", default=None, help="Desired username")
    p.set_defaults(func=cmd_register)

    # login
    p = subparsers.add_parser("login", help="Log in to ChoreHouse")
    p.add_argument("--username", default=None, help="Your username")
    p.set_defaults(func=cmd_login)

    # logout
    p = subparsers.add_parser("logout", help="Log out")
    p.set_defaults(func=cmd_logout)

    # whoami
    p = subparsers.add_parser("whoami", help="Show who is currently logged in")
    p.set_defaults(func=cmd_whoami)
