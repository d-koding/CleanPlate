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
    Hash a password using scrypt (memory-hard, built into Python 3.6+).

    Parameters chosen per OWASP scrypt recommendations:
      N=2^14 (CPU/memory cost), r=8 (block size), p=1 (parallelism)
    Salt: 32 random bytes via secrets.token_bytes (CSPRNG).
    Output: "scrypt:<hex_salt>:<hex_hash>"

    scrypt is preferred over PBKDF2 because its memory-hardness
    resists GPU/ASIC brute-force attacks.
    """
    salt = secrets.token_bytes(32)
    dk = hashlib.scrypt(
        plaintext.encode(),
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
    except ValueError:
        return False

    if scheme != "scrypt":
        return False

    salt = bytes.fromhex(salt_hex)
    expected_dk = bytes.fromhex(dk_hex)

    actual_dk = hashlib.scrypt(
        plaintext.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32
    )
    return hmac.compare_digest(actual_dk, expected_dk)


# ---------------------------------------------------------------------------
# COMMANDS
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

    if len(username) < 3 or len(username) > 32:
        print("Error: username must be between 3 and 32 characters.")
        return

    if not username.isalnum() and not all(c.isalnum() or c in "-_" for c in username):
        print("Error: username may only contain letters, numbers, hyphens, and underscores.")
        return

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
    execute(
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

    # Always run verify even if user not found, to resist timing attacks.
    # Dummy hash has valid format so scrypt always runs.
    dummy = "scrypt:" + "00" * 32 + ":" + "00" * 32
    stored_hash = row["password_hash"] if row else dummy
    valid = _verify_password(password, stored_hash)

    if row is None or not valid:
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
    p = subparsers.add_parser("register", help="Create a new user account")
    p.add_argument("--username", default=None, help="Desired username")
    p.set_defaults(func=cmd_register)

    p = subparsers.add_parser("login", help="Log in to ChoreHouse")
    p.add_argument("--username", default=None, help="Your username")
    p.set_defaults(func=cmd_login)

    p = subparsers.add_parser("logout", help="Log out")
    p.set_defaults(func=cmd_logout)

    p = subparsers.add_parser("whoami", help="Show who is currently logged in")
    p.set_defaults(func=cmd_whoami)