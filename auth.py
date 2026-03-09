"""
auth.py — Identity & Access
Owner: Dylan O'Connor

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
from pathlib import Path
from db import execute, query_one
from session import clear_session, load_session, require_session, save_session

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
        raise RuntimeError(f"Required wordlist not found: {path}")

_COMPROMISED_PASSWORDS = _load_wordlist("top10k_passwords.txt")


# ---------------------------------------------------------------------------
# CRYPTO
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

    DICTIONARY = {"dragon", "sunshine", "letmein", "monkey"}  # stub — replace with wordlist file
    if password.lower() in DICTIONARY:
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

    recipe_errors = _check_password_strength(password)
    if password != confirm:
        print("Error: passwords do not match.")
        return
    
    if recipe_errors:
        print("Error: password must contain:")
        for rule in recipe_errors:
            print(f"  • {rule}")
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