"""
auth.py — Identity & Access
Owner: Dylan O'Connor

Responsibilities:
  - User registration and login
  - Password hashing (all crypto decisions live here)
  - Session management helpers

Dependencies: hashlib, hmac, secrets, getpass (stdlib); zxcvbn (third-party)

Password strength requirements:
  - minimum 8 characters
  - not in common/compromised password lists (SecLists 10k + common.txt)
  - zxcvbn score ≥ 2 out of 4 ("fair" or better)
  - interactive prompts loop and display zxcvbn feedback until the requirement is met

TODO:
Username should be HMAC

"""

import getpass
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import zxcvbn as _zxcvbn
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
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
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15


# ---------------------------------------------------------------------------
# CRYPTO
# ---------------------------------------------------------------------------

def _get_username_hmac_key() -> bytes:
    """
    Return the server-side username HMAC key from the environment.

    Supported variables:
      - CLEANPLATE_USERNAME_HMAC_KEY
      - USERNAME_HMAC_KEY

    If the value starts with ``hex:``, the remainder is parsed as hex bytes.
    Otherwise the raw UTF-8 bytes of the environment variable are used.
    """
    for env_name in ("CLEANPLATE_USERNAME_HMAC_KEY", "USERNAME_HMAC_KEY"):
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
        "Username HMAC key is not configured. Set CLEANPLATE_USERNAME_HMAC_KEY "
        "(or USERNAME_HMAC_KEY) before starting the server."
    )


def _normalize_username(username: str) -> str:
    return username.strip()


def _username_hmac(username: str) -> str:
    key = _get_username_hmac_key()
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
        """SELECT id, username, display_name, password_hash, email, email_verified,
                  failed_login_attempts, locked_until
           FROM users
           WHERE username = ?""",
        (_username_hmac(username),),
    )
    if row is not None:
        if row["display_name"] is None:
            _migrate_legacy_username(row)
            return query_one(
                """SELECT id, username, display_name, password_hash, email, email_verified,
                          failed_login_attempts, locked_until
                   FROM users
                   WHERE id = ?""",
                (row["id"],),
            )
        return row

    legacy_row = query_one(
        """SELECT id, username, display_name, password_hash, email, email_verified,
                  failed_login_attempts, locked_until
           FROM users
           WHERE username = ? OR display_name = ?""",
        (username, username),
    )
    if legacy_row is not None:
        _migrate_legacy_username(legacy_row)
        return query_one(
            """SELECT id, username, display_name, password_hash, email, email_verified,
                      failed_login_attempts, locked_until
               FROM users
               WHERE id = ?""",
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

_ZXCVBN_MIN_SCORE = 2  # 0-4; 2 = "somewhat guessable"
_SCORE_LABELS = ["very weak", "weak", "fair", "strong", "very strong"]


def _check_password_strength(password: str) -> tuple[list[str], list[str]]:
    """
    Returns (errors, suggestions).
    errors: hard failures — password must not be accepted.
    suggestions: human-readable hints from zxcvbn to guide the user.
    """
    errors: list[str] = []

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

    result = _zxcvbn.zxcvbn(password)
    score: int = result["score"]
    feedback = result["feedback"]
    suggestions: list[str] = list(feedback.get("suggestions", []))
    warning: str = feedback.get("warning", "")
    if warning and warning not in suggestions:
        suggestions.insert(0, warning)

    if score < _ZXCVBN_MIN_SCORE:
        label = _SCORE_LABELS[score]
        errors.append(
            f"password is too weak ({label}; aim for at least '{_SCORE_LABELS[_ZXCVBN_MIN_SCORE]}')"
        )

    return errors, suggestions


def _prompt_password_with_strength(prompt: str = "Password (min 8 chars): ") -> str | None:
    """
    Interactively prompt for a password, looping until strength requirements
    are met.  Prints zxcvbn feedback after each failed attempt.
    Returns the accepted password, or None if the user provides an empty input.
    """
    while True:
        password = getpass.getpass(prompt)
        if not password:
            print("Error: password cannot be empty.")
            return None
        errors, suggestions = _check_password_strength(password)
        if not errors:
            return password
        print("Password does not meet requirements:")
        for e in errors:
            print(f"  • {e}")
        if suggestions:
            print("Tips to strengthen your password:")
            for s in suggestions:
                print(f"  → {s}")
        print("Please try a different password.\n")


def _is_sequential(password: str) -> bool:
    """Detect monotonically incrementing/decrementing codepoint runs."""
    if len(password) < 4:
        return False
    codes = [ord(c) for c in password]
    diffs = [codes[i+1] - codes[i] for i in range(len(codes) - 1)]
    return all(d == 1 for d in diffs) or all(d == -1 for d in diffs)


def _validate_email(email: str) -> bool:
    """Basic structural check — not exhaustive, just catches obvious garbage."""
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


def _prompt_email(prompt: str = "Email address: ") -> str | None:
    """
    Interactively prompt for an email address, looping until a valid one is given.
    Returns the normalised email, or None if the user provides an empty input.
    """
    while True:
        email = input(prompt).strip().lower()
        if not email:
            print("Error: email cannot be empty.")
            return None
        if _validate_email(email):
            return email
        print(f"Error: '{email}' is not a valid email address. Please try again.")


def _send_email(recipient: str, subject: str, body: str) -> None:
    """
    Send an email via SMTP. Reads config from environment variables:
      CLEANPLATE_SMTP_HOST, CLEANPLATE_SMTP_PORT (default 587),
      CLEANPLATE_SMTP_USER, CLEANPLATE_SMTP_PASS
    """
    host = os.environ.get("CLEANPLATE_SMTP_HOST", "")
    port = int(os.environ.get("CLEANPLATE_SMTP_PORT", "587"))
    user = os.environ.get("CLEANPLATE_SMTP_USER", "")
    password = os.environ.get("CLEANPLATE_SMTP_PASS", "")

    if not host or not user:
        raise ValueError(
            "SMTP not configured. Set CLEANPLATE_SMTP_HOST, CLEANPLATE_SMTP_USER, "
            "and CLEANPLATE_SMTP_PASS environment variables."
        )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = recipient

    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls()
        if password:
            smtp.login(user, password)
        smtp.send_message(msg)


def _send_verification_email(email: str, code: str) -> None:
    body = (
        f"Welcome to CleanPlate!\n\n"
        f"Your verification code is:\n\n"
        f"    {code}\n\n"
        f"Enter it with:\n\n"
        f"    verify {code}\n\n"
        f"This code expires in 24 hours.\n"
    )
    _send_email(email, "Verify your CleanPlate account", body)


def _issue_verification_code(user_id: int) -> str:
    code = str(secrets.randbelow(900000) + 100000)  # 6-digit code
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    execute(
        """INSERT INTO email_verifications (user_id, code, expires_at)
           VALUES (?, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at""",
        (user_id, code, expires_at),
    )
    return code


def _find_user_by_email(email: str):
    return query_one(
        """SELECT id, username, display_name, password_hash, email, email_verified,
                  failed_login_attempts, locked_until
           FROM users
           WHERE email = ?""",
        (email.strip().lower(),),
    )


def _record_failed_login(user_id: int, attempts: int) -> None:
    if attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)).isoformat()
        execute(
            """UPDATE users
               SET failed_login_attempts = 0, locked_until = ?
               WHERE id = ?""",
            (locked_until, user_id),
        )
        return

    execute(
        """UPDATE users
           SET failed_login_attempts = ?, locked_until = NULL
           WHERE id = ?""",
        (attempts, user_id),
    )


def _clear_login_failures(user_id: int) -> None:
    execute(
        """UPDATE users
           SET failed_login_attempts = 0, locked_until = NULL
           WHERE id = ?""",
        (user_id,),
    )


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

    email = getattr(args, "email", None)
    if email is None:
        email = _prompt_email()
        if email is None:
            return
    else:
        email = email.strip().lower()
        if not email:
            print("Error: email cannot be empty.")
            return
        if not _validate_email(email):
            print("Error: invalid email address.")
            return

    password = getattr(args, "password", None)
    if password is None:
        password = _prompt_password_with_strength()
        if password is None:
            return
    else:
        if not password:
            print("Error: password cannot be empty.")
            return
        errors, suggestions = _check_password_strength(password)
        if errors:
            print("Password does not meet requirements:")
            for rule in errors:
                print(f"  • {rule}")
            if suggestions:
                print("Tips to strengthen your password:")
                for s in suggestions:
                    print(f"  → {s}")
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

    if _find_user_by_email(email):
        print(f"Error: an account with that email already exists.")
        raise SystemExit(1)

    try:
        pw_hash = _hash_password(password)
        user_id = execute(
            "INSERT INTO users (username, display_name, password_hash, email, email_verified) VALUES (?, ?, ?, ?, 0)",
            (_username_hmac(username), username, pw_hash, email)
        )
    except Exception:
        print("Error: could not create account. Please try again.")
        return

    try:
        code = _issue_verification_code(user_id)
        _send_verification_email(email, code)
        print(f"Account created for '{username}'.")
        print(f"A verification code has been sent to {email}.")
        print("Run:  verify <code>  to activate your account.")
    except Exception as e:
        print(f"Account created for '{username}', but could not send verification email: {e}")
        print("Contact your admin to manually verify your account.")


def cmd_login(args) -> None:
    """
    Log in to CleanPlate. Accepts username or email address.
    Usage: python main.py login --username alice
           python main.py login --username alice@example.com
    """
    username = args.username
    if username is None:
        username = input("Username or email: ").strip()
    username = username.strip()
    password = getattr(args, "password", None)
    if password is None:
        password = getpass.getpass("Password: ")
    if not password:
        print("Error: password cannot be empty.")
        return

    try:
        if "@" in username:
            row = _find_user_by_email(username)
        else:
            row = _find_user_by_username(_normalize_username(username))
    except Exception:
        print("Error: database unavailable.")
        return

    if row is not None and row["locked_until"]:
        try:
            locked_until = datetime.fromisoformat(row["locked_until"])
        except ValueError:
            locked_until = None
        if locked_until is not None and locked_until > datetime.now(timezone.utc):
            print(
                "Error: too many failed login attempts. "
                f"Try again after {locked_until.strftime('%Y-%m-%d %H:%M:%S UTC')}."
            )
            return
        _clear_login_failures(row["id"])
        row = _find_user_by_email(username) if "@" in username else _find_user_by_username(_normalize_username(username))

    # Always run verify even if user not found, to resist timing attacks.
    dummy = "scrypt:" + "00" * 32 + ":" + "00" * 32
    stored_hash = row["password_hash"] if row else dummy
    valid = _verify_password(password, stored_hash)

    if row is None or not valid:
        if row is not None:
            _record_failed_login(row["id"], row["failed_login_attempts"] + 1)
        print("Error: invalid username or password.")
        return

    if not row["email_verified"]:
        print("Error: your email address has not been verified.")
        print(f"Check {row['email']} for your verification code, then run:  verify <code>")
        raise SystemExit(1)

    try:
        _clear_login_failures(row["id"])
        save_session(row["id"], row["display_name"])
    except Exception:
        print("Error: could not save session.")
        return

    print(f"Logged in as '{row['display_name']}'.")


def cmd_verify_email(args) -> None:
    """
    Verify email address with the code that was emailed at registration.
    Usage: python main.py verify <code>
    """
    code = getattr(args, "code", None)
    if code is None:
        code = input("Verification code: ").strip()
    if not code:
        print("Error: code cannot be empty.")
        raise SystemExit(1)

    row = query_one(
        """SELECT ev.user_id, ev.expires_at, u.display_name
           FROM email_verifications ev
           JOIN users u ON u.id = ev.user_id
           WHERE ev.code = ?""",
        (code,),
    )
    if row is None:
        print("Error: invalid verification code.")
        raise SystemExit(1)

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        print("Error: verification code has expired. Run:  resend-verification  to get a new one.")
        raise SystemExit(1)

    execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["user_id"],))
    execute("DELETE FROM email_verifications WHERE user_id = ?", (row["user_id"],))

    print(f"Email verified. Welcome, {row['display_name']}! You can now log in.")


def cmd_resend_verification(args) -> None:
    """
    Resend the email verification code.
    Usage: python main.py resend-verification --username alice
    """
    username = getattr(args, "username", None)
    if username is None:
        username = input("Username or email: ").strip()
    username = username.strip()

    try:
        if "@" in username:
            row = _find_user_by_email(username)
        else:
            row = _find_user_by_username(_normalize_username(username))
    except Exception:
        print("Error: database unavailable.")
        return

    if row is None:
        print("Error: account not found.")
        return

    if row["email_verified"]:
        print("Your email is already verified.")
        return

    try:
        code = _issue_verification_code(row["id"])
        _send_verification_email(row["email"], code)
        print(f"Verification code resent to {row['email']}.")
    except Exception as e:
        print(f"Error: could not send email: {e}")


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
        new_password = _prompt_password_with_strength("New password (min 8 chars): ")
        if new_password is None:
            return
    else:
        if not new_password:
            print("Error: new password cannot be empty.")
            return
        errors, suggestions = _check_password_strength(new_password)
        if errors:
            print("Password does not meet requirements:")
            for rule in errors:
                print(f"  • {rule}")
            if suggestions:
                print("Tips to strengthen your password:")
                for s in suggestions:
                    print(f"  → {s}")
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

    email = row["email"]
    body = (
        f"Hi,\n\n"
        f"A password reset was requested for your CleanPlate account.\n\n"
        f"Your reset token is:\n\n"
        f"    {token}\n\n"
        f"Run this command to reset your password:\n\n"
        f"    recover-password {username} {token}\n\n"
        f"This token expires in 15 minutes. If you did not request this, ignore this email.\n"
    )
    try:
        _send_email(email, "CleanPlate password reset", body)
        print("If that account exists, a password reset token has been sent to the registered email.")
    except Exception:
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
        new_password = _prompt_password_with_strength("New password (min 8 chars): ")
        if new_password is None:
            return
    else:
        if not new_password:
            print("Error: new password cannot be empty.")
            return
        errors, suggestions = _check_password_strength(new_password)
        if errors:
            print("Password does not meet requirements:")
            for rule in errors:
                print(f"  • {rule}")
            if suggestions:
                print("Tips to strengthen your password:")
                for s in suggestions:
                    print(f"  → {s}")
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

    p = subparsers.add_parser("verify", help="Verify your email address")
    p.add_argument("code", nargs="?", help="Verification code from email")
    p.set_defaults(func=cmd_verify_email)

    p = subparsers.add_parser("resend-verification", help="Resend the email verification code")
    p.add_argument("--username", default=None, help="Your username or email")
    p.set_defaults(func=cmd_resend_verification)

    p = subparsers.add_parser("logout", help="Log out")
    p.set_defaults(func=cmd_logout)

    p = subparsers.add_parser("whoami", help="Show who is currently logged in")
    p.set_defaults(func=cmd_whoami)
