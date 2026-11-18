"""Authentication storage and session helpers for the activities API."""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generator

SESSION_TTL_SECONDS = 8 * 60 * 60
PASSWORD_ITERATIONS = 600_000
SESSION_COOKIE_NAME = "school_session"
_DUMMY_SALT = bytes.fromhex("9d" * 16)
_DUMMY_PASSWORD_HASH = hashlib.pbkdf2_hmac(
    "sha256", b"invalid-password", _DUMMY_SALT, PASSWORD_ITERATIONS
)


@dataclass(frozen=True)
class User:
    email: str
    name: str
    grade: str | None
    role: str

    def public_data(self) -> dict[str, str | None]:
        return {
            "email": self.email,
            "name": self.name,
            "grade": self.grade,
            "role": self.role,
        }


def _database_path() -> Path:
    configured_path = os.environ.get("USERS_DB_PATH")
    return Path(configured_path) if configured_path else Path(__file__).with_name(
        "users.sqlite"
    )


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 254 or normalized.count("@") != 1:
        raise ValueError("Enter a valid email address")
    local, domain = normalized.split("@")
    if not local or not domain or "." not in domain:
        raise ValueError("Enter a valid email address")
    return normalized


def _connect() -> sqlite3.Connection:
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    os.chmod(path, 0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connection() -> Generator[sqlite3.Connection, None, None]:
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return salt.hex(), password_hash.hex()


def initialize_auth_store() -> None:
    with _connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                grade TEXT,
                role TEXT NOT NULL CHECK (role IN ('student', 'admin')),
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
            """
        )

        admin_email = os.environ.get("ADMIN_EMAIL")
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if bool(admin_email) != bool(admin_password):
            raise RuntimeError(
                "Set both ADMIN_EMAIL and ADMIN_PASSWORD to configure an admin account"
            )
        if admin_email and admin_password:
            normalized_email = normalize_email(admin_email)
            salt, password_hash = _hash_password(admin_password)
            connection.execute(
                """
                INSERT INTO users (email, name, grade, role, password_salt, password_hash)
                VALUES (?, ?, NULL, 'admin', ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    name = excluded.name,
                    grade = NULL,
                    role = 'admin',
                    password_salt = excluded.password_salt,
                    password_hash = excluded.password_hash
                """,
                (normalized_email, "Administrator", salt, password_hash),
            )


def _user_from_row(row: sqlite3.Row) -> User:
    return User(
        email=row["email"],
        name=row["name"],
        grade=row["grade"],
        role=row["role"],
    )


def create_student_account(email: str, password: str, name: str, grade: str) -> User:
    normalized_email = normalize_email(email)
    name = name.strip()
    grade = grade.strip()
    if not name or len(name) > 120:
        raise ValueError("Name must contain between 1 and 120 characters")
    if not grade or len(grade) > 40:
        raise ValueError("Grade must contain between 1 and 40 characters")
    salt, password_hash = _hash_password(password)

    with _connection() as connection:
        try:
            connection.execute(
                """
                INSERT INTO users (email, name, grade, role, password_salt, password_hash)
                VALUES (?, ?, ?, 'student', ?, ?)
                """,
                (normalized_email, name, grade, salt, password_hash),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("An account with this email already exists") from error
        row = connection.execute(
            "SELECT email, name, grade, role FROM users WHERE email = ?",
            (normalized_email,),
        ).fetchone()
    if row is None:
        raise RuntimeError("Student account could not be loaded after registration")
    return _user_from_row(row)


def authenticate_user(email: str, password: str) -> User | None:
    try:
        normalized_email = normalize_email(email)
    except ValueError:
        normalized_email = ""

    with _connection() as connection:
        row = connection.execute(
            """
            SELECT email, name, grade, role, password_salt, password_hash
            FROM users WHERE email = ?
            """,
            (normalized_email,),
        ).fetchone()

    salt = bytes.fromhex(row["password_salt"]) if row else _DUMMY_SALT
    expected_hash = (
        bytes.fromhex(row["password_hash"]) if row else _DUMMY_PASSWORD_HASH
    )
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    if row is None or not hmac.compare_digest(actual_hash, expected_hash):
        return None
    return _user_from_row(row)


def get_student_account(email: str) -> User | None:
    normalized_email = normalize_email(email)
    with _connection() as connection:
        row = connection.execute(
            "SELECT email, name, grade, role FROM users WHERE email = ? AND role = 'student'",
            (normalized_email,),
        ).fetchone()
    return _user_from_row(row) if row else None


def create_session(user: User) -> tuple[str, int]:
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with _connection() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
        connection.execute(
            "INSERT INTO sessions (token_hash, email, expires_at) VALUES (?, ?, ?)",
            (token_hash, user.email, expires_at),
        )
    return token, expires_at


def get_user_for_session(token: str | None) -> User | None:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with _connection() as connection:
        row = connection.execute(
            """
            SELECT users.email, users.name, users.grade, users.role, sessions.expires_at
            FROM sessions JOIN users ON users.email = sessions.email
            WHERE sessions.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] <= now:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            return None
    return _user_from_row(row)


def delete_session(token: str | None) -> None:
    if not token:
        return
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _connection() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


initialize_auth_store()
