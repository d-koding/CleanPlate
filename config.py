"""
config.py — shared project configuration loader.

Uses a repo-local INI file so client and server can share sensible defaults
without requiring repeated environment exports.
"""

from __future__ import annotations

import configparser
import os
from pathlib import Path


DEFAULT_ENV_PATH = Path(__file__).resolve().parent / ".env"
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "cleanplate.ini"


def load_env_file(path: Path | None = None) -> None:
    env_path = path or DEFAULT_ENV_PATH
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_env_file()


def get_config_path() -> Path:
    raw = os.environ.get("CLEANPLATE_CONFIG")
    if raw:
        return Path(raw).expanduser().resolve()
    return DEFAULT_CONFIG_PATH


def load_config() -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read(get_config_path())
    return parser


def get_option(section: str, option: str, fallback=None):
    parser = load_config()
    if not parser.has_section(section):
        return fallback
    return parser.get(section, option, fallback=fallback)


def get_bool(section: str, option: str, fallback: bool = False) -> bool:
    parser = load_config()
    if not parser.has_section(section):
        return fallback
    return parser.getboolean(section, option, fallback=fallback)


def get_int(section: str, option: str, fallback: int) -> int:
    parser = load_config()
    if not parser.has_section(section):
        return fallback
    return parser.getint(section, option, fallback=fallback)


def resolve_path(value: str | None) -> str | None:
    if not value:
        return None
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)
    return str((get_config_path().parent / path).resolve())
