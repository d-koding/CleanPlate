"""
api_client.py — HTTP client helpers for the cleanplate CLI.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


DEFAULT_SERVER_URL = os.environ.get("CLEANPLATE_SERVER_URL", "http://127.0.0.1:8000")


class ClientError(RuntimeError):
    pass


def get_server_url() -> str:
    return os.environ.get("CLEANPLATE_SERVER_URL", DEFAULT_SERVER_URL).rstrip("/")


def invoke(action: str, args: dict, session: dict | None) -> dict:
    payload = json.dumps({"action": action, "args": args, "session": session}).encode("utf-8")
    req = urllib.request.Request(
        f"{get_server_url()}/command",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
            raise ClientError(body.get("error", f"Server returned HTTP {exc.code}")) from exc
        except json.JSONDecodeError:
            raise ClientError(f"Server returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ClientError(
            f"Could not reach CleanPlate server at {get_server_url()}. "
            "Start it with: python3 main.py serve"
        ) from exc
