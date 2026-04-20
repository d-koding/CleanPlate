"""
api_client.py — HTTP client helpers for the cleanplate CLI.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlparse

from config import get_bool, get_option, resolve_path


class ClientError(RuntimeError):
    pass


def _format_cert_verification_error(exc: ssl.SSLCertVerificationError) -> str:
    return getattr(exc, "verify_message", None) or str(exc)


def _default_server_url() -> str:
    return get_option("client", "server_url", "https://127.0.0.1:8443")


def _default_ca_cert_path() -> str | None:
    return resolve_path(get_option("client", "ca_cert", None))


def _allow_insecure_http() -> bool:
    return get_bool("client", "allow_insecure_http", False)


def get_server_url() -> str:
    return os.environ.get("CLEANPLATE_SERVER_URL", _default_server_url()).rstrip("/")


def _build_ssl_context(server_url: str) -> ssl.SSLContext | None:
    parsed = urlparse(server_url)
    if parsed.scheme != "https":
        return None

    cafile = os.environ.get("CLEANPLATE_CA_CERT", _default_ca_cert_path())
    context = ssl.create_default_context(cafile=cafile)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    if hasattr(context, "set_alpn_protocols"):
        context.set_alpn_protocols(["http/1.1"])
    if hasattr(ssl, "OP_NO_COMPRESSION") and hasattr(context, "options"):
        context.options |= ssl.OP_NO_COMPRESSION
    return context


def invoke(action: str, args: dict, session: dict | None) -> dict:
    server_url = get_server_url()
    parsed = urlparse(server_url)
    allow_insecure_http = os.environ.get("CLEANPLATE_ALLOW_INSECURE_HTTP", "").lower() in {"1", "true", "yes"}
    if parsed.scheme != "https" and not (allow_insecure_http or _allow_insecure_http()):
        raise ClientError(
            "Refusing insecure HTTP transport. Use an https:// CLEANPLATE_SERVER_URL "
            "or set CLEANPLATE_ALLOW_INSECURE_HTTP=1 for local-only development."
        )
    payload = json.dumps({"action": action, "args": args, "session": session}).encode("utf-8")
    req = urllib.request.Request(
        f"{server_url}/command",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    ssl_context = _build_ssl_context(server_url)
    try:
        with urllib.request.urlopen(req, context=ssl_context) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
            raise ClientError(body.get("error", f"Server returned HTTP {exc.code}")) from exc
        except json.JSONDecodeError:
            raise ClientError(f"Server returned HTTP {exc.code}") from exc
    except ssl.SSLCertVerificationError as exc:
        raise ClientError(
            f"TLS certificate validation failed for {server_url}: {_format_cert_verification_error(exc)}"
        ) from exc
    except ssl.SSLError as exc:
        raise ClientError(f"TLS error while connecting to {server_url}: {exc}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise ClientError(
                f"TLS certificate validation failed for {server_url}: {_format_cert_verification_error(reason)}"
            ) from exc
        if isinstance(reason, ssl.SSLError):
            raise ClientError(f"TLS error while connecting to {server_url}: {reason}") from exc
        raise ClientError(
            f"Could not reach CleanPlate server at {server_url}. "
            "Start it with: python3 main.py serve"
        ) from exc
