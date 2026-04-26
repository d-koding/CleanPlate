"""
api_server.py — thin HTTP transport for cleanplate server-side commands.

The existing feature modules remain the source of truth for business logic.
This module exposes them over HTTP so the CLI can act as a client.
"""

from __future__ import annotations

import errno
import json
import os
import ssl
from argparse import Namespace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import activity
import auth
import chores
import households
from config import get_bool, get_int, get_option, resolve_path
from db import init_db
from output_capture import capture_stdout
from session import load_session, session_scope


COMMANDS = {
    "register": auth.cmd_register,
    "login": auth.cmd_login,
    "verify": auth.cmd_verify_email,
    "resend-verification": auth.cmd_resend_verification,
    "reset-password": auth.cmd_reset_password,
    "forgot-password": auth.cmd_forgot_password,
    "recover-password": auth.cmd_recover_password,
    "whoami": auth.cmd_whoami,
    "logout": auth.cmd_logout,
    "household.create": households.cmd_create_household,
    "household.join": households.cmd_join_household,
    "household.show": households.cmd_show_household,
    "household.list": households.cmd_list_households,
    "household.leave": households.cmd_leave_household,
    "household.rotate-invite": households.cmd_rotate_invite,
    "household.rename": households.cmd_rename_household,
    "chore.reschedule": chores.cmd_reschedule_chore,
    "household.remove-member": households.cmd_remove_member,
    "household.promote": households.cmd_promote_member,
    "household.demote": households.cmd_demote_member,
    "household.send-invite": households.cmd_send_invite,
    "chore.create": chores.cmd_create_chore,
    "chore.assign": chores.cmd_assign_chore,
    "chore.list": chores.cmd_list_chores,
    "chore.show": chores.cmd_show_chore,
    "activity.complete": activity.cmd_complete,
    "activity.incomplete": activity.cmd_incomplete,
    "activity.dispute": activity.cmd_dispute,
    "activity.resolve": activity.cmd_resolve,
    "activity.audit": activity.cmd_audit,
    "activity.verify-audit": activity.cmd_verify_audit,
    "activity.poll": activity.cmd_poll,
}


def invoke_command(action: str, args: dict, session_data: dict | None) -> tuple[int, dict]:
    handler = COMMANDS.get(action)
    if handler is None:
        return HTTPStatus.NOT_FOUND, {"ok": False, "error": f"Unknown action: {action}"}

    with session_scope(session_data), capture_stdout() as buf:
        try:
            handler(Namespace(**args))
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            return HTTPStatus.OK, {
                "ok": False,
                "error": buf.getvalue().strip() or f"Command exited with status {code}",
                "exit_code": code,
                "output": buf.getvalue(),
                "session": load_session(),
            }
        except Exception as exc:
            return HTTPStatus.INTERNAL_SERVER_ERROR, {
                "ok": False,
                "error": f"Server error: {exc}",
                "output": buf.getvalue(),
                "session": load_session(),
            }

        return HTTPStatus.OK, {
            "ok": True,
            "output": buf.getvalue(),
            "session": load_session(),
        }


class CleanPlateHandler(BaseHTTPRequestHandler):
    server_version = "CleanPlateHTTP/1.0"

    def do_GET(self) -> None:
        if self.path != "/health":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})
            return
        self._send_json(HTTPStatus.OK, {"ok": True, "status": "healthy"})

    def do_POST(self) -> None:
        if self.path != "/command":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid JSON payload"})
            return

        action = payload.get("action")
        args = payload.get("args", {})
        session_data = payload.get("session")

        if not isinstance(action, str):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Missing action"})
            return
        if not isinstance(args, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "args must be an object"})
            return
        if session_data is not None and not isinstance(session_data, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "session must be an object or null"})
            return

        status, response = invoke_command(action, args, session_data)
        self._send_json(status, response)

    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class CleanPlateThreadingServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _wrap_server_socket_for_tls(
    server: ThreadingHTTPServer,
    *,
    certfile: str,
    keyfile: str,
) -> ThreadingHTTPServer:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    if hasattr(context, "set_alpn_protocols"):
        context.set_alpn_protocols(["http/1.1"])
    if hasattr(ssl, "OP_NO_COMPRESSION") and hasattr(context, "options"):
        context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def make_server(
    host: str = "127.0.0.1",
    port: int = 8443,
    *,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    allow_insecure_http: bool = False,
) -> ThreadingHTTPServer:
    init_db()
    if (tls_cert is None) != (tls_key is None):
        raise ValueError("Both tls_cert and tls_key must be provided together.")
    if not allow_insecure_http and not (tls_cert and tls_key):
        raise ValueError("TLS certificate and key are required unless allow_insecure_http is enabled.")

    server = CleanPlateThreadingServer((host, port), CleanPlateHandler)
    if tls_cert and tls_key:
        return _wrap_server_socket_for_tls(server, certfile=tls_cert, keyfile=tls_key)
    return server


def run_server(
    host: str | None = None,
    port: int | None = None,
    *,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    allow_insecure_http: bool = False,
) -> None:
    host = host or get_option("server", "host", "127.0.0.1")
    port = port or get_int("server", "port", 8443)
    tls_cert = tls_cert or os.environ.get("CLEANPLATE_TLS_CERT") or resolve_path(get_option("server", "tls_cert", None))
    tls_key = tls_key or os.environ.get("CLEANPLATE_TLS_KEY") or resolve_path(get_option("server", "tls_key", None))
    allow_insecure_http = allow_insecure_http or get_bool("server", "allow_insecure_http", False)
    try:
        server = make_server(
            host,
            port,
            tls_cert=tls_cert,
            tls_key=tls_key,
            allow_insecure_http=allow_insecure_http,
        )
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            scheme = "https" if tls_cert and tls_key else "http"
            print(f"Error: a CleanPlate server is already running on {scheme}://{host}:{port}")
            return
        raise
    except ValueError as exc:
        print(f"Error: {exc}")
        return
    scheme = "https" if tls_cert and tls_key else "http"
    print(f"CleanPlate server listening on {scheme}://{host}:{port}")
    server.serve_forever()
