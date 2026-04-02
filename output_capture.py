"""
output_capture.py — thread-safe stdout capture for concurrent request handling.
"""

from __future__ import annotations

import io
import sys
from contextlib import contextmanager
from contextvars import ContextVar


_ORIGINAL_STDOUT = sys.stdout
_CURRENT_STDOUT: ContextVar[io.StringIO | None] = ContextVar("cleanplate_current_stdout", default=None)


class _ContextStdout:
    encoding = getattr(_ORIGINAL_STDOUT, "encoding", "utf-8")
    errors = getattr(_ORIGINAL_STDOUT, "errors", "strict")

    def write(self, text: str) -> int:
        stream = _CURRENT_STDOUT.get() or _ORIGINAL_STDOUT
        return stream.write(text)

    def flush(self) -> None:
        stream = _CURRENT_STDOUT.get() or _ORIGINAL_STDOUT
        stream.flush()

    def isatty(self) -> bool:
        stream = _CURRENT_STDOUT.get() or _ORIGINAL_STDOUT
        return bool(getattr(stream, "isatty", lambda: False)())

    def fileno(self) -> int:
        stream = _CURRENT_STDOUT.get() or _ORIGINAL_STDOUT
        if hasattr(stream, "fileno"):
            return stream.fileno()
        return _ORIGINAL_STDOUT.fileno()


if not isinstance(sys.stdout, _ContextStdout):
    sys.stdout = _ContextStdout()


@contextmanager
def capture_stdout():
    buffer = io.StringIO()
    token = _CURRENT_STDOUT.set(buffer)
    try:
        yield buffer
    finally:
        _CURRENT_STDOUT.reset(token)
