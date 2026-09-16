"""Bounded HTTP body reads — mitigates Content-Length and slow-drip DoS.

BaseHTTPRequestHandler.rfile.read(n) blocks until n bytes arrive. Attacks:

1. Lying Content-Length (huge n, no/few bytes) — hang until socket timeout.
2. Slow drip: send 1 byte just under REQUEST_SOCKET_TIMEOUT forever while
   Content-Length stays <= MAX_BODY_BYTES. Per-read timeout alone never fires;
   a worker stays busy for ~MAX_BODY_BYTES * inter-byte delay.

Policy
------
* Reject Content-Length above MAX_BODY_BYTES immediately (no read).
* Reject negative / non-integer Content-Length.
* Read in small chunks under an **absolute** wall-clock deadline
  (BODY_READ_DEADLINE_SECONDS), independent of per-socket idle timeout.
* Per-connection socket timeout still bounds silence between chunks.
"""

from __future__ import annotations

import time
from typing import Any, Dict

# Default: 1 MiB is ample for proposal+records JSON on the Edge API.
MAX_BODY_BYTES = 1 * 1024 * 1024
# Per-connection idle/read timeout (seconds) — silence between bytes.
REQUEST_SOCKET_TIMEOUT = 10.0
# Absolute wall-clock budget for an entire body (slow-drip ceiling).
# At 1 MiB this still allows ~30 KiB/s average; drips of 1 B / 9 s cannot finish.
BODY_READ_DEADLINE_SECONDS = 30.0
# Chunk size for deadline-aware reads.
_READ_CHUNK = 1024


class BodyLimitError(Exception):
    """Client sent an unacceptable Content-Length or body / timed out."""

    def __init__(self, reason: str = "body_limit") -> None:
        super().__init__(reason)
        self.reason = reason


def parse_content_length(headers: Any, *, max_bytes: int = MAX_BODY_BYTES) -> int:
    raw = headers.get("Content-Length") if headers is not None else None
    if raw is None or raw == "":
        return 0
    try:
        n = int(raw)
    except (TypeError, ValueError):
        raise BodyLimitError("content_length_invalid")
    if n < 0:
        raise BodyLimitError("content_length_negative")
    if n > max_bytes:
        raise BodyLimitError("content_length_too_large")
    return n


def read_bounded_body(
    rfile: Any,
    headers: Any,
    *,
    max_bytes: int = MAX_BODY_BYTES,
    deadline_seconds: float = BODY_READ_DEADLINE_SECONDS,
) -> bytes:
    """Read at most max_bytes within an absolute deadline.

    Raises BodyLimitError:
      - before any read if Content-Length is hostile
      - body_read_deadline if the wall clock budget is exhausted mid-read
      - body_incomplete if the peer closes early
    """
    n = parse_content_length(headers, max_bytes=max_bytes)
    if n == 0:
        return b""
    to_read = min(n, max_bytes)
    deadline = time.monotonic() + max(0.05, float(deadline_seconds))
    chunks: list[bytes] = []
    got = 0
    while got < to_read:
        if time.monotonic() >= deadline:
            raise BodyLimitError("body_read_deadline")
        remaining = to_read - got
        want = min(remaining, _READ_CHUNK)
        try:
            # Prefer read1(): at most one underlying recv, so we re-check the
            # absolute deadline between dribbles instead of blocking until
            # `want` bytes accumulate (BufferedReader.read would).
            if hasattr(rfile, "read1"):
                piece = rfile.read1(want)
            else:
                piece = rfile.read(want)
        except Exception as exc:
            name = type(exc).__name__.lower()
            if "timeout" in name or "timed out" in str(exc).lower():
                raise BodyLimitError("body_read_timeout") from exc
            raise BodyLimitError("body_read_error") from exc
        if not piece:
            raise BodyLimitError("body_incomplete")
        chunks.append(piece)
        got += len(piece)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise BodyLimitError("body_too_large")
    return data


def read_bounded_json(
    rfile: Any,
    headers: Any,
    *,
    max_bytes: int = MAX_BODY_BYTES,
    deadline_seconds: float = BODY_READ_DEADLINE_SECONDS,
) -> Dict[str, Any]:
    import json

    raw = read_bounded_body(
        rfile, headers, max_bytes=max_bytes, deadline_seconds=deadline_seconds
    )
    if not raw:
        return {}
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BodyLimitError("bad_json") from exc
    if not isinstance(obj, dict):
        raise BodyLimitError("json_not_object")
    return obj
