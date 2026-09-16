"""Durable execution ledger for request_id idempotency.

Process-local sets cannot survive restart and cannot prevent the case:

  executor() succeeds → issue_for_agent() fails → same request_id retried
  → executor must NOT run again.

States (per request_id):
  reserved            — accepted, not yet finished executor
  executed_unissued   — executor finished; ATLP issue not confirmed
  completed           — ATLP issue succeeded

Transitions are append-only to a SQLite file (or pure in-memory for tests).
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional


class LedgerError(PermissionError):
    """Raised when a request_id cannot be (re)executed safely."""


class ExecutionLedger:
    def __init__(self, path: Optional[str | Path] = None) -> None:
        self._lock = threading.Lock()
        self._mem: dict[str, str] = {}
        self._path = Path(path) if path else None
        self._conn: Optional[sqlite3.Connection] = None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_ledger (
                    request_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _get(self, rid: str) -> Optional[str]:
        if self._conn is not None:
            row = self._conn.execute(
                "SELECT state FROM execution_ledger WHERE request_id = ?", (rid,)
            ).fetchone()
            return row[0] if row else None
        return self._mem.get(rid)

    def _set(self, rid: str, state: str) -> None:
        now = time.time()
        if self._conn is not None:
            self._conn.execute(
                """
                INSERT INTO execution_ledger(request_id, state, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    state = excluded.state,
                    updated_at = excluded.updated_at
                """,
                (rid, state, now),
            )
            self._conn.commit()
        else:
            self._mem[rid] = state

    def reserve(self, request_id: str) -> None:
        """Claim request_id for a new attempt, or reject unsafe retries."""
        with self._lock:
            st = self._get(request_id)
            if st == "completed":
                raise LedgerError("duplicate request_id: already completed")
            if st == "executed_unissued":
                raise LedgerError(
                    "duplicate request_id: executor already ran; issue incomplete"
                )
            if st == "reserved":
                raise LedgerError("duplicate request_id: in flight")
            self._set(request_id, "reserved")

    def mark_executed(self, request_id: str) -> None:
        """Call immediately after executor success, before ATLP issue."""
        with self._lock:
            st = self._get(request_id)
            if st not in ("reserved", "executed_unissued"):
                raise LedgerError(f"cannot mark executed from state={st!r}")
            self._set(request_id, "executed_unissued")

    def mark_completed(self, request_id: str) -> None:
        with self._lock:
            self._set(request_id, "completed")

    def release_reservation(self, request_id: str) -> None:
        """Drop reservation only if executor never ran (safe to retry whole path)."""
        with self._lock:
            st = self._get(request_id)
            if st == "reserved":
                if self._conn is not None:
                    self._conn.execute(
                        "DELETE FROM execution_ledger WHERE request_id = ? AND state = 'reserved'",
                        (request_id,),
                    )
                    self._conn.commit()
                else:
                    self._mem.pop(request_id, None)

    def state(self, request_id: str) -> Optional[str]:
        with self._lock:
            return self._get(request_id)
