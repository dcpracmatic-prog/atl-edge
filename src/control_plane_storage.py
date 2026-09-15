"""Storage backends for `src/control_plane.py`.

`ControlPlane`'s business logic (revoked/expired checks, entitlement
signing) is backend-agnostic. What differs between a single-process MVP and
a production deployment is exactly one thing: how "read the node count for
this license, then insert a new node row if there's room" is made atomic
against concurrent activations. This module isolates that one operation
behind `StorageBackend.register_node_atomic()` so `ControlPlane` itself
never has to know which database it's talking to.

Two implementations:

  SQLiteBackend   — the default. Zero external dependencies (stdlib only),
                    one file on disk. Atomicity comes from `BEGIN IMMEDIATE`,
                    which takes SQLite's single writer lock for the whole
                    database up front. Correct, but coarse: an activation
                    for License A blocks an unrelated activation for
                    License B for the duration of the transaction. Fine for
                    an MVP or a single-process pilot.

  PostgresBackend — for a real multi-process/multi-host control plane.
                    Requires `psycopg` (`pip install "psycopg[binary]"`) and
                    a running Postgres server; the import is deferred so
                    `control_plane.py` still works with zero extra
                    dependencies when Postgres isn't in use. Atomicity comes
                    from `SELECT ... FOR UPDATE` on the specific license
                    row, which locks only that license — concurrent
                    activations for *different* licenses don't contend with
                    each other, unlike SQLiteBackend's whole-database lock.

Both are proven against the exact same concurrency test
(`examples/control_plane_selftest.py` for SQLite,
`examples/control_plane_postgres_selftest.py` for Postgres): N threads
racing to activate the last free node slot on one license must produce
exactly one winner.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Protocol


class StorageError(ValueError):
    """Backend-level failure distinct from `control_plane.LicenseError` —
    a caller that only wants to catch business-rule rejections shouldn't
    accidentally also catch a database connectivity failure the same way.
    """


@dataclass(frozen=True)
class LicenseRow:
    license_id: str
    organization_id: str
    plan: str
    api_key_fingerprint: str
    issued_at: float
    expires_at: float
    max_nodes: int
    max_agents: int
    capabilities: List[str]
    revoked: bool


class StorageBackend(Protocol):
    def init_schema(self) -> None: ...
    def insert_license(self, row: LicenseRow) -> None: ...
    def set_revoked(self, license_id: str) -> bool: ...
    def get_by_fingerprint(self, api_key_fingerprint: str) -> Optional[LicenseRow]: ...
    def get_by_id(self, license_id: str) -> Optional[LicenseRow]: ...
    def node_count(self, license_id: str) -> int: ...

    def register_node_atomic(self, license_id: str, node_id: str, instance_id: str,
                              now: float, max_nodes: int) -> None:
        """Ensure `node_id` is registered for `license_id`.

        If `node_id` is already registered, update its `instance_id`
        (idempotent re-activation). If it is not, insert it ONLY if the
        current node count is below `max_nodes` — atomically with the count
        check, so this is the one method that has to actually prevent the
        race, not just report on it.

        Raises StorageError (wrapping a backend-specific "capacity
        exceeded" condition) if there is no room. Callers translate that
        into `control_plane.LicenseError("max_nodes exceeded")`.
        """
        ...


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS licenses (
    license_id           TEXT PRIMARY KEY,
    organization_id      TEXT NOT NULL,
    plan                 TEXT NOT NULL,
    api_key_fingerprint  TEXT NOT NULL UNIQUE,
    issued_at            REAL NOT NULL,
    expires_at           REAL NOT NULL,
    max_nodes            INTEGER NOT NULL,
    max_agents           INTEGER NOT NULL,
    capabilities_json    TEXT NOT NULL,
    revoked              INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS license_nodes (
    license_id    TEXT NOT NULL REFERENCES licenses(license_id),
    node_id       TEXT NOT NULL,
    instance_id   TEXT NOT NULL,
    registered_at REAL NOT NULL,
    PRIMARY KEY (license_id, node_id)
);
"""


class SQLiteBackend:
    def __init__(self, db_path: Path):
        import json as _json  # local import keeps module-level import list minimal
        self._json = _json
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        import os
        with self._connect() as conn:
            conn.executescript(_SQLITE_SCHEMA)
        os.chmod(self.db_path, 0o600)

    def insert_license(self, row: LicenseRow) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO licenses (license_id, organization_id, plan, api_key_fingerprint, "
                "issued_at, expires_at, max_nodes, max_agents, capabilities_json, revoked) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row.license_id, row.organization_id, row.plan, row.api_key_fingerprint,
                 row.issued_at, row.expires_at, row.max_nodes, row.max_agents,
                 self._json.dumps(row.capabilities), int(row.revoked)),
            )

    def set_revoked(self, license_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("UPDATE licenses SET revoked = 1 WHERE license_id = ?", (license_id,))
            return cur.rowcount > 0

    def _row(self, r: sqlite3.Row) -> LicenseRow:
        return LicenseRow(
            license_id=r["license_id"], organization_id=r["organization_id"], plan=r["plan"],
            api_key_fingerprint=r["api_key_fingerprint"], issued_at=r["issued_at"],
            expires_at=r["expires_at"], max_nodes=r["max_nodes"], max_agents=r["max_agents"],
            capabilities=self._json.loads(r["capabilities_json"]), revoked=bool(r["revoked"]),
        )

    def get_by_fingerprint(self, api_key_fingerprint: str) -> Optional[LicenseRow]:
        with self._connect() as conn:
            r = conn.execute(
                "SELECT * FROM licenses WHERE api_key_fingerprint = ?", (api_key_fingerprint,)
            ).fetchone()
            return self._row(r) if r else None

    def get_by_id(self, license_id: str) -> Optional[LicenseRow]:
        with self._connect() as conn:
            r = conn.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
            return self._row(r) if r else None

    def node_count(self, license_id: str) -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) AS n FROM license_nodes WHERE license_id = ?", (license_id,)
            ).fetchone()["n"]

    def register_node_atomic(self, license_id: str, node_id: str, instance_id: str,
                              now: float, max_nodes: int) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT 1 FROM license_nodes WHERE license_id = ? AND node_id = ?",
                (license_id, node_id),
            ).fetchone()
            if existing is None:
                count = conn.execute(
                    "SELECT COUNT(*) AS n FROM license_nodes WHERE license_id = ?", (license_id,)
                ).fetchone()["n"]
                if count >= max_nodes:
                    conn.execute("ROLLBACK")
                    raise StorageError("max_nodes exceeded")
                conn.execute(
                    "INSERT INTO license_nodes (license_id, node_id, instance_id, registered_at) "
                    "VALUES (?, ?, ?, ?)",
                    (license_id, node_id, instance_id, now),
                )
            else:
                conn.execute(
                    "UPDATE license_nodes SET instance_id = ? WHERE license_id = ? AND node_id = ?",
                    (instance_id, license_id, node_id),
                )
            conn.execute("COMMIT")
        except StorageError:
            raise
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# PostgreSQL backend
# ---------------------------------------------------------------------------

_POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS licenses (
    license_id           TEXT PRIMARY KEY,
    organization_id      TEXT NOT NULL,
    plan                 TEXT NOT NULL,
    api_key_fingerprint  TEXT NOT NULL UNIQUE,
    issued_at            DOUBLE PRECISION NOT NULL,
    expires_at           DOUBLE PRECISION NOT NULL,
    max_nodes            INTEGER NOT NULL,
    max_agents           INTEGER NOT NULL,
    capabilities_json    TEXT NOT NULL,
    revoked              BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS license_nodes (
    license_id    TEXT NOT NULL REFERENCES licenses(license_id),
    node_id       TEXT NOT NULL,
    instance_id   TEXT NOT NULL,
    registered_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (license_id, node_id)
);
"""


class PostgresBackend:
    """Requires `psycopg` (v3): `pip install "psycopg[binary]" --break-system-packages`.

    `dsn` is a standard libpq connection string, e.g.
    `postgresql://atl_control_plane:PASSWORD@127.0.0.1:5432/atl_control_plane`.
    Credentials belong in environment/secret-manager configuration, not
    hardcoded — same principle as every other secret in this package.
    """

    def __init__(self, dsn: str):
        try:
            import psycopg  # noqa: F401  (import here: optional dependency)
        except ImportError as exc:
            raise StorageError(
                'PostgresBackend requires psycopg: pip install "psycopg[binary]" --break-system-packages'
            ) from exc
        self._psycopg = psycopg
        self.dsn = dsn

    def _connect(self):
        return self._psycopg.connect(self.dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(_POSTGRES_SCHEMA)

    def insert_license(self, row: LicenseRow) -> None:
        import json as _json
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO licenses (license_id, organization_id, plan, api_key_fingerprint, "
                "issued_at, expires_at, max_nodes, max_agents, capabilities_json, revoked) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (row.license_id, row.organization_id, row.plan, row.api_key_fingerprint,
                 row.issued_at, row.expires_at, row.max_nodes, row.max_agents,
                 _json.dumps(row.capabilities), row.revoked),
            )

    def set_revoked(self, license_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("UPDATE licenses SET revoked = TRUE WHERE license_id = %s", (license_id,))
            return cur.rowcount > 0

    def _row(self, r) -> LicenseRow:
        import json as _json
        (license_id, organization_id, plan, api_key_fingerprint, issued_at, expires_at,
         max_nodes, max_agents, capabilities_json, revoked) = r
        return LicenseRow(
            license_id=license_id, organization_id=organization_id, plan=plan,
            api_key_fingerprint=api_key_fingerprint, issued_at=issued_at, expires_at=expires_at,
            max_nodes=max_nodes, max_agents=max_agents,
            capabilities=_json.loads(capabilities_json), revoked=bool(revoked),
        )

    def get_by_fingerprint(self, api_key_fingerprint: str) -> Optional[LicenseRow]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT license_id, organization_id, plan, api_key_fingerprint, issued_at, expires_at, "
                "max_nodes, max_agents, capabilities_json, revoked FROM licenses "
                "WHERE api_key_fingerprint = %s", (api_key_fingerprint,),
            )
            r = cur.fetchone()
            return self._row(r) if r else None

    def get_by_id(self, license_id: str) -> Optional[LicenseRow]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT license_id, organization_id, plan, api_key_fingerprint, issued_at, expires_at, "
                "max_nodes, max_agents, capabilities_json, revoked FROM licenses "
                "WHERE license_id = %s", (license_id,),
            )
            r = cur.fetchone()
            return self._row(r) if r else None

    def node_count(self, license_id: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT COUNT(*) FROM license_nodes WHERE license_id = %s", (license_id,)
            )
            return cur.fetchone()[0]

    def register_node_atomic(self, license_id: str, node_id: str, instance_id: str,
                              now: float, max_nodes: int) -> None:
        """`SELECT ... FOR UPDATE` locks only this license's row for the
        transaction's duration — concurrent activations against a
        *different* license proceed unblocked, unlike SQLiteBackend's
        whole-database lock. This is the concrete advantage of a real
        server-grade database over the SQLite reference backend.
        """
        with self._connect() as conn:
            with conn.transaction():
                conn.execute("SELECT license_id FROM licenses WHERE license_id = %s FOR UPDATE", (license_id,))
                cur = conn.execute(
                    "SELECT 1 FROM license_nodes WHERE license_id = %s AND node_id = %s",
                    (license_id, node_id),
                )
                existing = cur.fetchone()
                if existing is None:
                    cur = conn.execute(
                        "SELECT COUNT(*) FROM license_nodes WHERE license_id = %s", (license_id,)
                    )
                    count = cur.fetchone()[0]
                    if count >= max_nodes:
                        raise StorageError("max_nodes exceeded")
                    conn.execute(
                        "INSERT INTO license_nodes (license_id, node_id, instance_id, registered_at) "
                        "VALUES (%s, %s, %s, %s)",
                        (license_id, node_id, instance_id, now),
                    )
                else:
                    conn.execute(
                        "UPDATE license_nodes SET instance_id = %s WHERE license_id = %s AND node_id = %s",
                        (instance_id, license_id, node_id),
                    )
