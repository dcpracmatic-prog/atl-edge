#!/usr/bin/env python3
"""PostgreSQL-backed control plane: requires a running Postgres reachable at
ATL_TEST_POSTGRES_DSN (or the default local dev DSN below). Proves the same
business rules as the SQLite backend, PLUS the concrete advantage of
per-license row locking: two licenses under concurrent load don't block
each other, while each individually still enforces max_nodes exactly."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.control_plane import ControlPlane, LicenseError
from src.control_plane_storage import PostgresBackend, StorageError

DEFAULT_DSN = "postgresql://atl_control_plane:atl-dev-only@127.0.0.1:5432/atl_control_plane"


def main() -> int:
    dsn = os.environ.get("ATL_TEST_POSTGRES_DSN", DEFAULT_DSN)
    try:
        import psycopg
        with psycopg.connect(dsn, connect_timeout=3):
            pass
    except Exception as exc:
        print(f"SKIP: no reachable Postgres at {dsn} ({exc})")
        return 0

    with tempfile.TemporaryDirectory() as td:
        # Fresh table state per run: drop and let init_schema() recreate.
        import psycopg
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS license_nodes")
            conn.execute("DROP TABLE IF EXISTS licenses")

        cp = ControlPlane.with_postgres(Path(td) / "state", dsn)
        assert isinstance(cp.backend, PostgresBackend)

        issued = cp.issue_license("acme-corp", "enterprise", max_nodes=2, max_agents=5)
        print("license issued (Postgres-backed):", issued["license_id"])

        ent1 = cp.activate(issued["api_key"], node_id="node-1", instance_id="inst-1", agent_id="a1")
        assert ent1.payload["node_id"] == "node-1"
        print("activation for node-1: OK")

        # Idempotent re-activation.
        cp.activate(issued["api_key"], node_id="node-1", instance_id="inst-1-updated", agent_id="a1")
        print("re-activation of the same node is idempotent: OK")

        ent2 = cp.activate(issued["api_key"], node_id="node-2", instance_id="inst-2", agent_id="a1")
        assert ent2.payload["node_id"] == "node-2"
        print("activation for node-2 (fills max_nodes=2): OK")

        try:
            cp.activate(issued["api_key"], node_id="node-3", instance_id="inst-3", agent_id="a1")
            print("FAIL: third node accepted despite max_nodes=2")
            return 1
        except LicenseError as exc:
            assert "max_nodes" in str(exc)
        print("third node rejected once max_nodes exceeded: OK")

        summary = cp.get_license(issued["license_id"])
        assert summary.node_count == 2
        print(f"get_license reports node_count={summary.node_count}: OK")

        cp.revoke_license(issued["license_id"])
        try:
            cp.activate(issued["api_key"], node_id="node-4", instance_id="inst-4", agent_id="a1")
            print("FAIL: revoked license still activated")
            return 1
        except LicenseError as exc:
            assert "revoked" in str(exc)
        print("revoked license rejected: OK")

        # ---- Concurrency: 30 threads racing for the last slot on ONE license ----
        race_issued = cp.issue_license("race-corp", "pro", max_nodes=1, max_agents=1)
        outcomes: list[bool] = []
        lock = threading.Lock()

        def try_activate(node_id: str) -> None:
            try:
                cp.activate(race_issued["api_key"], node_id=node_id, instance_id=f"i-{node_id}", agent_id="a1")
                ok = True
            except LicenseError:
                ok = False
            with lock:
                outcomes.append(ok)

        threads = [threading.Thread(target=try_activate, args=(f"race-node-{i}",)) for i in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        succeeded = sum(1 for o in outcomes if o)
        race_summary = cp.get_license(race_issued["license_id"])
        assert succeeded == 1, f"expected exactly 1 winner, got {succeeded}"
        assert race_summary.node_count == 1
        print(f"concurrent race, 30 threads, ONE Postgres-row-locked license, max_nodes=1: "
              f"exactly 1 winner, node_count={race_summary.node_count}: OK")

        # ---- Row-level locking: a SECOND license's activation should NOT ----
        # ---- be blocked while a DIFFERENT license's row is locked at the ----
        # ---- actual database level. This is the concrete advantage over ----
        # ---- SQLiteBackend's whole-database lock — proven with a raw ----
        # ---- connection holding a real `FOR UPDATE`, not a Python-level mock. ----
        other_issued = cp.issue_license("other-corp", "pro", max_nodes=5, max_agents=5)
        third_issued = cp.issue_license("third-corp", "pro", max_nodes=1, max_agents=1)

        lock_held = threading.Event()
        release_lock = threading.Event()

        def hold_row_lock():
            with psycopg.connect(dsn, autocommit=False) as conn:
                conn.execute("SELECT license_id FROM licenses WHERE license_id = %s FOR UPDATE",
                              (other_issued["license_id"],))
                lock_held.set()
                release_lock.wait(timeout=5)
                conn.commit()

        t_lock = threading.Thread(target=hold_row_lock)
        t_lock.start()
        assert lock_held.wait(timeout=5), "row lock was never acquired"

        # While `other_issued`'s row is locked at the DB level, activating a
        # DIFFERENT license must complete immediately.
        t0 = time.time()
        cp.activate(third_issued["api_key"], node_id="fast-node", instance_id="i", agent_id="a1")
        elapsed = time.time() - t0

        release_lock.set()
        t_lock.join(timeout=5)

        assert elapsed < 2.0, f"unrelated license activation was blocked for {elapsed:.2f}s"
        print(f"unrelated license activation completed in {elapsed:.3f}s while a DIFFERENT "
              f"license's row was locked at the DB level: OK (per-license locking, not whole-database)")

        # Sanity check the inverse: activating THE SAME locked license DOES wait.
        lock_held.clear()
        release_lock.clear()
        t_lock2 = threading.Thread(target=hold_row_lock)
        t_lock2.start()
        assert lock_held.wait(timeout=5)

        result_holder: dict = {}

        def blocked_activate():
            t0b = time.time()
            cp.activate(other_issued["api_key"], node_id="blocked-node", instance_id="i", agent_id="a1")
            result_holder["elapsed"] = time.time() - t0b

        t_blocked = threading.Thread(target=blocked_activate)
        t_blocked.start()
        time.sleep(0.3)
        assert "elapsed" not in result_holder, "activation on the SAME locked license did not block"
        release_lock.set()
        t_lock2.join(timeout=5)
        t_blocked.join(timeout=5)
        assert result_holder["elapsed"] >= 0.2, "activation returned suspiciously fast for a blocked call"
        print(f"activation on the SAME locked license correctly waited ({result_holder['elapsed']:.3f}s): OK")

        print()
        print("control_plane postgres selftest: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
