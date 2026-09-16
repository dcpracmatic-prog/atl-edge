#!/usr/bin/env python3
"""Inbox/Outbox on-disk file workflow: atomic writes, discovery, expiry sweep,
path-traversal guard, ack/archive idempotency."""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.file_workflow import Inbox, Outbox


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        ib = Inbox(root / "inbox")
        it1 = ib.receive("db-export", "customers.csv", b"id,name\n1,foo\n")
        it2 = ib.receive("db-export", "orders.csv", b"id,total\n1,10\n")
        pending = ib.list_pending("db-export")
        assert len(pending) == 2, pending
        print("inbox.list_pending: OK", [p.original_name for p in pending])

        ib.archive(it1, root / "inbox-archive")
        pending = ib.list_pending("db-export")
        assert [p.item_id for p in pending] == [it2.item_id]
        assert (root / "inbox-archive" / "db-export" / it1.path.name).exists()
        print("inbox.archive: OK")

        ob = Outbox(root / "outbox")
        now = time.time()
        ready_entry = ob.deposit("node-1", "req-A", b"PKG-A", policy_id="crm.read", expiry=now + 60)
        ob.deposit("node-1", "req-B", b"PKG-B", policy_id="crm.read", expiry=now - 1)  # pre-expired

        ready = ob.list_ready("node-1", now=now)
        assert [e.request_id for e in ready] == ["req-A"], ready
        assert not (root / "outbox" / "node-1" / "req-B.atlp").exists(), "expired entry must be swept"
        print("outbox.list_ready + expiry sweep: OK")

        assert ob.read_package(ready[0]) == b"PKG-A"
        ob.ack(ready[0], archive_root=root / "outbox-archive")
        assert ob.list_ready("node-1", now=now) == []
        assert (root / "outbox-archive" / "node-1" / "req-A.atlp").exists()
        print("outbox.read_package + ack (archived): OK")

        # ack is idempotent
        ob.ack(ready[0], archive_root=root / "outbox-archive")
        print("outbox.ack idempotent (double-ack does not raise): OK")

        evil = ob.deposit("../../etc", "../../passwd", b"nope", policy_id="p", expiry=now + 60)
        assert ".." not in str(evil.package_path.relative_to(root))
        print("path-traversal guard on node_id/request_id: OK")

        print()
        print("file_workflow selftest: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
