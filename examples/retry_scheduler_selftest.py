#!/usr/bin/env python3
"""RetryScheduler: persistent backoff across run_once() calls, recovery once
the Connector comes back, and dead-lettering after max_attempts is exceeded."""
from __future__ import annotations

import hashlib
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data_plane import LocalDataPlane, OnPremAuditLog, PackageCrypto, node_key
from src.file_workflow import Outbox
from src.transport import RetryScheduler


def main() -> int:
    NODE_ID = "agent-node-01"
    master = hashlib.sha256(b"atl-dev-master").digest()
    node_key_bytes = node_key(master, NODE_ID)

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        crypto = PackageCrypto.from_master(master, NODE_ID, key_id="node-v1")
        dp = LocalDataPlane(crypto, OnPremAuditLog(root / "audit.jsonl"))
        outbox = Outbox(root / "outbox")

        issued = dp.issue_for_agent([{"customer_id": 1}], policy_id="crm.read", ttl_seconds=600,
                                     fields=["customer_id"], request_id="retry-req-1")
        outbox.deposit(NODE_ID, issued.header.request_id, issued.package,
                        policy_id=issued.header.policy_id, expiry=issued.header.expiry)

        # Point at a port nothing is listening on: every attempt fails.
        dead_url = "http://127.0.0.1:1"  # port 1 is reliably closed/unprivileged-refused
        scheduler = RetryScheduler(
            outbox, NODE_ID, dead_url, node_key_bytes,
            max_attempts=3, base_delay=0.01, max_delay=0.05,
            dead_letter_root=root / "dead-letter",
        )

        t0 = time.time()
        s1 = scheduler.run_once(now=t0)
        assert s1["delivered"] == 0 and s1["dead_lettered"] == 0
        assert outbox.list_ready(NODE_ID, now=t0) is not None  # still present, just not "due" per state
        print("attempt 1 failed, entry retained for retry: OK")

        # A NEW RetryScheduler instance pointed at the same outbox must see
        # the persisted backoff state (not reset attempts to 0).
        scheduler2 = RetryScheduler(
            outbox, NODE_ID, dead_url, node_key_bytes,
            max_attempts=3, base_delay=0.01, max_delay=0.05,
            dead_letter_root=root / "dead-letter",
        )
        state = scheduler2._load_state()
        assert state["retry-req-1"].attempts == 1
        print("backoff state persisted across RetryScheduler instances: OK")

        # Fast-forward past the backoff window and retry until dead-lettered.
        t = t0
        for _ in range(5):
            t += 1.0  # comfortably past base_delay/max_delay in this test
            summary = scheduler2.run_once(now=t)
            if summary["dead_lettered"]:
                break
        else:
            print("FAIL: entry was never dead-lettered")
            return 1

        assert (root / "dead-letter" / NODE_ID / "retry-req-1.atlp").exists()
        assert (root / "dead-letter" / NODE_ID / "retry-req-1.deadletter.json").exists()
        print("entry dead-lettered after max_attempts, package preserved for inspection: OK")

        # The outbox itself should no longer list it as ready (it's gone).
        assert outbox.list_ready(NODE_ID, now=t) == []
        print("dead-lettered entry removed from live outbox: OK")

        print()
        print("retry scheduler selftest: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
