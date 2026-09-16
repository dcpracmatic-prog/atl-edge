#!/usr/bin/env python3
"""Authenticated Edge -> Cloud Connector transport: happy path, forged
signature rejection, and replay rejection. Runs real HTTP over loopback."""
from __future__ import annotations

import hashlib
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data_plane import LocalDataPlane, OnPremAuditLog, PackageCrypto, node_key
from src.file_workflow import Outbox
from src.transport import derive_transport_key, push_ready, sign_request
from connector.cloud_runtime import ConnectorIngestServer


def main() -> int:
    NODE_ID = "agent-node-01"
    master = hashlib.sha256(b"atl-dev-master").digest()
    node_key_bytes = node_key(master, NODE_ID)

    received = []
    connector = ConnectorIngestServer(NODE_ID, node_key_bytes.hex(), lambda n, r, p: received.append((n, r, p)), port=0)
    connector.start()
    try:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            crypto = PackageCrypto.from_master(master, NODE_ID, key_id="node-v1")
            dp = LocalDataPlane(crypto, OnPremAuditLog(root / "audit.jsonl"))
            outbox = Outbox(root / "outbox")

            issued = dp.issue_for_agent(
                [{"customer_id": i, "status": "active"} for i in range(5)],
                policy_id="crm.read", ttl_seconds=30, fields=["customer_id", "status"],
                request_id="req-happy",
            )
            outbox.deposit(NODE_ID, issued.header.request_id, issued.package,
                            policy_id=issued.header.policy_id, expiry=issued.header.expiry)

            url = f"http://127.0.0.1:{connector.port}"
            results = push_ready(outbox, NODE_ID, url, node_key_bytes, archive_root=root / "archive")
            assert len(results) == 1 and results[0].delivered and results[0].status == 200
            assert outbox.list_ready(NODE_ID) == []
            assert len(received) == 1 and received[0][2]["n_out"] == 5
            print("happy path push -> connector -> agent handler: OK")

            # Forged signature must be rejected, and must never reach the agent handler.
            bad_req = urllib.request.Request(
                url + f"/ingest/{NODE_ID}/forged-1", data=b"not-a-real-package",
                headers={"X-ATL-Timestamp": str(int(time.time())), "X-ATL-Nonce": secrets.token_hex(8),
                         "X-ATL-Signature": "00" * 32},
                method="POST",
            )
            try:
                urllib.request.urlopen(bad_req, timeout=5)
                print("FAIL: forged signature was accepted")
                return 1
            except urllib.error.HTTPError as exc:
                assert exc.code == 401, exc.code
            assert len(received) == 1, "forged request reached the agent handler"
            print("forged signature rejected (401), never reached agent handler: OK")

            # Replaying an identical, validly-signed request must be rejected the second time.
            issued2 = dp.issue_for_agent([{"customer_id": 1}], policy_id="crm.read", ttl_seconds=30,
                                          fields=["customer_id"], request_id="req-replay")
            entry2 = outbox.deposit(NODE_ID, issued2.header.request_id, issued2.package,
                                     policy_id=issued2.header.policy_id, expiry=issued2.header.expiry)
            path = f"/ingest/{NODE_ID}/req-replay"
            pkg = outbox.read_package(entry2)
            headers = sign_request(derive_transport_key(node_key_bytes), "POST", path, pkg)

            def send():
                r = urllib.request.Request(url + path, data=pkg, headers=headers, method="POST")
                return urllib.request.urlopen(r, timeout=5).getcode()

            assert send() == 200
            try:
                send()
                print("FAIL: replay of identical signed request was accepted")
                return 1
            except urllib.error.HTTPError as exc:
                assert exc.code == 401, exc.code
            print("replay of identical signed request rejected (401) on second delivery: OK")

            print()
            print("transport selftest: PASS")
            return 0
    finally:
        connector.stop()


if __name__ == "__main__":
    raise SystemExit(main())
