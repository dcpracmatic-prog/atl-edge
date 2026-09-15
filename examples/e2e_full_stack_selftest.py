#!/usr/bin/env python3
"""Full-stack MVP selftest: every piece wired together, no shortcuts.

Control Plane (real, HTTP) -> atlctl-style activation -> licensed
ATLDataPlaneMVP.production() -> Edge Outbox (disk) -> authenticated
transport push (HTTP, HMAC-signed) -> Cloud Connector (HTTP, on the
premium agent's instance) -> decrypted payload handed to a mock agent.

This is the thing that answers "does the whole product actually work
end-to-end, not just its parts in isolation".
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.control_plane import ControlPlane
from src.control_plane_server import ControlPlaneServer
from src.licensing import SignedEntitlement, verify_entitlement, NodeIdentity, write_node_identity
from src.data_plane import LocalDataPlane, PackageCrypto, OnPremAuditLog, node_key
from src.data_catalog import DataAsset, DataCatalog, NodeAccessPolicy, Sensitivity
from src.mvp import ATLDataPlaneMVP
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.file_workflow import Outbox
from src.transport import push_ready
from connector.cloud_runtime import ConnectorIngestServer


def main() -> int:
    ORG = "acme-corp"
    NODE_ID = "agent-node-01"
    INSTANCE_ID = "aws-prod-01"
    AGENT_ID = "premium-agent-01"

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        # ---- 1. Control plane: issue a license, serve activation over HTTP ----
        cp = ControlPlane(root / "control-plane-state")
        issued = cp.issue_license(ORG, "enterprise", duration_days=365, max_nodes=1, max_agents=5)
        cp_server = ControlPlaneServer(cp, port=0)
        cp_server.start()
        try:
            import urllib.request
            pub = json.loads(
                urllib.request.urlopen(f"http://127.0.0.1:{cp_server.port}/v1/public-key", timeout=5).read()
            )["public_key_pem"].encode()
            act_req = urllib.request.Request(
                f"http://127.0.0.1:{cp_server.port}/v1/activate",
                data=json.dumps({
                    "api_key": issued["api_key"], "node_id": NODE_ID,
                    "instance_id": INSTANCE_ID, "agent_id": AGENT_ID,
                }).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            signed_obj = json.loads(urllib.request.urlopen(act_req, timeout=5).read())
        finally:
            cp_server.stop()

        signed = SignedEntitlement(payload=signed_obj["payload"], signature=signed_obj["signature"])
        entitlement = verify_entitlement(signed, pub, organization_id=ORG, node_id=NODE_ID)
        assert entitlement.license_id == issued["license_id"]
        print(f"[control-plane] activated license={entitlement.license_id} node={NODE_ID}: OK")

        # ---- 2. Edge: build the licensed, production MVP ----
        master = hashlib.sha256(b"atl-dev-only-not-for-production").digest()
        node_key_bytes = node_key(master, NODE_ID)
        crypto = PackageCrypto.from_master(master, NODE_ID, key_id="node-v1")
        audit = OnPremAuditLog(root / "audit.jsonl")
        dp = LocalDataPlane(crypto, audit)
        catalog = DataCatalog()
        catalog.register(DataAsset(
            asset_id="crm", name="CRM", sensitivity=Sensitivity.INTERNAL,
            fields={"customer_id": Sensitivity.INTERNAL, "status": Sensitivity.PUBLIC},
        ))
        # "customer_id" trips the catalog's conservative "customer" field-name
        # hint and reclassifies upward to CONFIDENTIAL even though the asset
        # itself was registered as INTERNAL (see src/data_catalog.py) — the
        # classifier never downgrades, so the node policy has to allow for it.
        access = NodeAccessPolicy(node_id=NODE_ID, allowed_assets=("crm",), max_sensitivity=Sensitivity.CONFIDENTIAL)
        gate = ProposalGate(default_proposal_policy())

        mvp = ATLDataPlaneMVP.production(gate, dp, entitlement, catalog=catalog, node_access=access)
        print("[edge] ATLDataPlaneMVP.production() constructed with enforced license: OK")

        proposal = {
            "schema_version": 1, "tool": "lookup", "operation": "read", "resource": "crm",
            "fields": ["customer_id", "status"], "arguments": {"status": "active"},
        }
        records = [{"customer_id": i, "status": "active"} for i in range(10)]
        execution = mvp.execute_and_issue(
            proposal, records, executor=lambda p: "executed",
            fields=["customer_id", "status"], request_id="e2e-req-1",
        )
        assert execution.executor_result == "executed"
        assert execution.issue.header.license_id == entitlement.license_id
        assert execution.issue.header.result_manifest_hash.startswith("sha256:")
        print("[edge] proposal executed + package sealed, license/manifest bound in header: OK")

        # ---- 3. Edge: deposit sealed package into the on-disk Outbox ----
        outbox = Outbox(root / "outbox")
        entry = outbox.deposit(
            NODE_ID, execution.issue.header.request_id, execution.issue.package,
            policy_id=execution.issue.header.policy_id, expiry=execution.issue.header.expiry,
        )
        assert outbox.list_ready(NODE_ID) == [entry]
        print(f"[edge] package deposited to outbox: {entry.package_bytes} bytes, request_id={entry.request_id}")

        # ---- 4. Cloud Connector: start on the "premium agent instance" ----
        received = []

        def agent_handler(node_id: str, request_id: str, plaintext: dict) -> None:
            received.append((node_id, request_id, plaintext))

        connector = ConnectorIngestServer(NODE_ID, node_key_bytes.hex(), agent_handler, port=0)
        connector.start()
        try:
            connector_url = f"http://127.0.0.1:{connector.port}"

            # ---- 5. Authenticated transport push, Edge -> Connector ----
            results = push_ready(outbox, NODE_ID, connector_url, node_key_bytes,
                                  archive_root=root / "outbox-archive")
            assert len(results) == 1 and results[0].delivered and results[0].status == 200
            print("[transport] HMAC-signed push delivered, 200 ACCEPTED: OK")

            assert outbox.list_ready(NODE_ID) == []
            print("[edge] outbox emptied after successful delivery: OK")

            assert len(received) == 1
            got_node, got_rid, plaintext = received[0]
            assert got_rid == "e2e-req-1"
            assert plaintext["n_out"] == 10
            print(f"[connector->agent] decrypted payload delivered to premium agent handler, n_out={plaintext['n_out']}: OK")
        finally:
            connector.stop()

        print()
        print("=" * 72)
        print("FULL-STACK E2E: control-plane -> licensed MVP -> outbox -> transport -> connector -> agent : PASS")
        print("=" * 72)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
