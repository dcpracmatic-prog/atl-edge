#!/usr/bin/env python3
"""TLS end to end: both HTTP surfaces (Control Plane, Cloud Connector) running
real TLS with a dev self-signed certificate — verified against that specific
cert (not `insecure_skip_verify`), plus a check that the two-flag insecure
escape hatch actually requires both flags."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.control_plane import ControlPlane
from src.control_plane_server import ControlPlaneServer
from src.data_plane import LocalDataPlane, OnPremAuditLog, PackageCrypto, node_key
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.dev_tls import client_context, generate_self_signed_cert
from src.file_workflow import Outbox
from src.transport import push_ready
from connector.cloud_runtime import ConnectorIngestServer


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        # ---- Control Plane over real TLS ----
        cert_path, key_path = generate_self_signed_cert("control-plane.test", root / "certs")
        cp = ControlPlane(root / "cp-state")
        issued = cp.issue_license("acme-corp", "enterprise", max_nodes=1, max_agents=1)
        cp_server = ControlPlaneServer(cp, port=0, tls_certfile=cert_path, tls_keyfile=key_path)
        cp_server.start()
        try:
            assert cp_server.url_scheme == "https"
            base = f"https://127.0.0.1:{cp_server.port}"

            # Plain HTTP client against an HTTPS-only server must fail outright.
            try:
                urllib.request.urlopen(base.replace("https", "http") + "/v1/public-key", timeout=5)
                print("FAIL: plaintext HTTP reached a TLS-only server")
                return 1
            except Exception:
                pass  # expected: connection reset / protocol error

            # Client trusting the SPECIFIC dev cert: succeeds and actually verifies.
            ctx = client_context(ca_path=cert_path)
            with urllib.request.urlopen(base + "/v1/public-key", timeout=5, context=ctx) as resp:
                pub = json.loads(resp.read())["public_key_pem"]
            assert "BEGIN PUBLIC KEY" in pub
            print("control plane over TLS, verified against the specific dev cert: OK")

            # Client with NO trust anchor for this self-signed cert must fail closed.
            import ssl
            default_ctx = ssl.create_default_context()
            try:
                urllib.request.urlopen(base + "/v1/public-key", timeout=5, context=default_ctx)
                print("FAIL: self-signed cert was accepted by default system trust store")
                return 1
            except urllib.error.URLError:
                print("self-signed cert correctly rejected by default trust store (no CA path given): OK")

            # Full activation over TLS.
            act_req = urllib.request.Request(
                base + "/v1/activate",
                data=json.dumps({"api_key": issued["api_key"], "node_id": "node-1",
                                  "instance_id": "inst-1", "agent_id": "agent-1"}).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(act_req, timeout=5, context=ctx) as resp:
                signed_obj = json.loads(resp.read())
            assert signed_obj["payload"]["license_id"] == issued["license_id"]
            print("activation over TLS: OK")
        finally:
            cp_server.stop()

        # ---- Cloud Connector over real TLS ----
        NODE_ID = "agent-node-01"
        master = hashlib.sha256(b"atl-dev-master").digest()
        node_key_bytes = node_key(master, NODE_ID)
        conn_cert, conn_key = generate_self_signed_cert("connector.test", root / "certs")

        received = []
        connector = ConnectorIngestServer(
            NODE_ID, node_key_bytes.hex(), lambda n, r, p: received.append((n, r, p)),
            port=0, tls_certfile=conn_cert, tls_keyfile=conn_key,
        )
        connector.start()
        try:
            assert connector.url_scheme == "https"
            crypto = PackageCrypto.from_master(master, NODE_ID, key_id="node-v1")
            gate = ProposalGate(default_proposal_policy())
            dp = LocalDataPlane(crypto, OnPremAuditLog(root / "audit.jsonl"), issue_auth_key=gate.issue_auth_key)
            outbox = Outbox(root / "outbox")
            def issue(records, *, policy_id, ttl_seconds, fields, request_id):
                checked = gate.check({"schema_version": 1, "tool": "lookup", "operation": "read", "fields": list(fields)})
                assert checked.allowed
                auth = gate.authorize_issue(checked, request_id=request_id, ttl_seconds=ttl_seconds, fields=fields)
                return dp.issue_for_agent(records, policy_id=checked.policy_id, ttl_seconds=ttl_seconds, fields=fields,
                                          request_id=request_id, policy_hash=checked.policy_hash,
                                          proposal_hash=checked.proposal_hash, authorization=auth)
            issued_pkg = issue([{"customer_id": 1}], policy_id="crm.read", ttl_seconds=30,
                                             fields=["customer_id"], request_id="tls-req-1")
            outbox.deposit(NODE_ID, issued_pkg.header.request_id, issued_pkg.package,
                            policy_id=issued_pkg.header.policy_id, expiry=issued_pkg.header.expiry)

            conn_ctx = client_context(ca_path=conn_cert)
            url = f"https://127.0.0.1:{connector.port}"
            results = push_ready(outbox, NODE_ID, url, node_key_bytes, ssl_context=conn_ctx,
                                  archive_root=root / "outbox-archive")
            assert len(results) == 1 and results[0].delivered
            assert len(received) == 1 and received[0][1] == "tls-req-1"
            print("Edge -> Connector push over TLS, verified: OK")
        finally:
            connector.stop()

        # ---- insecure_skip_verify requires the second, explicit flag ----
        try:
            client_context(insecure_skip_verify=True)  # allow_insecure defaults False
            print("FAIL: insecure_skip_verify worked without allow_insecure")
            return 1
        except ValueError:
            print("insecure_skip_verify correctly refused without allow_insecure=True: OK")

        print()
        print("tls selftest: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
