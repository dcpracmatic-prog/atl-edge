#!/usr/bin/env python3
"""Reference Control Plane: issuance, HTTP activation, max_nodes enforcement,
revocation, and tamper detection on a forwarded entitlement."""
from __future__ import annotations

import json
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.control_plane import ControlPlane, LicenseError
from src.control_plane_server import ControlPlaneServer
from src.licensing import SignedEntitlement, verify_entitlement


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        cp = ControlPlane(Path(td) / "state")
        issued = cp.issue_license("acme-corp", "enterprise", duration_days=365, max_nodes=1, max_agents=5)
        print("license issued:", issued["license_id"])

        server = ControlPlaneServer(cp, port=0)
        server.start()
        try:
            base = f"http://127.0.0.1:{server.port}"
            pub = json.loads(urllib.request.urlopen(base + "/v1/public-key", timeout=5).read())["public_key_pem"].encode()

            def activate(node_id: str) -> dict:
                req = urllib.request.Request(
                    base + "/v1/activate",
                    data=json.dumps({"api_key": issued["api_key"], "node_id": node_id,
                                      "instance_id": f"inst-{node_id}", "agent_id": "agent-01"}).encode(),
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                return json.loads(urllib.request.urlopen(req, timeout=5).read())

            signed_obj = activate("node-1")
            signed = SignedEntitlement(payload=signed_obj["payload"], signature=signed_obj["signature"])
            ent = verify_entitlement(signed, pub, organization_id="acme-corp", node_id="node-1")
            assert ent.license_id == issued["license_id"]
            print("HTTP activation for node-1: OK")

            # Re-activating the SAME node is idempotent.
            activate("node-1")
            print("re-activation of the same node is idempotent: OK")

            # A SECOND, different node must be rejected (max_nodes=1).
            try:
                activate("node-2")
                print("FAIL: second node was accepted despite max_nodes=1")
                return 1
            except urllib.error.HTTPError as exc:
                assert exc.code == 403, exc.code
            print("second node rejected once max_nodes exceeded: OK")

            # Tamper the payload after receiving it over the wire: signature must fail.
            tampered = dict(signed.payload)
            tampered["plan"] = "free"
            try:
                verify_entitlement(SignedEntitlement(payload=tampered, signature=signed.signature), pub)
                print("FAIL: tampered entitlement verified")
                return 1
            except ValueError:
                print("tampered entitlement (plan swapped) rejected by signature check: OK")
        finally:
            server.stop()

        # Revocation must block subsequent activations even with the same valid key.
        cp.revoke_license(issued["license_id"])
        try:
            cp.activate(issued["api_key"], node_id="node-1", instance_id="inst-node-1", agent_id="agent-01")
            print("FAIL: revoked license still activated")
            return 1
        except LicenseError as exc:
            assert "revoked" in str(exc)
        print("revoked license rejected on activate(): OK")

        # ---- Concurrency: race N threads for a license with max_nodes=1 ----
        # This is the exact race the SQLite BEGIN IMMEDIATE transaction in
        # ControlPlane.activate() exists to close: read-count-then-insert
        # done as two separate steps would let more than one thread observe
        # count < max_nodes and both insert.
        import threading
        race_cp = ControlPlane(Path(td) / "race-state")
        race_issued = race_cp.issue_license("race-corp", "pro", max_nodes=1, max_agents=1)
        outcomes: list[bool] = []
        outcomes_lock = threading.Lock()

        def try_activate(node_id: str) -> None:
            try:
                race_cp.activate(race_issued["api_key"], node_id=node_id,
                                  instance_id=f"inst-{node_id}", agent_id="agent-01")
                ok = True
            except LicenseError:
                ok = False
            with outcomes_lock:
                outcomes.append(ok)

        threads = [threading.Thread(target=try_activate, args=(f"race-node-{i}",)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        succeeded = sum(1 for o in outcomes if o)
        summary = race_cp.get_license(race_issued["license_id"])
        assert succeeded == 1, f"expected exactly 1 winner, got {succeeded}"
        assert summary.node_count == 1, f"max_nodes=1 must hold under concurrency, got {summary.node_count}"
        print(f"concurrent activation race (20 threads, max_nodes=1): exactly 1 winner, node_count={summary.node_count}: OK")

        print()
        print("control_plane selftest: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
