"""Hardening v2.1 properties: ledger, max_agents, entitlement expiry, locks."""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))


def test_ledger_blocks_second_executor():
    from src.execution_ledger import ExecutionLedger, LedgerError

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "led.sqlite"
        led = ExecutionLedger(path)
        led.reserve("r1")
        led.mark_executed("r1")
        # simulate process restart
        led2 = ExecutionLedger(path)
        try:
            led2.reserve("r1")
            raise AssertionError("should block")
        except LedgerError as e:
            assert "executor already ran" in str(e)
        print("OK ledger survives restart / blocks second executor")


def test_max_agents_enforced():
    from src.control_plane import ControlPlane, LicenseError

    with tempfile.TemporaryDirectory() as td:
        cp = ControlPlane(Path(td) / "state")
        summary = cp.issue_license("org", "pro", duration_days=30, max_nodes=2, max_agents=1)
        api_key = summary["api_key"]
        cp.activate(api_key, node_id="n1", instance_id="i1", agent_id="agent-a")
        try:
            cp.activate(api_key, node_id="n1", instance_id="i1", agent_id="agent-b")
            raise AssertionError("second agent should fail")
        except LicenseError as e:
            assert "max_agents" in str(e)
        # same agent re-activate ok
        cp.activate(api_key, node_id="n1", instance_id="i2", agent_id="agent-a")
        print("OK max_agents enforced")


def test_entitlement_expiry_runtime():
    from src.mvp import ATLDataPlaneMVP
    from src.proposal_gate import ProposalGate, default_proposal_policy
    from src.data_plane import LocalDataPlane, PackageCrypto, OnPremAuditLog
    from src.licensing import Entitlement
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        crypto = PackageCrypto.from_master(b"0" * 32, "node-1")
        audit = OnPremAuditLog(Path(td) / "a.jsonl")
        dp = LocalDataPlane(crypto, audit)
        gate = ProposalGate(default_proposal_policy())
        ent = Entitlement(
            license_id="L",
            organization_id="O",
            plan="p",
            issued_at=time.time() - 100,
            expires_at=time.time() - 1,  # already expired
            capabilities=("agent_access",),
            node_id="node-1",
        )
        try:
            ATLDataPlaneMVP(
                gate, dp, entitlement=ent, require_license=True, require_fields=False,
                ledger_path=str(Path(td) / "led.sqlite"),
            )
            raise AssertionError("expired should fail at construct or execute")
        except PermissionError as e:
            assert "expired" in str(e)
        # Also verify hot-path check if instance was built with a still-valid window
        # then time is forced past expires_at inside _check_license.
        ent2 = Entitlement(
            license_id="L", organization_id="O", plan="p",
            issued_at=time.time() - 100,
            expires_at=time.time() + 60,
            capabilities=("agent_access",), node_id="node-1",
        )
        mvp = ATLDataPlaneMVP(
            gate, dp, entitlement=ent2, require_license=True, require_fields=False,
            ledger_path=str(Path(td) / "led2.sqlite"),
        )
        mvp.entitlement = Entitlement(
            license_id="L", organization_id="O", plan="p",
            issued_at=time.time() - 100,
            expires_at=time.time() - 1,
            capabilities=("agent_access",), node_id="node-1",
        )
        try:
            mvp.execute_and_issue(
                {"schema_version": 1, "tool": "lookup", "operation": "read",
                 "arguments": {}, "fields": ["customer_id"], "resource": "crm"},
                [{"customer_id": "1"}],
                executor=lambda p: {"ok": True},
                fields=["customer_id"],
                request_id="exp-1",
            )
            raise AssertionError("hot path should reject expired")
        except PermissionError as e:
            assert "expired" in str(e)
        print("OK entitlement expiry at construct and hot path")


def test_edge_requires_master_key():
    import importlib
    os.environ.pop("ATL_MASTER_KEY_HEX", None)
    os.environ.pop("ATL_ALLOW_DEV_DEFAULTS", None)
    os.environ.pop("ATL_ENTITLEMENT_EXPIRES_AT", None)
    from src import edge_api_server
    try:
        edge_api_server.default_runtime_from_env()
        raise AssertionError("should fail closed")
    except RuntimeError as e:
        assert "ATL_MASTER_KEY_HEX" in str(e) or "ATL_NODE_ID" in str(e)
    print("OK edge fail-closed without dev defaults")


def test_replay_and_nonce_locks_smoke():
    from src.data_plane import ReplayCache
    from src.transport import NonceCache
    import threading

    rc = ReplayCache()
    nc = NonceCache()
    errors = []

    def worker(i):
        try:
            rc.check_and_record(f"id-{i}", time.time() + 60)
            nc.check_and_record(f"n-{i}", time.time())
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    print("OK concurrent replay/nonce smoke")


if __name__ == "__main__":
    test_ledger_blocks_second_executor()
    test_max_agents_enforced()
    test_entitlement_expiry_runtime()
    test_edge_requires_master_key()
    test_replay_and_nonce_locks_smoke()
    print("ALL hardening v2.1 selftests passed")
