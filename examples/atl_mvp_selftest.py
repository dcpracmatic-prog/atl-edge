#!/usr/bin/env python3
"""End-to-end deterministic MVP check: Proposal -> MORPH -> execute -> ATLP."""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from src.data_plane import CloudDecryptConnector, LocalDataPlane, OnPremAuditLog, PackageCrypto
from src.morph8 import MorphGate
from src.mvp import ATLDataPlaneMVP
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.data_catalog import DataAsset, DataCatalog, NodeAccessPolicy, Sensitivity


def main() -> int:
    policy = default_proposal_policy()
    gate = ProposalGate(policy, MorphGate())
    master = hashlib.sha256(b"atl-dev-only-not-for-production").digest()
    crypto = PackageCrypto.from_master(master, "mvp-node", key_id="mvp-v1")
    with tempfile.TemporaryDirectory() as td:
        audit = OnPremAuditLog(Path(td) / "audit.jsonl")
        dp = LocalDataPlane(crypto, audit)
        catalog = DataCatalog()
        catalog.register(DataAsset(
            asset_id="crm", name="CRM", sensitivity=Sensitivity.INTERNAL,
            fields={"id": Sensitivity.INTERNAL, "region": Sensitivity.PUBLIC, "status": Sensitivity.PUBLIC}
        ))
        access = NodeAccessPolicy(
            node_id="mvp-node", allowed_assets=("crm",), max_sensitivity=Sensitivity.INTERNAL
        )
        app = ATLDataPlaneMVP(gate, dp, catalog=catalog, node_access=access)
        records = [{"id": i, "region": "MX", "status": "active", "noise": "x" * 100} for i in range(20)]
        calls = []

        good = {"schema_version": 1, "tool": "lookup", "operation": "read", "resource": "crm", "fields": ["id", "region", "status"], "arguments": {"status": "active"}}
        r1 = app.execute_and_issue(
            good, records, executor=lambda p: calls.append(p) or "executed",
            fields=["id", "region", "status"], request_id="mvp-good",
        )
        assert r1.gate.allowed and r1.gate.decision == "ACCEPT"
        assert r1.executor_result == "executed" and len(calls) == 1
        assert r1.issue.metrics["classification_gate"] == "ENFORCED"
        assert r1.issue.metrics["protection_profile"] == "FAST_LOCAL"
        connector = CloudDecryptConnector(crypto)
        opened = connector.open_package(r1.issue.package)
        assert opened["n_out"] == 20

        bad = {"schema_version": 1, "tool": "lookup", "operation": "read", "action": "delete", "arguments": {}}
        before = len(calls)
        try:
            app.execute_and_issue(bad, records, executor=lambda p: calls.append(p) or "SHOULD-NOT-RUN")
            raise AssertionError("rejected proposal executed")
        except PermissionError:
            pass
        assert len(calls) == before, "executor was called after MORPH rejection"

        # Semantic authorization: operation and dangerous arguments are policy-gated,
        # not merely checked by tool name.
        for malicious in (
            {"schema_version": 1, "tool": "lookup", "operation": "delete", "arguments": {}},
            {"schema_version": 1, "tool": "lookup", "operation": "read", "arguments": {"command": "rm -rf /"}},
            {"schema_version": 1, "tool": "lookup", "operation": "read", "arguments": {}, "limit": 1000},
        ):
            before = len(calls)
            try:
                app.execute_and_issue(malicious, records, executor=lambda p: calls.append(p) or "SHOULD-NOT-RUN")
                raise AssertionError("semantic policy bypass")
            except PermissionError:
                pass
            assert len(calls) == before

        # Data classification must run before the business executor. A node with
        # only confidential clearance cannot retrieve a sensitive payroll field.
        sensitive_catalog = DataCatalog()
        sensitive_catalog.register(DataAsset(
            asset_id="payroll", name="Payroll", sensitivity=Sensitivity.CONFIDENTIAL,
            fields={"salary": Sensitivity.SENSITIVE}
        ))
        restricted_app = ATLDataPlaneMVP(
            gate, dp, catalog=sensitive_catalog,
            node_access=NodeAccessPolicy(node_id="mvp-node", allowed_assets=("payroll",), max_sensitivity=Sensitivity.CONFIDENTIAL),
        )
        sensitive_proposal = {"schema_version": 1, "tool": "lookup", "operation": "read", "resource": "payroll", "fields": ["salary"], "arguments": {}}
        before = len(calls)
        try:
            restricted_app.execute_and_issue(sensitive_proposal, [{"salary": 5580}], executor=lambda p: calls.append(p) or "SHOULD-NOT-RUN")
            raise AssertionError("sensitive data bypass")
        except PermissionError as exc:
            assert "sensitivity_exceeds_node_policy" in str(exc)
        assert len(calls) == before, "executor ran before data authorization"

        # Idempotency: the same request_id cannot execute twice through the canonical seam.
        rid = "idempotency-test"
        app.execute_and_issue(good, records, executor=lambda p: calls.append(p) or "executed", request_id=rid)
        before = len(calls)
        try:
            app.execute_and_issue(good, records, executor=lambda p: calls.append(p) or "SHOULD-NOT-RUN", request_id=rid)
            raise AssertionError("duplicate request_id executed")
        except PermissionError:
            pass
        assert len(calls) == before

        # Audit chain is tamper-evident and the ATLP header carries the policy/proposal linkage.
        assert audit.verify()
        assert r1.issue.header.policy_hash == r1.gate.policy_hash
        assert r1.issue.header.proposal_hash == r1.gate.proposal_hash
        assert r1.issue.header.principal_id == "local-agent"

        # Production connector path consumes only a provisioned node key.
        node_key = __import__("src.data_plane", fromlist=["node_key"]).node_key(master, "mvp-node")
        node_connector = CloudDecryptConnector.from_node_key(node_key, "mvp-node", key_id="mvp-v1")
        assert node_connector.open_package(r1.issue.package)["n_out"] == 20

        # Determinism: same proposal and policy produce same gate decision/masks.
        a = gate.check(good)
        b = gate.check(good)
        assert a == b

        print("proposal=ACCEPT executor=CALLED")
        print("proposal=REJECT executor=BLOCKED")
        print("morph=DETERMINISTIC")
        print("predigest=LOCAL")
        print("atlp=SEALED+OPEN")
        print("audit=ON_PREM")
        print("MVP integration selftest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
