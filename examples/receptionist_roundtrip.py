#!/usr/bin/env python3
"""Receptionist NL → propose(template) → execute_and_issue → open_package roundtrip."""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from src.data_plane import CloudDecryptConnector, LocalDataPlane, OnPremAuditLog, PackageCrypto
from src.morph8 import MorphGate
from src.mvp import ATLDataPlaneMVP
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.proposer import propose


def main() -> int:
    policy = default_proposal_policy()
    gate = ProposalGate(policy, MorphGate())
    master = hashlib.sha256(b"atl-receptionist-roundtrip").digest()
    crypto = PackageCrypto.from_master(master, "receptionist-node", key_id="recv-v1")
    with tempfile.TemporaryDirectory() as td:
        audit = OnPremAuditLog(Path(td) / "audit.jsonl")
        dp = LocalDataPlane(crypto, audit)
        app = ATLDataPlaneMVP(gate, dp)

        proposal = propose(
            "Lista clientes activos en México: solo id, región y status.",
            backend="template",
        )
        assert proposal["tool"] == "lookup"
        assert proposal["resource"] == "crm"
        assert proposal["fields"] == ["id", "region", "status"]

        records = [
            {"id": 1, "region": "MX", "status": "active", "noise": "n"},
            {"id": 2, "region": "MX", "status": "active", "noise": "n"},
        ]
        calls = []
        execution = app.execute_and_issue(
            proposal,
            records,
            executor=lambda p: calls.append(p) or "ok",
            fields=proposal["fields"],
            request_id="receptionist-roundtrip-1",
        )
        assert execution.gate.allowed and calls and execution.executor_result == "ok"
        assert execution.issue is not None

        opened = CloudDecryptConnector(crypto).open_package(execution.issue.package)
        rows = opened["rows"]
        assert isinstance(rows, list) and len(rows) == 2
        assert all(set(r.keys()) <= {"id", "region", "status"} for r in rows)
        assert opened["n_out"] == 2

    print("receptionist_roundtrip: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
