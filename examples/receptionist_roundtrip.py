#!/usr/bin/env python3
"""Intent → template → execute_and_issue → open_package. Minimización real."""
from __future__ import annotations
import hashlib, json, tempfile
from pathlib import Path
from src.proposer import propose
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.data_plane import CloudDecryptConnector, LocalDataPlane, OnPremAuditLog, PackageCrypto
from src.mvp import ATLDataPlaneMVP
from src.data_catalog import DataAsset, DataCatalog, NodeAccessPolicy, Sensitivity
from src.morph8 import MorphGate

FORBIDDEN = {"email", "notes", "correo"}
INTENTS = [
    "Lista clientes activos en México: solo id, región y status.",
    "Resume cuántos clientes hay por región (solo conteo, campos id y region).",
    "Valida que status sea active o paused; no leas notas.",
    "Normaliza region a MX/US y devuelve id y region.",
    "JSON por favor: lookup read crm fields id region status limit 20.",
]

def main() -> int:
    master = hashlib.sha256(b"receptionist-roundtrip").digest()
    crypto = PackageCrypto.from_master(master, "eval-node", key_id="v1")
    with tempfile.TemporaryDirectory() as td:
        dp = LocalDataPlane(crypto, OnPremAuditLog(Path(td) / "a.jsonl"))
        cat = DataCatalog()
        cat.register(DataAsset(
            asset_id="crm", name="CRM", sensitivity=Sensitivity.INTERNAL,
            fields={"id": Sensitivity.INTERNAL, "region": Sensitivity.PUBLIC,
                    "status": Sensitivity.PUBLIC, "email": Sensitivity.CONFIDENTIAL,
                    "notes": Sensitivity.SENSITIVE},
        ))
        app = ATLDataPlaneMVP(
            ProposalGate(default_proposal_policy(), MorphGate()), dp,
            catalog=cat,
            node_access=NodeAccessPolicy(node_id="eval-node", allowed_assets=("crm",),
                                         max_sensitivity=Sensitivity.INTERNAL),
            require_fields=True,
        )
        records = [{"id": i, "region": "MX", "status": "active",
                    "email": "x@y.invalid", "notes": "secreto"} for i in range(40)]
        conn = CloudDecryptConnector(crypto)
        naive = len(json.dumps(records))
        for i, intent in enumerate(INTENTS):
            prop = propose(intent, backend="template")
            allowed = set(prop["fields"])
            ev = app.execute_and_issue(
                prop, records, executor=lambda p: {"ok": True},
                fields=prop["fields"], request_id=f"rt-{i}",
            )
            opened = conn.open_package(ev.issue.package)
            assert ev.gate.allowed, (intent, ev.gate)
            assert opened["n_out"] >= 1, opened
            rows = opened["rows"]
            keys = {k for r in rows if isinstance(r, dict) for k in r}
            leak = keys & FORBIDDEN
            extra = keys - allowed
            assert not leak, (intent, leak)
            assert not extra, (intent, extra, allowed)
            print(f"OK {i} fields={prop['fields']} n_out={opened['n_out']} naive={naive}")
    print("receptionist_roundtrip: PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
