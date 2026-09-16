"""Canonical ATL MVP orchestration path.

Flow for local Llama / on-prem agent → premium/cloud agent packages:

1. **Proposal Schema + MORPH-8 + policy** (`ProposalGate`): structural validation
   of the *proposal* the local agent wants to execute — tools allowlist, action
   policy, causal graph, rejection of control/dangerous fields. This is the
   gate on *what the agent is allowed to ask for*, not a SQL sandbox.
2. **Data authorization** (`authorize_request`): optional catalog + node policy
   on requested fields / sensitivity.
3. **Executor** only after gate + data auth accept.
4. **Predigest** projects records to the requested field list (minimum useful
   payload), then **ATLP** seals the package for the connector.

MORPH does not by itself strip record columns; field minimization is the
proposal `fields` / caller `fields` contract applied in `predigest_records`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Sequence
import threading
import uuid

from .data_plane import LocalDataPlane, LocalIssueResult
from .proposal_gate import GateResult, ProposalGate
from .data_catalog import DataCatalog, NodeAccessPolicy, authorize_request
from .result_packaging import ResultManifest, package_requested_fields
from .licensing import Entitlement
from .execution_ledger import ExecutionLedger, LedgerError


@dataclass(frozen=True)
class MVPExecution:
    gate: GateResult
    issue: Optional[LocalIssueResult]
    executor_result: Any = None


class ATLDataPlaneMVP:
    """Single canonical orchestration seam for the current MVP."""

    def __init__(self, gate: ProposalGate, data_plane: LocalDataPlane, *,
                 catalog: Optional[DataCatalog] = None,
                 node_access: Optional[NodeAccessPolicy] = None,
                 entitlement: Optional[Entitlement] = None,
                 require_license: bool = False,
                 require_fields: bool = False,
                 ledger_path: str | None = None):
        self.gate = gate
        self.data_plane = data_plane
        self.catalog = catalog
        self.node_access = node_access
        self.entitlement = entitlement
        self.require_license = require_license
        self.require_fields = require_fields
        self.ledger = ExecutionLedger(ledger_path)
        self._execution_lock = threading.RLock()
        # Fail-fast: a misconfigured license requirement must not surface as a
        # per-request PermissionError deep in the hot path. If licensing is
        # required, the entitlement/capability/node binding are validated once
        # here, at construction time, so a bad boot configuration is loud.
        if self.require_license:
            self._check_license()

    @classmethod
    def production(
        cls,
        gate: ProposalGate,
        data_plane: LocalDataPlane,
        entitlement: Entitlement,
        *,
        catalog: Optional[DataCatalog] = None,
        node_access: Optional[NodeAccessPolicy] = None,
        ledger_path: str | None = None,
    ) -> "ATLDataPlaneMVP":
        """Construct an MVP instance with licensing enforced.

        This is the intended production entry point: it always requires a
        valid, capability-matching, node-bound entitlement. Use the plain
        constructor (require_license=False) only for local dev/test wiring.
        """
        return cls(
            gate, data_plane, catalog=catalog, node_access=node_access,
            entitlement=entitlement, require_license=True, require_fields=True,
            ledger_path=ledger_path,
        )

    def _check_license(self) -> None:
        import time
        if self.entitlement is None:
            raise PermissionError("license required")
        if "agent_access" not in self.entitlement.capabilities:
            raise PermissionError("license capability denied")
        if self.entitlement.node_id and self.data_plane.crypto.node_id != self.entitlement.node_id:
            raise PermissionError("license node mismatch")
        now = time.time()
        if now < float(self.entitlement.issued_at):
            raise PermissionError("license not yet active")
        if now >= float(self.entitlement.expires_at):
            raise PermissionError("license expired")

    def execute_and_issue(
        self,
        proposal: Mapping[str, Any],
        records: Sequence[Dict[str, Any]],
        *,
        executor: Callable[[Dict[str, Any]], Any],
        requester: str = "local-agent",
        purpose: str = "premium-agent-task",
        ttl_seconds: int = 120,
        fields: Optional[Sequence[str]] = None,
        request_id: Optional[str] = None,
    ) -> MVPExecution:
        # A caller-supplied request_id is the idempotency boundary. Generate one
        # before execution so it is the same identity for execution + ATLP.
        rid = request_id or str(uuid.uuid4())
        try:
            self.ledger.reserve(rid)
        except LedgerError as exc:
            raise PermissionError(str(exc)) from exc
        executed = False
        try:
            if self.require_license:
                self._check_license()

            # Gate first: MORPH + execution policy must accept before any side effect.
            gate = self.gate.check(proposal)
            if not gate.allowed:
                raise PermissionError(f"proposal rejected: {gate.reason}")

            # The requested-fields contract is independent of whether the
            # optional classification/access layer is enabled: it always
            # comes from the caller-supplied `fields` or the proposal itself,
            # so the ATLP result-manifest binding below is always available.
            requested_fields = tuple(fields or gate.proposal.get("fields") or ())
            if self.require_fields and not requested_fields:
                raise PermissionError(
                    "fields required: declare proposal.fields or pass fields= "
                    "so predigest projects the minimum useful columns"
                )

            # Optional local data classification/access layer. `resource` is the
            # canonical asset identifier in the proposal schema. Classification
            # may raise a declared class when a value detector finds sensitive
            # content; it never downgrades data.
            if self.catalog is not None and self.node_access is not None:
                asset_id = str(gate.proposal.get("resource") or "")
                sample = records[0] if records else None
                decision = authorize_request(
                    self.catalog, self.node_access, asset_id, requested_fields, sample
                )
                if not decision.allowed:
                    raise PermissionError(f"data access rejected: {decision.reason}")
            else:
                decision = None

            # Only after both proposal and data classification/access checks pass
            # is the business executor allowed to run.
            manifest_hash = ""
            if requested_fields and records:
                # Bind the requested field contract into the encrypted header.
                # The values remain in the normal predigest payload; the manifest
                # hash makes the ordering/minimization contract authenticated.
                manifest, _ = package_requested_fields(rid, requested_fields, records[0])
                manifest_hash = manifest.manifest_hash

            exec_result = executor(gate.proposal)
            # Durable: executor ran — never allow a retry to run it again.
            self.ledger.mark_executed(rid)
            executed = True

            # Predigest MUST use the same field contract as authorization/manifest:
            # caller `fields` override, else proposal["fields"]. Empty means
            # "no field projection" (full records) — document operationally.
            issue_fields = list(requested_fields) if requested_fields else None
            issue = self.data_plane.issue_for_agent(
                records,
                policy_id=gate.policy_id,
                ttl_seconds=ttl_seconds,
                fields=issue_fields,
                requester=requester,
                purpose=purpose,
                request_id=rid,
                policy_hash=gate.policy_hash,
                proposal_hash=gate.proposal_hash,
                result_manifest_hash=manifest_hash,
                license_id=self.entitlement.license_id if self.entitlement else "",
            )
            if decision is not None:
                issue.metrics.update({
                    "asset_id": decision.asset_id,
                    "effective_sensitivity": decision.effective_level.name.lower(),
                    "protection_profile": decision.protection_profile,
                    "classification_gate": "ENFORCED",
                })
            self.ledger.mark_completed(rid)
            return MVPExecution(gate=gate, issue=issue, executor_result=exec_result)
        except Exception:
            if not executed:
                # Safe to drop reservation so a full retry can be attempted.
                self.ledger.release_reservation(rid)
            raise
