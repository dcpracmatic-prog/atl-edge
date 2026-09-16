"""Mandatory execution gate for ATL Proposal Schema v1.

The gate is intentionally stricter than MORPH alone: MORPH checks structural
validity and policy context, while this Python layer enforces semantic policy
on operations, arguments, resources and effects before an executor is called.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from .morph8 import MorphGate, MorphResult


@dataclass(frozen=True)
class ProposalPolicy:
    policy_id: str
    allow_tools: tuple[str, ...]
    allow_operations: tuple[str, ...] = ()
    allow_actions: tuple[str, ...] = ()
    deny_actions: tuple[str, ...] = ()
    deny_operations: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ("tool", "operation")
    deny_fields: tuple[str, ...] = ("shell", "exec", "command", "raw_sql", "sql_script")
    allowed_resources: tuple[str, ...] = ()
    allowed_fields: tuple[str, ...] = ()
    allowed_effects: tuple[str, ...] = ()
    deny_argument_keys: tuple[str, ...] = (
        "shell", "exec", "command", "raw_sql", "sql_script", "subprocess", "python",
    )
    max_argument_bytes: int = 8192
    max_limit: int = 100
    max_fields: int = 64
    max_effects: int = 32
    max_argument_depth: int = 16

    def to_morph_policy(self) -> str:
        lines = [f"allow_tool={x}" for x in self.allow_tools]
        lines += [f"allow_operation={x}" for x in self.allow_operations]
        lines += [f"allow_action={x}" for x in self.allow_actions]
        lines += [f"deny_action={x}" for x in self.deny_actions]
        lines += [f"deny_operation={x}" for x in self.deny_operations]
        lines += [f"require={x}" for x in self.required_fields]
        lines += [f"deny_field={x}" for x in self.deny_fields]
        return "\n".join(lines)

    def canonical_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "allow_tools": sorted(self.allow_tools),
            "allow_operations": sorted(self.allow_operations),
            "allow_actions": sorted(self.allow_actions),
            "deny_actions": sorted(self.deny_actions),
            "deny_operations": sorted(self.deny_operations),
            "required_fields": sorted(self.required_fields),
            "deny_fields": sorted(self.deny_fields),
            "allowed_resources": sorted(self.allowed_resources),
            "allowed_fields": sorted(self.allowed_fields),
            "allowed_effects": sorted(self.allowed_effects),
            "deny_argument_keys": sorted(self.deny_argument_keys),
            "max_argument_bytes": self.max_argument_bytes,
            "max_limit": self.max_limit,
            "max_fields": self.max_fields,
            "max_effects": self.max_effects,
            "max_argument_depth": self.max_argument_depth,
        }

    @property
    def policy_hash(self) -> str:
        blob = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return "sha256:" + hashlib.sha256(blob).hexdigest()


def default_proposal_policy() -> ProposalPolicy:
    return ProposalPolicy(
        policy_id="proposal.v1.default",
        allow_tools=("lookup", "normalize", "validate", "publish"),
        allow_operations=("read", "normalize", "validate", "publish"),
        allow_actions=("read", "transform", "validate", "publish"),
        deny_actions=("delete", "drop", "truncate", "exec", "shell"),
        deny_operations=("delete", "drop", "truncate", "exec", "shell"),
        allowed_effects=("read", "transform", "validate", "publish"),
    )


class ProposalSchemaError(ValueError):
    pass


def _str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProposalSchemaError(f"{name} must be a non-empty string")
    return value


def validate_proposal_schema(proposal: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(proposal, Mapping):
        raise ProposalSchemaError("proposal must be an object")
    allowed = {"schema_version", "tool", "operation", "arguments", "action", "resource", "fields", "limit", "steps", "effects", "metadata"}
    unknown = set(proposal) - allowed
    if unknown:
        raise ProposalSchemaError(f"unknown fields: {sorted(unknown)}")
    if proposal.get("schema_version", 1) != 1:
        raise ProposalSchemaError("schema_version must be 1")
    tool = _str(proposal.get("tool"), "tool")
    operation = _str(proposal.get("operation"), "operation")
    args = proposal.get("arguments", {})
    if not isinstance(args, Mapping):
        raise ProposalSchemaError("arguments must be an object")
    if "action" in proposal:
        _str(proposal["action"], "action")
    if "resource" in proposal:
        _str(proposal["resource"], "resource")
    if "fields" in proposal:
        f = proposal["fields"]
        if not isinstance(f, list) or any(not isinstance(x, str) or not x.strip() for x in f):
            raise ProposalSchemaError("fields must be a list of strings")
    if "limit" in proposal:
        if not isinstance(proposal["limit"], int) or isinstance(proposal["limit"], bool) or proposal["limit"] < 1:
            raise ProposalSchemaError("limit must be a positive integer")
    effects = proposal.get("effects", [])
    if not isinstance(effects, list) or len(effects) > 32 or any(not isinstance(x, str) or not x.strip() for x in effects):
        raise ProposalSchemaError("effects must be a list of <=32 strings")
    steps = proposal.get("steps", [])
    if not isinstance(steps, list) or len(steps) > 128:
        raise ProposalSchemaError("steps must be a list with <=128 items")
    ids = set()
    normalized_steps = []
    for st in steps:
        if not isinstance(st, Mapping):
            raise ProposalSchemaError("each step must be an object")
        allowed_step = {"id", "tool", "operation", "arguments", "action", "resource", "fields", "limit", "depends_on", "effects"}
        extra = set(st) - allowed_step
        if extra:
            raise ProposalSchemaError(f"unknown step fields: {sorted(extra)}")
        sid = _str(st.get("id"), "step.id")
        if sid in ids:
            raise ProposalSchemaError(f"duplicate step id: {sid}")
        ids.add(sid)
        _str(st.get("tool"), "step.tool")
        _str(st.get("operation"), "step.operation")
        st_args = st.get("arguments", {})
        if not isinstance(st_args, Mapping):
            raise ProposalSchemaError("step.arguments must be an object")
        if "action" in st:
            _str(st["action"], "step.action")
        if "resource" in st:
            _str(st["resource"], "step.resource")
        if "fields" in st:
            if not isinstance(st["fields"], list) or len(st["fields"]) > 64 or any(not isinstance(x, str) or not x.strip() for x in st["fields"]):
                raise ProposalSchemaError("step.fields must be a list of <=64 strings")
        if "limit" in st and (not isinstance(st["limit"], int) or isinstance(st["limit"], bool) or st["limit"] < 1):
            raise ProposalSchemaError("step.limit must be a positive integer")
        step_effects = st.get("effects", [])
        if not isinstance(step_effects, list) or len(step_effects) > 32 or any(not isinstance(x, str) or not x.strip() for x in step_effects):
            raise ProposalSchemaError("step.effects must be a list of <=32 strings")
        deps = st.get("depends_on", [])
        if not isinstance(deps, list) or len(deps) > 32 or any(not isinstance(x, str) or not x for x in deps):
            raise ProposalSchemaError("step.depends_on must be a list of <=32 strings")
        st_out = dict(st)
        st_out.update(id=sid, tool=_str(st.get("tool"), "step.tool"), operation=_str(st.get("operation"), "step.operation"), arguments=dict(st_args), depends_on=list(deps))
        normalized_steps.append(st_out)
    for st in normalized_steps:
        missing = set(st["depends_on"]) - ids
        if missing:
            raise ProposalSchemaError(f"missing dependencies: {sorted(missing)}")
    out = dict(proposal)
    out.update(schema_version=1, tool=tool, operation=operation, arguments=dict(args), steps=normalized_steps, effects=list(effects))
    return out


def _canonical_hash(obj: Mapping[str, Any]) -> str:
    blob = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class IssueAuthorization:
    """Short-lived capability authorizing exactly one ATLP issuance.

    The token is MACed with a process-local secret shared only by the
    canonical ProposalGate and LocalDataPlane. It binds the request identity
    and proposal/policy hashes, preventing raw DataPlane issuance from
    bypassing the gate contract.
    """
    request_id: str
    policy_id: str
    policy_hash: str
    proposal_hash: str
    ttl_seconds: int
    fields_hash: str
    expires_at: float
    signature: str


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    decision: str
    proposal: Dict[str, Any]
    morph: Optional[MorphResult]
    reason: str
    policy_id: str
    policy_hash: str
    proposal_hash: str


class ProposalGate:
    def __init__(self, policy: ProposalPolicy, morph: Optional[MorphGate] = None, *, issue_auth_key: Optional[bytes] = None):
        self.policy = policy
        self.morph = morph or MorphGate()
        self._issue_auth_key = issue_auth_key or os.urandom(32)
        if len(self._issue_auth_key) < 32:
            raise ValueError("issue_auth_key must be at least 32 bytes")

    @property
    def issue_auth_key(self) -> bytes:
        """Opaque process-local key used to bind the Data Plane to this gate."""
        return self._issue_auth_key

    def authorize_issue(
        self,
        result: "GateResult",
        *,
        request_id: str,
        ttl_seconds: int,
        fields: Optional[Sequence[str]] = None,
        now: Optional[float] = None,
    ) -> IssueAuthorization:
        if not result.allowed:
            raise PermissionError("cannot authorize rejected proposal")
        if not isinstance(request_id, str) or not request_id.strip():
            raise ValueError("request_id required")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        field_values = tuple(fields or result.proposal.get("fields") or ())
        fields_blob = json.dumps(field_values, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        fields_hash = hashlib.sha256(fields_blob).hexdigest()
        expires_at = (time.time() if now is None else now) + ttl_seconds
        payload = {
            "request_id": request_id, "policy_id": result.policy_id,
            "policy_hash": result.policy_hash, "proposal_hash": result.proposal_hash,
            "ttl_seconds": ttl_seconds, "fields_hash": fields_hash,
            "expires_at": expires_at,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(self._issue_auth_key, blob, hashlib.sha256).hexdigest()
        return IssueAuthorization(signature=signature, **payload)

    def _semantic_policy_check(self, proposal: Dict[str, Any]) -> Optional[str]:
        p = self.policy
        if proposal["operation"] in p.deny_operations:
            return f"operation_denied:{proposal['operation']}"
        if p.allow_operations and proposal["operation"] not in p.allow_operations:
            return f"operation_not_allowed:{proposal['operation']}"
        if "action" in proposal:
            action = proposal["action"]
            if action in p.deny_actions:
                return f"action_denied:{action}"
            if p.allow_actions and action not in p.allow_actions:
                return f"action_not_allowed:{action}"
        if p.allowed_resources and proposal.get("resource") not in p.allowed_resources:
            return "resource_not_allowed"
        if p.allowed_fields and "fields" in proposal:
            bad = set(proposal["fields"]) - set(p.allowed_fields)
            if bad:
                return f"fields_not_allowed:{sorted(bad)}"
        if p.allowed_effects:
            bad = set(proposal.get("effects", [])) - set(p.allowed_effects)
            if bad:
                return f"effects_not_allowed:{sorted(bad)}"
        def inspect_arguments(args: Mapping[str, Any], label: str) -> Optional[str]:
            arg_blob = json.dumps(args, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(arg_blob) > p.max_argument_bytes:
                return f"{label}_arguments_too_large"
            bad_keys = set()
            too_deep = False
            def walk(x: Any, depth: int = 0) -> None:
                nonlocal too_deep
                if depth > p.max_argument_depth:
                    too_deep = True
                    return
                if isinstance(x, Mapping):
                    for k, v in x.items():
                        if str(k).lower() in p.deny_argument_keys:
                            bad_keys.add(str(k))
                        walk(v, depth + 1)
                elif isinstance(x, list):
                    for v in x:
                        walk(v, depth + 1)
            walk(args)
            if too_deep:
                return f"{label}_argument_depth_exceeded"
            if bad_keys:
                return f"dangerous_{label}_argument_keys:{sorted(bad_keys)}"
            return None

        argument_error = inspect_arguments(proposal["arguments"], "proposal")
        if argument_error:
            return argument_error
        if len(proposal.get("fields", [])) > p.max_fields:
            return "fields_too_many"
        if len(proposal.get("effects", [])) > p.max_effects:
            return "effects_too_many"
        if "limit" in proposal and proposal["limit"] > p.max_limit:
            return "limit_exceeded"
        for st in proposal.get("steps", []):
            if st["operation"] in p.deny_operations or (p.allow_operations and st["operation"] not in p.allow_operations):
                return f"step_operation_not_allowed:{st['operation']}"
            if p.allowed_resources and st.get("resource") not in p.allowed_resources:
                return "step_resource_not_allowed"
            if p.allowed_effects and set(st.get("effects", [])) - set(p.allowed_effects):
                return "step_effect_not_allowed"
            if "limit" in st and st["limit"] > p.max_limit:
                return "step_limit_exceeded"
            if len(st.get("fields", [])) > p.max_fields:
                return "step_fields_too_many"
            if len(st.get("effects", [])) > p.max_effects:
                return "step_effects_too_many"
            step_argument_error = inspect_arguments(st.get("arguments", {}), "step")
            if step_argument_error:
                return step_argument_error
        return None

    def check(self, proposal: Mapping[str, Any]) -> GateResult:
        try:
            normalized = validate_proposal_schema(proposal)
        except ProposalSchemaError as exc:
            raw = dict(proposal) if isinstance(proposal, Mapping) else {}
            return GateResult(False, "REJECT", raw, None, f"schema:{exc}", self.policy.policy_id, self.policy.policy_hash, _canonical_hash(raw))
        proposal_hash = _canonical_hash(normalized)
        semantic = self._semantic_policy_check(normalized)
        if semantic:
            return GateResult(False, "REJECT", normalized, None, f"policy:{semantic}", self.policy.policy_id, self.policy.policy_hash, proposal_hash)
        text = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        morph = self.morph.process(text, self.policy.to_morph_policy())
        if morph.decision == "REPAIR":
            try:
                normalized = json.loads(morph.text)
            except json.JSONDecodeError:
                return GateResult(False, "REJECT", normalized, morph, "morph:repair_not_json", self.policy.policy_id, self.policy.policy_hash, proposal_hash)
            proposal_hash = _canonical_hash(normalized)
        allowed = morph.decision in ("ACCEPT", "REPAIR")
        return GateResult(allowed, morph.decision, normalized, morph, "accepted" if allowed else "morph:" + ",".join(morph.violations), self.policy.policy_id, self.policy.policy_hash, proposal_hash)

    def execute(self, proposal: Mapping[str, Any], executor: Callable[[Dict[str, Any]], Any]) -> tuple[GateResult, Any]:
        result = self.check(proposal)
        if not result.allowed:
            raise PermissionError(f"proposal rejected: {result.reason}")
        return result, executor(result.proposal)
