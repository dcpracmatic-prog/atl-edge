from __future__ import annotations

import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.data_plane import LocalDataPlane, OnPremAuditLog, PackageCrypto, INERT
from src.proposal_gate import ProposalGate, default_proposal_policy


def make_gate_and_plane(tmp_path: Path):
    gate = ProposalGate(default_proposal_policy())
    master = hashlib.sha256(b"test-master").digest()
    crypto = PackageCrypto.from_master(master, "test-node", key_id="test-v1")
    dp = LocalDataPlane(
        crypto,
        OnPremAuditLog(tmp_path / "audit.jsonl"),
        issue_auth_key=gate.issue_auth_key,
    )
    return gate, dp


def test_nested_dangerous_argument_in_step_is_rejected():
    gate = ProposalGate(default_proposal_policy())
    proposal = {
        "schema_version": 1,
        "tool": "lookup",
        "operation": "read",
        "steps": [
            {
                "id": "s1",
                "tool": "lookup",
                "operation": "read",
                "arguments": {"options": {"nested": {"exec": "whoami"}}},
            }
        ],
    }
    result = gate.check(proposal)
    assert not result.allowed
    assert result.reason.startswith("policy:dangerous_step_argument_keys:")


def test_nested_dangerous_argument_in_list_is_rejected():
    gate = ProposalGate(default_proposal_policy())
    proposal = {
        "schema_version": 1,
        "tool": "lookup",
        "operation": "read",
        "arguments": {"items": [{"safe": 1}, {"command": "id"}]},
    }
    result = gate.check(proposal)
    assert not result.allowed
    assert result.reason.startswith("policy:dangerous_proposal_argument_keys:")


def test_argument_depth_is_bounded():
    gate = ProposalGate(default_proposal_policy())
    value = "x"
    for _ in range(18):
        value = {"nested": value}
    result = gate.check({
        "schema_version": 1,
        "tool": "lookup",
        "operation": "read",
        "arguments": value,
    })
    assert not result.allowed
    assert result.reason == "policy:proposal_argument_depth_exceeded"


def test_fields_and_effects_have_schema_limits():
    gate = ProposalGate(default_proposal_policy())
    too_many_fields = gate.check({
        "schema_version": 1,
        "tool": "lookup",
        "operation": "read",
        "fields": [f"f{i}" for i in range(65)],
    })
    assert not too_many_fields.allowed
    assert too_many_fields.reason == "policy:fields_too_many"

    too_many_effects = gate.check({
        "schema_version": 1,
        "tool": "lookup",
        "operation": "read",
        "effects": ["read"] * 33,
    })
    assert not too_many_effects.allowed
    assert "effects must be a list of <=32 strings" in too_many_effects.reason


def test_direct_data_plane_issue_requires_gate_authorization(tmp_path: Path):
    gate, dp = make_gate_and_plane(tmp_path)
    with pytest.raises(PermissionError, match=f"^{INERT}$"):
        dp.issue_for_agent(
            [{"customer_id": 1}],
            policy_id=gate.policy.policy_id,
            ttl_seconds=30,
            fields=["customer_id"],
            request_id="direct-bypass",
            policy_hash=gate.policy.policy_hash,
            proposal_hash="sha256:" + "0" * 64,
        )


def test_gate_authorization_binds_request_policy_and_fields(tmp_path: Path):
    gate, dp = make_gate_and_plane(tmp_path)
    proposal = {
        "schema_version": 1,
        "tool": "lookup",
        "operation": "read",
        "fields": ["customer_id"],
    }
    checked = gate.check(proposal)
    assert checked.allowed
    auth = gate.authorize_issue(
        checked, request_id="bound-1", ttl_seconds=30, fields=["customer_id"]
    )

    issued = dp.issue_for_agent(
        [{"customer_id": 1}],
        policy_id=checked.policy_id,
        ttl_seconds=30,
        fields=["customer_id"],
        request_id="bound-1",
        policy_hash=checked.policy_hash,
        proposal_hash=checked.proposal_hash,
        authorization=auth,
    )
    assert issued.header.proposal_hash == checked.proposal_hash

    with pytest.raises(PermissionError, match=f"^{INERT}$"):
        dp.issue_for_agent(
            [{"customer_id": 1}],
            policy_id=checked.policy_id,
            ttl_seconds=30,
            fields=["status"],
            request_id="bound-1",
            policy_hash=checked.policy_hash,
            proposal_hash=checked.proposal_hash,
            authorization=auth,
        )
