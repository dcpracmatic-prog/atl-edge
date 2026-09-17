#!/usr/bin/env python3
"""Self-test: constrained local-agent proposer → ProposalGate / MVP seam."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock

from src.morph8 import MorphGate
from src.mvp import ATLDataPlaneMVP
from src.data_plane import LocalDataPlane, OnPremAuditLog, PackageCrypto
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.proposer import (
    PROPOSAL_SCHEMA_V1,
    ConstrainedDecodeError,
    ProposeBackend,
    _generate_llama_cpp,
    backend_available,
    propose,
    propose_and_check,
    propose_detailed,
    proposal_schema_v1_gbnf,
    template_propose,
)


def main() -> int:
    # --- Schema + GBNF are exported and non-empty ---
    assert PROPOSAL_SCHEMA_V1["required"] == [
        "schema_version",
        "tool",
        "operation",
        "arguments",
    ]
    gbnf = proposal_schema_v1_gbnf()
    assert "schema_version" in gbnf and "lookup" in gbnf
    assert '"shell"' not in gbnf.lower()
    assert '"command"' not in gbnf.lower()
    assert "limit-val" in gbnf
    assert "arg-key" in gbnf
    try:
        from llama_cpp import LlamaGrammar  # type: ignore

        LlamaGrammar.from_string(gbnf)
        print("proposer=GBNF_LLAMA_GRAMMAR_OK")
    except ImportError:
        print("proposer=GBNF_LLAMA_GRAMMAR_SKIP")

    # --- Template happy path ---
    p = template_propose(
        'lookup from crm fields=[id, region, status] status=active',
        default_limit=10,
    )
    assert p["schema_version"] == 1
    assert p["tool"] == "lookup" and p["operation"] == "read"
    assert p["resource"] == "crm"
    assert p["fields"] == ["id", "region", "status"]
    assert p["arguments"].get("status") == "active"
    assert p["limit"] == 10

    p2 = propose("validar registros on payroll", backend="template")
    assert p2["tool"] == "validate" and p2["operation"] == "validate"

    # Spanish "de" must not become the resource (lista de clientes).
    p_de = template_propose("consulta lista de clientes from crm fields=[id, status]")
    assert p_de["resource"] == "crm"

    # Template must refuse destructive / PII-style intents (never silent lookup).
    for intent in (
        "borra todos los clientes del crm",
        "delete crm rows",
        "run shell please",
        "execute bash",
        "send email to bob",
        "show notes",
        "get ssn for customer",
        # command / server exec (ES+EN) — never rewrite to lookup
        "Ejecuta un comando en el servidor para listar clientes",
        "run a command on the server",
        "server command to dump crm",
        # oversized limits — refuse (match ProposalGate max_limit=100)
        "Trae 10 mil filas from crm fields=[id, status]",
        "lookup from crm fields=[id] limit=10000",
        # unknown tool names — fail closed
        "launch_report from crm fields=[id]",
        # prose / chitchat — not executable
        "háblame de los VIP from crm",
        "explícame los clientes from crm fields=[id]",
        "talk about the VIP customers from crm",
        # real PII asks (not negations)
        "traer notas from crm",
    ):
        try:
            template_propose(intent)
            raise AssertionError(f"template must refuse intent: {intent!r}")
        except ConstrainedDecodeError:
            pass
        try:
            propose(intent, backend="template")
            raise AssertionError(f"propose(template) must refuse: {intent!r}")
        except ConstrainedDecodeError:
            pass
    print("proposer=REFUSE_INTENTS_OK")

    # Deny-list must NOT false-positive on negated notes ("no leas notas").
    for intent in (
        "Valida registros on payroll; no leas notas",
        "don't read notes, just validate from crm fields=[id, status]",
    ):
        pn = template_propose(intent)
        assert pn["tool"] == "validate", (intent, pn)
        assert ProposalGate(default_proposal_policy(), MorphGate()).check(pn).allowed, (intent, pn)
    # Explicit in-range limit is honored (not silently dropped to default).
    p_lim = template_propose("lookup from crm fields=[id] limit=10")
    assert p_lim["limit"] == 10
    print("proposer=NEGATION_AND_LIMIT_OK")

    # --- Template feeds ProposalGate ---
    policy = default_proposal_policy()
    gate = ProposalGate(policy, MorphGate())
    gr = propose_and_check(
        "consulta from crm fields=[id, status] status=active",
        gate,
        backend=ProposeBackend.TEMPLATE,
    )
    assert gr.allowed and gr.decision == "ACCEPT", gr.reason

    # --- Injected constrained generator (simulates outlines/xgrammar/llama.cpp) ---
    def good_generator(user_text: str, schema) -> str:
        assert schema is PROPOSAL_SCHEMA_V1 or schema.get("$id")
        return json.dumps(
            {
                "schema_version": 1,
                "tool": "lookup",
                "operation": "read",
                "resource": "crm",
                "fields": ["id", "region"],
                "arguments": {"q": user_text[:32]},
                "effects": ["read"],
            }
        )

    detailed = propose_detailed(
        "need id and region",
        backend="outlines",
        generator=good_generator,
    )
    assert detailed.constrained and detailed.source == "injected"
    assert detailed.proposal["fields"] == ["id", "region"]
    assert gate.check(detailed.proposal).allowed

    # --- Fail closed: backend missing, no fallback ---
    # Prefer a backend that is almost certainly not installed in CI.
    for name in ("outlines", "xgrammar", "llama_cpp"):
        if backend_available(name):
            continue
        try:
            propose("anything", backend=name, fallback_template=False)
            raise AssertionError(f"{name} should fail closed when unavailable")
        except ConstrainedDecodeError as exc:
            assert "fail closed" in str(exc) or "not installed" in str(exc)
        break
    else:
        # All grammar backends present — still verify unknown backend fails closed.
        try:
            propose("x", backend="not-a-real-backend")
            raise AssertionError("unknown backend must fail closed")
        except ConstrainedDecodeError:
            pass

    # --- Template fallback when grammar backend unavailable ---
    fb = propose(
        "lookup from crm fields=[id] status=ok",
        backend="xgrammar",
        fallback_template=True,
    )
    assert fb["tool"] == "lookup"
    assert (fb.get("metadata") or {}).get("proposer") == "template"
    fb_d = propose_detailed(
        "lookup from crm fields=[id] status=ok",
        backend="xgrammar",
        fallback_template=True,
    )
    assert fb_d.backend == "template", fb_d
    assert fb_d.source == "template"
    assert fb_d.constrained is False
    print("proposer=FALLBACK_BACKEND_TEMPLATE_OK")

    # --- Injected generator that returns prose / invalid JSON → fail closed ---
    def prose_generator(user_text: str, schema) -> str:
        return "Sure! I will look up the CRM for you in natural language."

    try:
        propose("crm please", backend="outlines", generator=prose_generator)
        raise AssertionError("prose output must not become a proposal")
    except ConstrainedDecodeError as exc:
        assert "not JSON" in str(exc) or "schema rejected" in str(exc)

    def dangerous_generator(user_text: str, schema) -> str:
        return json.dumps(
            {
                "schema_version": 1,
                "tool": "lookup",
                "operation": "read",
                "arguments": {},
                "shell": "rm -rf /",
            }
        )

    try:
        propose("x", backend="llama_cpp", generator=dangerous_generator)
        raise AssertionError("unknown/dangerous fields must be rejected")
    except ConstrainedDecodeError:
        pass


    # --- llama_cpp mock: grammar= must be passed to create_completion ---
    fake_llama = types.ModuleType("llama_cpp")

    class FakeGrammar:
        @staticmethod
        def from_string(s: str):
            assert "schema_version" in s
            return "FAKE_GRAMMAR"

    fake_llama.LlamaGrammar = FakeGrammar
    sys.modules["llama_cpp"] = fake_llama
    try:
        model = MagicMock()
        model.create_completion = MagicMock(
            return_value={
                "choices": [
                    {
                        "text": json.dumps(
                            {
                                "schema_version": 1,
                                "tool": "lookup",
                                "operation": "read",
                                "resource": "crm",
                                "fields": ["id"],
                                "arguments": {},
                                "effects": ["read"],
                            }
                        )
                    }
                ]
            }
        )
        raw = _generate_llama_cpp("lookup from crm fields=[id]", model=model)
        assert model.create_completion.called
        kwargs = model.create_completion.call_args.kwargs
        assert kwargs.get("grammar") == "FAKE_GRAMMAR"
        assert json.loads(raw)["tool"] == "lookup"
        print("proposer=LLAMA_CPP_GRAMMAR_KWARG_OK")
    finally:
        sys.modules.pop("llama_cpp", None)

    # --- xgrammar fail-closed when generate_constrained missing ---
    class BareModel:
        def generate(self, *a, **k):
            return (
                '{"schema_version":1,"tool":"lookup","operation":"read","arguments":{}}'
            )

    try:
        propose("x", backend="xgrammar", model=BareModel(), fallback_template=False)
        # If package missing, ConstrainedDecodeError is also correct.
        if backend_available("xgrammar"):
            raise AssertionError("xgrammar must fail closed without generate_constrained")
    except ConstrainedDecodeError as exc:
        msg = str(exc).lower()
        assert (
            "generate_constrained" in msg
            or "not installed" in msg
            or "fail closed" in msg
        )
    print("proposer=XGRAMMAR_FAIL_CLOSED_OK")

    # --- End-to-end: propose → execute_and_issue ---
    master = hashlib.sha256(b"atl-proposer-selftest").digest()
    crypto = PackageCrypto.from_master(master, "proposer-node", key_id="p-v1")
    with tempfile.TemporaryDirectory() as td:
        audit = OnPremAuditLog(Path(td) / "audit.jsonl")
        dp = LocalDataPlane(crypto, audit)
        app = ATLDataPlaneMVP(gate, dp)
        proposal = propose(
            "lookup from crm fields=[id, region, status] status=active",
            backend="template",
        )
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
            request_id="proposer-e2e-1",
        )
        assert execution.gate.allowed and calls and execution.executor_result == "ok"
        assert execution.issue is not None

    print("proposer=TEMPLATE_OK")
    print("proposer=CONSTRAINED_INJECT_OK")
    print("proposer=FAIL_CLOSED_OK")
    print("proposer=TEMPLATE_FALLBACK_OK")
    print("proposer=NO_PROSE_FALLBACK")
    print("proposer=MVP_SEAM_OK")
    print("proposer selftest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
