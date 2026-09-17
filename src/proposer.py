"""Local-agent proposal adapter: constrained decoding → Proposal Schema v1.

Product narrative (README / iva.md): the on-prem Llama (or same-enterprise
node) *proposes* work; ProposalGate + MORPH decide; MVP execute_and_issue runs.
This module is the missing adapter that turns natural-language user text into a
proposal **dict** accepted by ``ProposalGate.check`` /
``ATLDataPlaneMVP.execute_and_issue``.

Constrained decoding backends (explicit; pick one at call time):

* ``outlines`` — JSON Schema constrained generation (optional dependency)
* ``xgrammar`` — grammar-constrained generation (optional dependency)
* ``llama_cpp`` — llama.cpp GBNF grammar (optional ``llama-cpp-python``)
* ``template`` — deterministic, allowlisted template (no LLM)

Fail-closed rule
----------------
If a grammar-capable backend is requested but cannot enforce constraints
(missing install, no grammar hook, model refuses structured mode), this module
either **raises** ``ConstrainedDecodeError`` or falls back to ``template``.
It never returns unconstrained free-form LLM prose as a proposal.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Union

from .proposal_gate import (
    ProposalSchemaError,
    validate_proposal_schema,
)

# ---------------------------------------------------------------------------
# Schema v1 (JSON Schema) — aligned with validate_proposal_schema
# ---------------------------------------------------------------------------

PROPOSAL_SCHEMA_V1: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "atl.proposal.schema.v1",
    "title": "ATL Proposal Schema v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "tool", "operation", "arguments"],
    "properties": {
        "schema_version": {"type": "integer", "const": 1},
        "tool": {
            "type": "string",
            "minLength": 1,
            "enum": ["lookup", "normalize", "validate", "publish"],
        },
        "operation": {
            "type": "string",
            "minLength": 1,
            "enum": ["read", "normalize", "validate", "publish"],
        },
        "arguments": {
            "type": "object",
            "additionalProperties": {
                "type": ["string", "number", "boolean", "null"]
            },
        },
        "action": {
            "type": "string",
            "enum": ["read", "transform", "validate", "publish"],
        },
        "resource": {"type": "string", "minLength": 1},
        "fields": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "maxItems": 64,
        },
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        "effects": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["read", "transform", "validate", "publish"],
            },
        },
        "steps": {
            "type": "array",
            "maxItems": 128,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "tool", "operation"],
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "tool": {"type": "string", "minLength": 1},
                    "operation": {"type": "string", "minLength": 1},
                    "arguments": {"type": "object"},
                    "action": {"type": "string"},
                    "resource": {"type": "string"},
                    "fields": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "depends_on": {
                        "type": "array",
                        "maxItems": 32,
                        "items": {"type": "string"},
                    },
                    "effects": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
        "metadata": {"type": "object"},
    },
}


def proposal_schema_v1_gbnf() -> str:
    """GBNF grammar for llama.cpp constrained decoding of Proposal Schema v1.

    Intentionally narrow (default policy tools/ops) so a local GGUF model cannot
    emit shell/exec/delete fields. Callers may pass a custom GBNF via ``grammar``.
    """
    return r"""
root ::= "{" ws schema-version "," ws tool "," ws operation "," ws arguments resource-opt fields-opt limit-opt action-opt effects-opt "}" ws
schema-version ::= "\"schema_version\"" ws ":" ws "1"
tool ::= "\"tool\"" ws ":" ws tool-val
tool-val ::= "\"lookup\"" | "\"normalize\"" | "\"validate\"" | "\"publish\""
operation ::= "\"operation\"" ws ":" ws op-val
op-val ::= "\"read\"" | "\"normalize\"" | "\"validate\"" | "\"publish\""
arguments ::= "\"arguments\"" ws ":" ws object
resource-opt ::= ("," ws "\"resource\"" ws ":" ws string)?
fields-opt ::= ("," ws "\"fields\"" ws ":" ws string-array)?
limit-opt ::= ("," ws "\"limit\"" ws ":" ws number)?
action-opt ::= ("," ws "\"action\"" ws ":" ws action-val)?
action-val ::= "\"read\"" | "\"transform\"" | "\"validate\"" | "\"publish\""
effects-opt ::= ("," ws "\"effects\"" ws ":" ws effects-array)?
effects-array ::= "[" ws (action-val ("," ws action-val)*)? ws "]"
string-array ::= "[" ws (string ("," ws string)*)? ws "]"
object ::= "{" ws (string ws ":" ws value ("," ws string ws ":" ws value)*)? ws "}"
value ::= string | number | "true" | "false" | "null" | object | array
array ::= "[" ws (value ("," ws value)*)? ws "]"
string ::= "\"" ([^"\\] | "\\" ["\\/bfnrt] | "\\u" [0-9a-fA-F]{4})* "\""
number ::= "-"? ([0-9] | [1-9] [0-9]*) ("." [0-9]+)? ([eE] [+-]? [0-9]+)?
ws ::= ([ \t\n\r])*
""".strip()


class ProposeBackend(str, Enum):
    OUTLINES = "outlines"
    XGRAMMAR = "xgrammar"
    LLAMA_CPP = "llama_cpp"
    TEMPLATE = "template"


class ConstrainedDecodeError(RuntimeError):
    """Raised when constrained decoding cannot be enforced (fail closed)."""


@dataclass(frozen=True)
class ProposeResult:
    """Structured outcome for operators / tests (proposal always schema-valid)."""

    proposal: Dict[str, Any]
    backend: str
    constrained: bool
    source: str  # "grammar" | "template" | "injected"


# Optional generator callables for tests / DI without installing LLM stacks.
GeneratorFn = Callable[[str, Mapping[str, Any]], str]


def _normalize_backend(backend: Union[str, ProposeBackend, None]) -> ProposeBackend:
    if backend is None:
        return ProposeBackend.TEMPLATE
    if isinstance(backend, ProposeBackend):
        return backend
    key = str(backend).strip().lower().replace("-", "_")
    aliases = {
        "outlines": ProposeBackend.OUTLINES,
        "xgrammar": ProposeBackend.XGRAMMAR,
        "llamacpp": ProposeBackend.LLAMA_CPP,
        "llama_cpp": ProposeBackend.LLAMA_CPP,
        "llama.cpp": ProposeBackend.LLAMA_CPP,
        "gbnf": ProposeBackend.LLAMA_CPP,
        "template": ProposeBackend.TEMPLATE,
    }
    if key not in aliases:
        raise ConstrainedDecodeError(
            f"unknown propose backend {backend!r}; "
            f"supported: {[b.value for b in ProposeBackend]}"
        )
    return aliases[key]


def backend_available(backend: Union[str, ProposeBackend]) -> bool:
    """True when the named backend can enforce grammar / schema constraints."""
    b = _normalize_backend(backend)
    if b is ProposeBackend.TEMPLATE:
        return True
    if b is ProposeBackend.OUTLINES:
        try:
            import outlines  # noqa: F401
            return True
        except Exception:
            return False
    if b is ProposeBackend.XGRAMMAR:
        try:
            import xgrammar  # noqa: F401
            return True
        except Exception:
            return False
    if b is ProposeBackend.LLAMA_CPP:
        try:
            from llama_cpp import LlamaGrammar  # noqa: F401
            return True
        except Exception:
            return False
    return False


def _parse_proposal_json(raw: str) -> Dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        # Defensive: constrained paths should not emit fences; template never does.
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConstrainedDecodeError(f"proposal is not JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ConstrainedDecodeError("proposal JSON must be an object")
    try:
        return validate_proposal_schema(obj)
    except ProposalSchemaError as exc:
        raise ConstrainedDecodeError(f"proposal schema rejected: {exc}") from exc


# ---------------------------------------------------------------------------
# Template proposer (deterministic, fail-safe; never free-form LLM)
# ---------------------------------------------------------------------------

_RESOURCE_RE = re.compile(
    r"\b(?:from|on|resource|tabla|table|de)\s+[\"']?([A-Za-z_][A-Za-z0-9_\.]{0,63})[\"']?",
    re.IGNORECASE,
)
_FIELD_RE = re.compile(
    r"\b(?:fields?|campos?)\s*[:=]?\s*\[([^\]]+)\]",
    re.IGNORECASE,
)
_STATUS_RE = re.compile(
    r"\bstatus\s*[:=]\s*[\"']?([A-Za-z0-9_\-]+)[\"']?",
    re.IGNORECASE,
)


def template_propose(
    user_text: str,
    *,
    default_tool: str = "lookup",
    default_operation: str = "read",
    default_resource: str = "crm",
    default_fields: Optional[Sequence[str]] = None,
    default_limit: int = 20,
) -> Dict[str, Any]:
    """Build a Proposal Schema v1 dict from text with allowlisted heuristics.

    This is the safe fallback when a grammar backend is unavailable. It does
    not call an LLM.
    """
    text = (user_text or "").strip()
    lower = text.lower()

    tool = default_tool
    operation = default_operation
    action = "read"
    effects = ["read"]

    if any(w in lower for w in ("validate", "validar", "check")):
        tool, operation, action, effects = "validate", "validate", "validate", ["validate"]
    elif any(w in lower for w in ("normalize", "normalizar")):
        tool, operation, action, effects = "normalize", "normalize", "transform", ["transform"]
    elif any(w in lower for w in ("publish", "publicar")):
        tool, operation, action, effects = "publish", "publish", "publish", ["publish"]
    elif any(w in lower for w in ("lookup", "read", "leer", "consulta", "query", "buscar")):
        tool, operation, action, effects = "lookup", "read", "read", ["read"]

    resource = default_resource
    m = _RESOURCE_RE.search(text)
    if m:
        resource = m.group(1)

    fields: list[str]
    fm = _FIELD_RE.search(text)
    if fm:
        fields = [p.strip().strip("'\"") for p in fm.group(1).split(",") if p.strip()]
    elif default_fields:
        fields = list(default_fields)
    else:
        fields = ["id", "region", "status"]

    arguments: Dict[str, Any] = {}
    sm = _STATUS_RE.search(text)
    if sm:
        arguments["status"] = sm.group(1)

    proposal = {
        "schema_version": 1,
        "tool": tool,
        "operation": operation,
        "action": action,
        "resource": resource,
        "fields": fields,
        "limit": int(default_limit),
        "arguments": arguments,
        "effects": effects,
        "metadata": {"proposer": "template", "user_text_sha_len": len(text)},
    }
    return validate_proposal_schema(proposal)


# ---------------------------------------------------------------------------
# Grammar-backed generators (optional deps; fail closed if missing)
# ---------------------------------------------------------------------------

def _generate_outlines(
    user_text: str,
    schema: Mapping[str, Any],
    *,
    model: Any,
    max_tokens: int = 512,
) -> str:
    try:
        import outlines
    except Exception as exc:  # pragma: no cover - env dependent
        raise ConstrainedDecodeError(
            "outlines backend requested but outlines is not installed"
        ) from exc
    if model is None:
        raise ConstrainedDecodeError("outlines backend requires model=")
    # outlines API surface varies by version; support common patterns.
    try:
        generator = outlines.generate.json(model, dict(schema))  # type: ignore[attr-defined]
        out = generator(user_text, max_tokens=max_tokens)
    except TypeError:
        generator = outlines.generate.json(model, dict(schema))  # type: ignore[attr-defined]
        out = generator(user_text)
    if isinstance(out, dict):
        return json.dumps(out, ensure_ascii=False)
    return str(out)


def _generate_xgrammar(
    user_text: str,
    schema: Mapping[str, Any],
    *,
    model: Any,
    tokenizer: Any = None,
    max_tokens: int = 512,
) -> str:
    try:
        import xgrammar as xgr
    except Exception as exc:  # pragma: no cover
        raise ConstrainedDecodeError(
            "xgrammar backend requested but xgrammar is not installed"
        ) from exc
    if model is None:
        raise ConstrainedDecodeError("xgrammar backend requires model=")
    # Prefer JSON Schema compiler when available; otherwise fail closed.
    compiler = getattr(xgr, "GrammarCompiler", None)
    json_schema_grammar = getattr(xgr, "JsonSchema", None) or getattr(
        xgr, "compile_json_schema", None
    )
    if compiler is None and json_schema_grammar is None:
        raise ConstrainedDecodeError(
            "xgrammar installed but no JSON-schema grammar API found; fail closed"
        )
    # Generation must be supplied by the caller-bound model object that already
    # wires xgrammar logits processors — we only verify grammar construction.
    try:
        if callable(json_schema_grammar):
            _ = json_schema_grammar(dict(schema))
        elif compiler is not None and tokenizer is not None:
            _ = compiler(tokenizer).compile_json_schema(dict(schema))  # type: ignore[call-arg]
    except Exception as exc:
        raise ConstrainedDecodeError(
            f"xgrammar could not compile proposal schema: {exc}"
        ) from exc

    generate = getattr(model, "generate_constrained", None) or getattr(model, "generate", None)
    if not callable(generate):
        raise ConstrainedDecodeError(
            "xgrammar backend requires model.generate_constrained(...) or "
            "model.generate(...); no unconstrained path is provided"
        )
    out = generate(user_text, schema=dict(schema), max_tokens=max_tokens)
    if isinstance(out, dict):
        return json.dumps(out, ensure_ascii=False)
    return str(out)


def _generate_llama_cpp(
    user_text: str,
    *,
    model: Any,
    grammar: Optional[str] = None,
    max_tokens: int = 512,
    temperature: float = 0.0,
) -> str:
    try:
        from llama_cpp import LlamaGrammar
    except Exception as exc:  # pragma: no cover
        raise ConstrainedDecodeError(
            "llama_cpp backend requested but llama-cpp-python is not installed"
        ) from exc
    if model is None:
        raise ConstrainedDecodeError("llama_cpp backend requires model= (llama_cpp.Llama)")
    gbnf = grammar or proposal_schema_v1_gbnf()
    try:
        llama_grammar = LlamaGrammar.from_string(gbnf)
    except Exception as exc:
        raise ConstrainedDecodeError(f"invalid GBNF grammar: {exc}") from exc

    prompt = (
        "Emit ONLY a JSON object matching ATL Proposal Schema v1 for this request:\n"
        f"{user_text}\n"
    )
    # Grammar is mandatory — never call create without it.
    completion = model.create(
        prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        grammar=llama_grammar,
    )
    if isinstance(completion, dict):
        choices = completion.get("choices") or []
        if choices:
            text = choices[0].get("text") or choices[0].get("message", {}).get("content")
            if text:
                return str(text)
    text = getattr(completion, "text", None)
    if text:
        return str(text)
    raise ConstrainedDecodeError("llama_cpp returned empty completion under grammar")


def propose(
    user_text: str,
    *,
    schema: Optional[Mapping[str, Any]] = None,
    backend: Union[str, ProposeBackend, None] = "template",
    model: Any = None,
    tokenizer: Any = None,
    grammar: Optional[str] = None,
    fallback_template: bool = False,
    generator: Optional[GeneratorFn] = None,
    max_tokens: int = 512,
    default_resource: str = "crm",
    default_fields: Optional[Sequence[str]] = None,
    default_limit: int = 20,
) -> Dict[str, Any]:
    """Propose a Proposal Schema v1 dict from user text.

    Parameters
    ----------
    user_text:
        Natural-language intent from the local operator / agent front-end.
    schema:
        JSON Schema used by outlines / xgrammar (defaults to PROPOSAL_SCHEMA_V1).
    backend:
        ``outlines`` | ``xgrammar`` | ``llama_cpp`` | ``template``.
    model / tokenizer:
        Backend-specific model handle (required for grammar backends).
    grammar:
        Optional GBNF override for ``llama_cpp``.
    fallback_template:
        If True and a grammar backend is unavailable / cannot constrain,
        use ``template_propose`` instead of raising. Default False = fail closed.
    generator:
        Optional injectable ``(user_text, schema) -> json_str`` for tests.
        When set with a grammar backend name, the call is treated as constrained
        (caller is responsible for enforcing grammar outside this process).

    Returns
    -------
    dict
        A proposal accepted by ``validate_proposal_schema`` / ``ProposalGate``.
    """
    schema_map: Mapping[str, Any] = schema or PROPOSAL_SCHEMA_V1
    b = _normalize_backend(backend)

    if b is ProposeBackend.TEMPLATE:
        return template_propose(
            user_text,
            default_resource=default_resource,
            default_fields=default_fields,
            default_limit=default_limit,
        )

    def _fallback_or_raise(err: ConstrainedDecodeError) -> Dict[str, Any]:
        if fallback_template:
            return template_propose(
                user_text,
                default_resource=default_resource,
                default_fields=default_fields,
                default_limit=default_limit,
            )
        raise err

    if not backend_available(b) and generator is None:
        return _fallback_or_raise(
            ConstrainedDecodeError(
                f"backend {b.value!r} cannot enforce grammar (not installed); "
                "fail closed (set fallback_template=True for template path)"
            )
        )

    try:
        if generator is not None:
            raw = generator(user_text, schema_map)
        elif b is ProposeBackend.OUTLINES:
            raw = _generate_outlines(
                user_text, schema_map, model=model, max_tokens=max_tokens
            )
        elif b is ProposeBackend.XGRAMMAR:
            raw = _generate_xgrammar(
                user_text,
                schema_map,
                model=model,
                tokenizer=tokenizer,
                max_tokens=max_tokens,
            )
        elif b is ProposeBackend.LLAMA_CPP:
            raw = _generate_llama_cpp(
                user_text, model=model, grammar=grammar, max_tokens=max_tokens
            )
        else:  # pragma: no cover
            raise ConstrainedDecodeError(f"unhandled backend {b!r}")
        return _parse_proposal_json(raw)
    except ConstrainedDecodeError as exc:
        return _fallback_or_raise(exc)


def propose_detailed(user_text: str, **kwargs: Any) -> ProposeResult:
    """Like ``propose`` but returns backend/constraint metadata."""
    backend = _normalize_backend(kwargs.get("backend", "template"))
    fallback = bool(kwargs.get("fallback_template", False))
    had_generator = kwargs.get("generator") is not None
    try:
        proposal = propose(user_text, **kwargs)
    except ConstrainedDecodeError:
        raise
    constrained = backend is not ProposeBackend.TEMPLATE
    source = "template"
    if backend is ProposeBackend.TEMPLATE:
        source = "template"
        constrained = False
    elif had_generator:
        source = "injected"
    else:
        # If we landed on template via fallback, detect via metadata.
        meta = proposal.get("metadata") or {}
        if isinstance(meta, dict) and meta.get("proposer") == "template" and fallback:
            source = "template"
            constrained = False
        else:
            source = "grammar"
    return ProposeResult(
        proposal=proposal,
        backend=backend.value,
        constrained=constrained,
        source=source,
    )


def propose_and_check(
    user_text: str,
    gate: Any,
    **kwargs: Any,
) -> Any:
    """Convenience: propose then ``gate.check(proposal)`` (GateResult)."""
    proposal = propose(user_text, **kwargs)
    return gate.check(proposal)


__all__ = [
    "PROPOSAL_SCHEMA_V1",
    "ProposeBackend",
    "ProposeResult",
    "ConstrainedDecodeError",
    "proposal_schema_v1_gbnf",
    "backend_available",
    "template_propose",
    "propose",
    "propose_detailed",
    "propose_and_check",
]
