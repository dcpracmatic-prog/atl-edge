"""Local-agent proposal adapter: constrained decoding → Proposal Schema v1.

Product narrative (README / iva.md): the on-prem Llama (or same-enterprise
node) *proposes* work; ProposalGate + MORPH decide; MVP execute_and_issue runs.
This module is the missing adapter that turns natural-language user text into a
proposal **dict** accepted by ``ProposalGate.check`` /
``ATLDataPlaneMVP.execute_and_issue``.

Constrained decoding backends (explicit; pick one at call time):

* ``lm_format_enforcer`` — transformers + lm-format-enforcer (optional; Kaggle path)
* ``llama_cpp`` — llama.cpp GBNF grammar (optional ``llama-cpp-python``)
* ``outlines`` — JSON Schema constrained generation (**experimental**)
* ``xgrammar`` — grammar-constrained generation (**experimental**)
* ``template`` — deterministic, allowlisted template (no LLM)

Fail-closed rule
----------------
If a grammar-capable backend is requested but cannot enforce constraints
(missing install, no grammar hook, model refuses structured mode), this module
either **raises** ``ConstrainedDecodeError`` or falls back to ``template``.
It never returns unconstrained free-form LLM prose as a proposal.

Defense in depth
----------------
Schema / GBNF constrain *format* (and deny dangerous argument keys / step ops).
ProposalGate constrains *semantics*. The catalog constrains *fields*.
Do not loosen the gate because the schema already enumerates tools.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Union

from .proposal_gate import (
    ProposalSchemaError,
    default_proposal_policy,
    validate_proposal_schema,
)

# ---------------------------------------------------------------------------
# Canonical system prompt (LLM-backed proposers)
# ---------------------------------------------------------------------------

CANONICAL_SYSTEM_PROMPT = (
    "You are the ATL Edge local proposer. Emit ONLY a single JSON object matching "
    "ATL Proposal Schema v1. Allowed tools: lookup, normalize, validate, publish. "
    "Allowed operations: read, normalize, validate, publish. Never emit shell, "
    "exec, delete, drop, truncate, email, notes, SSN/PII fields, or dangerous "
    "argument keys (shell, exec, command, raw_sql, sql_script, subprocess, python). "
    "Prefer minimal fields and an explicit resource. No markdown, no prose."
)

# Deny-list for JSON Schema propertyNames (aligned with ProposalPolicy).
_DENY_ARGUMENT_KEYS = list(default_proposal_policy().deny_argument_keys)

# GBNF cannot express a blocklist cleanly — use a safe allowlist (stricter).
_GBNF_SAFE_ARG_KEYS = ("status", "q", "filter", "id", "region")

_TOOL_ENUM = ["lookup", "normalize", "validate", "publish"]
_OP_ENUM = ["read", "normalize", "validate", "publish"]
_ACTION_ENUM = ["read", "transform", "validate", "publish"]


def _arguments_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "propertyNames": {
            "type": "string",
            "not": {"enum": list(_DENY_ARGUMENT_KEYS)},
        },
        "additionalProperties": {
            "type": ["string", "number", "boolean", "null"]
        },
    }


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
            "enum": list(_TOOL_ENUM),
        },
        "operation": {
            "type": "string",
            "minLength": 1,
            "enum": list(_OP_ENUM),
        },
        "arguments": _arguments_schema(),
        "action": {
            "type": "string",
            "enum": list(_ACTION_ENUM),
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
                "enum": list(_ACTION_ENUM),
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
                    # Same enums as root so constrained generators cannot emit
                    # delete/shell in a step.
                    "tool": {
                        "type": "string",
                        "minLength": 1,
                        "enum": list(_TOOL_ENUM),
                    },
                    "operation": {
                        "type": "string",
                        "minLength": 1,
                        "enum": list(_OP_ENUM),
                    },
                    "arguments": _arguments_schema(),
                    "action": {
                        "type": "string",
                        "enum": list(_ACTION_ENUM),
                    },
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
                        "items": {
                            "type": "string",
                            "enum": list(_ACTION_ENUM),
                        },
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
    emit shell/exec/delete fields. Arguments use a safe-key allowlist aligned
    with ``deny_argument_keys``. ``limit`` is constrained to 1-100 (schema max).
    """
    arg_alts = " | ".join(f'"\\"{k}\\""' for k in _GBNF_SAFE_ARG_KEYS)
    return f"""
root ::= "{{" ws schema-version "," ws tool "," ws operation "," ws arguments resource-opt fields-opt limit-opt action-opt effects-opt "}}" ws
schema-version ::= "\\"schema_version\\"" ws ":" ws "1"
tool ::= "\\"tool\\"" ws ":" ws tool-val
tool-val ::= "\\"lookup\\"" | "\\"normalize\\"" | "\\"validate\\"" | "\\"publish\\""
operation ::= "\\"operation\\"" ws ":" ws op-val
op-val ::= "\\"read\\"" | "\\"normalize\\"" | "\\"validate\\"" | "\\"publish\\""
arguments ::= "\\"arguments\\"" ws ":" ws args-object
args-object ::= "{{" ws (arg-pair ("," ws arg-pair)*)? ws "}}"
arg-pair ::= arg-key ws ":" ws arg-value
arg-key ::= {arg_alts}
arg-value ::= string | number | "true" | "false" | "null"
resource-opt ::= ("," ws "\\"resource\\"" ws ":" ws string)?
fields-opt ::= ("," ws "\\"fields\\"" ws ":" ws string-array)?
limit-opt ::= ("," ws "\\"limit\\"" ws ":" ws limit-val)?
limit-val ::= "100" | [1-9] [0-9]?
action-opt ::= ("," ws "\\"action\\"" ws ":" ws action-val)?
action-val ::= "\\"read\\"" | "\\"transform\\"" | "\\"validate\\"" | "\\"publish\\""
effects-opt ::= ("," ws "\\"effects\\"" ws ":" ws effects-array)?
effects-array ::= "[" ws (action-val ("," ws action-val)*)? ws "]"
string-array ::= "[" ws (string ("," ws string)*)? ws "]"
string ::= "\\"" ([^"\\\\] | "\\\\" ["\\\\/bfnrt] | "\\\\u" [0-9a-fA-F]{{4}})* "\\""
number ::= "-"? ([0-9] | [1-9] [0-9]*) ("." [0-9]+)? ([eE] [+-]? [0-9]+)?
ws ::= ([ \\t\\n\\r])*
""".strip()


class ProposeBackend(str, Enum):
    LM_FORMAT_ENFORCER = "lm_format_enforcer"
    LLAMA_CPP = "llama_cpp"
    OUTLINES = "outlines"  # experimental until real-model CI exists
    XGRAMMAR = "xgrammar"  # experimental until real-model CI exists
    TEMPLATE = "template"


EXPERIMENTAL_BACKENDS = frozenset({ProposeBackend.OUTLINES, ProposeBackend.XGRAMMAR})


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
        "lm_format_enforcer": ProposeBackend.LM_FORMAT_ENFORCER,
        "lmformatenforcer": ProposeBackend.LM_FORMAT_ENFORCER,
        "transformers": ProposeBackend.LM_FORMAT_ENFORCER,
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
    if b is ProposeBackend.LM_FORMAT_ENFORCER:
        try:
            import lmformatenforcer  # noqa: F401
            import transformers  # noqa: F401
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

# Prefer resource= / from|on|tabla|table <id>. Do NOT match bare Spanish "de"
# (false positive on "lista de clientes").
_RESOURCE_RE = re.compile(
    r"(?:"
    r"\bresource\s*=\s*[\"']?([A-Za-z_][A-Za-z0-9_\.]{0,63})[\"']?"
    r"|\b(?:from|on|tabla|table)\s+[\"']?([A-Za-z_][A-Za-z0-9_\.]{0,63})[\"']?"
    r")",
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

# Hard refuse: destructive / shell / remote command intents (ES + EN).
# Never silently rewrite these to CRM lookup/read.
_REFUSE_DESTRUCTIVE_RE = re.compile(
    r"(?:"
    r"\b(?:delete|borra(?:r|d[oa]s?)?|elimin(?:ar|a|e)|drop|truncate)\b"
    r"|\b(?:shell|exec(?:ute)?|subprocess|bash|powershell)\b"
    r"|\b(?:comando|command)\b"
    r"|\b(?:ejecut(?:a|ar|e|o|en|ad))\b"
    r"|\brun\s+(?:a\s+)?commands?\b"
    r"|\bserver\s+commands?\b"
    r"|\bcommands?\s+on\s+(?:the\s+)?server\b"
    r")",
    re.IGNORECASE,
)

# Prose / chitchat — must not become an executable proposal.
_REFUSE_PROSE_RE = re.compile(
    r"(?:"
    r"\b(?:h[aá]blame|hablarme|cu[eé]ntame|expl[ií]came|descr[ií]beme|describe)\b"
    r"|\btalk\s+about\b"
    r"|\btell\s+me\s+about\b"
    r"|\bwhat\s+(?:can\s+you\s+)?(?:tell|say)\s+about\b"
    r")",
    re.IGNORECASE,
)

# PII / sensitive field tokens. Matched with negation awareness (see helper).
_PII_FIELD_RE = re.compile(
    r"\b(?:notes?|notas?|ssn|curp|rfc|pii|password|passwd|secret|"
    r"email|correo|e-mail)\b",
    re.IGNORECASE,
)

# Negation window immediately before a PII token ("no leas notas", "don't read notes").
_NEGATION_TAIL_RE = re.compile(
    r"(?:^|[\s,;:(])(?:"
    r"no|not|dont|do\s+not|nunca|sin|without|avoid|skip|"
    r"don[’']t|n[’']t"
    r")(?:\s+\w+){0,4}\s*$",
    re.IGNORECASE,
)

# Explicit limit=N / "N filas|rows|registros" / "N mil …".
_LIMIT_EQ_RE = re.compile(r"\blimit\s*[:=]?\s*(\d+)\b", re.IGNORECASE)
_ROW_COUNT_RE = re.compile(
    r"\b(\d+)\s*(mil)?\s*(?:filas?|rows?|registros?)\b",
    re.IGNORECASE,
)
_MIL_COUNT_RE = re.compile(r"\b(\d+)\s*mil\b", re.IGNORECASE)

# Schema / ProposalGate policy max (keep in sync with PROPOSAL_SCHEMA_V1 + max_limit).
_TEMPLATE_MAX_LIMIT = 100

# Allowlisted tool names + NL aliases that map to them.
_ALLOWED_TOOLS = frozenset(_TOOL_ENUM)
_TOOL_ALIASES = frozenset(
    {
        "lookup",
        "read",
        "leer",
        "consulta",
        "consultar",
        "query",
        "buscar",
        "busca",
        "trae",
        "traer",
        "dame",
        "show",
        "get",
        "list",
        "lista",
        "listar",
        "normalize",
        "normalizar",
        "validate",
        "validar",
        "valida",
        "valide",
        "check",
        "publish",
        "publicar",
    }
)

# snake_case / API-looking tool tokens (e.g. launch_report).
_SNAKE_TOOL_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+)\b")
_TOOL_EQ_RE = re.compile(r"\btool\s*[:=]\s*([A-Za-z_][A-Za-z0-9_]*)\b", re.IGNORECASE)
_LEADING_TOKEN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]{1,63})\b")


def _pii_ask_without_negation(text: str) -> bool:
    """True when a PII/sensitive field is requested, not merely negated."""
    for m in _PII_FIELD_RE.finditer(text):
        prefix = text[: m.start()]
        if _NEGATION_TAIL_RE.search(prefix):
            continue
        return True
    return False


def _parse_requested_limit(text: str) -> Optional[int]:
    """Extract an explicit row/limit request; None if the user did not specify one."""
    m = _LIMIT_EQ_RE.search(text)
    if m:
        return int(m.group(1))
    m = _ROW_COUNT_RE.search(text)
    if m:
        n = int(m.group(1))
        if m.group(2):
            n *= 1000
        return n
    m = _MIL_COUNT_RE.search(text)
    if m:
        return int(m.group(1)) * 1000
    return None


def _unknown_tool_name(text: str, resource: str) -> Optional[str]:
    """Return an unknown explicit tool token, or None if only allowlisted tools appear."""
    resource_l = (resource or "").lower()
    # tool=foo
    for m in _TOOL_EQ_RE.finditer(text):
        name = m.group(1).lower()
        if name not in _ALLOWED_TOOLS and name not in _TOOL_ALIASES:
            return m.group(1)
    # snake_case API-looking names (launch_report) — not the resource id.
    for m in _SNAKE_TOOL_RE.finditer(text):
        name = m.group(1)
        if name.lower() == resource_l:
            continue
        if name.lower() in _ALLOWED_TOOLS or name.lower() in _TOOL_ALIASES:
            continue
        return name
    # Leading token that looks like an API tool (has underscore) and is unknown.
    lm = _LEADING_TOKEN_RE.match(text)
    if lm:
        lead = lm.group(1)
        if "_" in lead and lead.lower() not in _ALLOWED_TOOLS and lead.lower() not in _TOOL_ALIASES:
            return lead
    return None


def template_propose(
    user_text: str,
    *,
    default_tool: str = "lookup",
    default_operation: str = "read",
    default_resource: str = "crm",
    default_fields: Optional[Sequence[str]] = ("id", "region", "status"),
    default_limit: int = 20,
) -> Dict[str, Any]:
    """Build a Proposal Schema v1 dict from text with allowlisted heuristics.

    This is the safe fallback when a grammar backend is unavailable. It does
    not call an LLM. Destructive / PII-style / prose / oversized / unknown-tool
    intents raise ConstrainedDecodeError (fail closed) instead of silently
    becoming a CRM lookup that ProposalGate would ACCEPT.
    """
    text = (user_text or "").strip()
    lower = text.lower()

    if _REFUSE_DESTRUCTIVE_RE.search(text):
        raise ConstrainedDecodeError(
            "template refused intent (delete/shell/exec/command); fail closed"
        )
    if _REFUSE_PROSE_RE.search(text):
        raise ConstrainedDecodeError(
            "template refused prose/chitchat intent; fail closed"
        )
    if _pii_ask_without_negation(text):
        raise ConstrainedDecodeError(
            "template refused intent (email/notes/PII request); fail closed"
        )

    requested_limit = _parse_requested_limit(text)
    if requested_limit is not None and requested_limit > _TEMPLATE_MAX_LIMIT:
        raise ConstrainedDecodeError(
            f"template refused oversized limit {requested_limit} "
            f"(max {_TEMPLATE_MAX_LIMIT}); fail closed"
        )

    resource = default_resource
    m = _RESOURCE_RE.search(text)
    if m:
        resource = m.group(1) or m.group(2)

    unknown = _unknown_tool_name(text, resource)
    if unknown is not None:
        raise ConstrainedDecodeError(
            f"template refused unknown tool {unknown!r}; fail closed"
        )

    tool = default_tool
    operation = default_operation
    action = "read"
    effects = ["read"]

    if any(w in lower for w in ("validate", "validar", "valida", "valide", "check")):
        tool, operation, action, effects = "validate", "validate", "validate", ["validate"]
    elif any(w in lower for w in ("normalize", "normalizar")):
        tool, operation, action, effects = "normalize", "normalize", "transform", ["transform"]
    elif any(w in lower for w in ("publish", "publicar")):
        tool, operation, action, effects = "publish", "publish", "publish", ["publish"]
    elif any(
        w in lower
        for w in (
            "lookup",
            "read",
            "leer",
            "consulta",
            "query",
            "buscar",
            "trae",
            "traer",
            "dame",
            "show",
            "get",
            "list",
            "lista",
        )
    ):
        tool, operation, action, effects = "lookup", "read", "read", ["read"]

    fields: list[str]
    fm = _FIELD_RE.search(text)
    if fm:
        fields = [p.strip().strip("'\"") for p in fm.group(1).split(",") if p.strip()]
    else:
        fields = [str(x) for x in (default_fields or ("id", "region", "status"))]

    arguments: Dict[str, Any] = {}
    sm = _STATUS_RE.search(text)
    if sm:
        arguments["status"] = sm.group(1)

    limit = int(requested_limit) if requested_limit is not None else int(default_limit)
    if limit < 1:
        raise ConstrainedDecodeError("template refused non-positive limit; fail closed")
    if limit > _TEMPLATE_MAX_LIMIT:
        raise ConstrainedDecodeError(
            f"template refused limit {limit} > {_TEMPLATE_MAX_LIMIT}; fail closed"
        )

    proposal = {
        "schema_version": 1,
        "tool": tool,
        "operation": operation,
        "action": action,
        "resource": resource,
        "fields": fields,
        "limit": limit,
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

    # Fail closed: require generate_constrained — never fall through to generic
    # model.generate (unconstrained).
    generate = getattr(model, "generate_constrained", None)
    if not callable(generate):
        raise ConstrainedDecodeError(
            "xgrammar backend requires model.generate_constrained(...); "
            "no unconstrained model.generate fallback; fail closed"
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
        f"{CANONICAL_SYSTEM_PROMPT}\n\n"
        "Emit ONLY a JSON object matching ATL Proposal Schema v1 for this request:\n"
        f"{user_text}\n"
    )
    # llama-cpp-python: create_completion or __call__ — never model.create(...).
    call_kwargs = {
        "max_tokens": max_tokens,
        "temperature": temperature,
        "grammar": llama_grammar,
    }
    if hasattr(model, "create_completion") and callable(model.create_completion):
        completion = model.create_completion(prompt, **call_kwargs)
    elif callable(model):
        completion = model(prompt, **call_kwargs)
    else:
        raise ConstrainedDecodeError(
            "llama_cpp model must support create_completion(...) or __call__(...); "
            "model.create is not used"
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


def _generate_lm_format_enforcer(
    user_text: str,
    schema: Mapping[str, Any],
    *,
    model: Any,
    tokenizer: Any = None,
    max_tokens: int = 512,
) -> str:
    """transformers + lm-format-enforcer constrained path (Kaggle-style)."""
    try:
        from lmformatenforcer import JsonSchemaParser
        from lmformatenforcer.integrations.transformers import (
            build_transformers_prefix_allowed_tokens_fn,
        )
    except Exception as exc:  # pragma: no cover
        raise ConstrainedDecodeError(
            "lm_format_enforcer backend requested but lm-format-enforcer "
            "(and transformers) are not installed"
        ) from exc
    if model is None:
        raise ConstrainedDecodeError("lm_format_enforcer backend requires model=")
    tok = tokenizer
    if tok is None:
        tok = getattr(model, "tokenizer", None)
    if tok is None:
        raise ConstrainedDecodeError(
            "lm_format_enforcer backend requires tokenizer= (or model.tokenizer)"
        )
    try:
        parser = JsonSchemaParser(dict(schema))
        prefix_fn = build_transformers_prefix_allowed_tokens_fn(tok, parser)
    except Exception as exc:
        raise ConstrainedDecodeError(
            f"lm-format-enforcer could not build schema constraint: {exc}"
        ) from exc

    prompt = f"{CANONICAL_SYSTEM_PROMPT}\n\nRequest:\n{user_text}\n\nJSON:\n"
    generate = getattr(model, "generate", None)
    if not callable(generate):
        raise ConstrainedDecodeError(
            "lm_format_enforcer backend requires model.generate(...); fail closed"
        )
    try:
        inputs = tok(prompt, return_tensors="pt")
        input_ids = inputs["input_ids"]
        if hasattr(model, "device"):
            input_ids = input_ids.to(model.device)
        output_ids = generate(
            input_ids,
            max_new_tokens=max_tokens,
            prefix_allowed_tokens_fn=prefix_fn,
            do_sample=False,
        )
        gen_ids = output_ids[0][input_ids.shape[-1] :]
        out = tok.decode(gen_ids, skip_special_tokens=True)
    except TypeError:
        out = generate(
            prompt,
            max_new_tokens=max_tokens,
            prefix_allowed_tokens_fn=prefix_fn,
        )
    if isinstance(out, dict):
        return json.dumps(out, ensure_ascii=False)
    return str(out)


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
        JSON Schema used by outlines / xgrammar / lm_format_enforcer
        (defaults to PROPOSAL_SCHEMA_V1).
    backend:
        ``lm_format_enforcer`` | ``llama_cpp`` | ``outlines`` | ``xgrammar`` |
        ``template``. ``outlines`` / ``xgrammar`` are experimental.
    model / tokenizer:
        Backend-specific model handle (required for grammar backends).
    grammar:
        Optional GBNF override for ``llama_cpp``.
    fallback_template:
        If True and a grammar backend is unavailable / cannot constrain,
        use ``template_propose`` instead of raising. Default False = fail closed.
        Template refuse intents still raise even when fallback is enabled.
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
        elif b is ProposeBackend.LM_FORMAT_ENFORCER:
            raw = _generate_lm_format_enforcer(
                user_text,
                schema_map,
                model=model,
                tokenizer=tokenizer,
                max_tokens=max_tokens,
            )
        else:  # pragma: no cover
            raise ConstrainedDecodeError(f"unhandled backend {b!r}")
        return _parse_proposal_json(raw)
    except ConstrainedDecodeError as exc:
        return _fallback_or_raise(exc)


def propose_detailed(user_text: str, **kwargs: Any) -> ProposeResult:
    """Like ``propose`` but returns backend/constraint metadata.

    When ``fallback_template`` kicks in, effective ``backend`` is reported as
    ``template`` (not the originally requested outlines/xgrammar/etc.) while
    ``source`` stays accurate (``template``).
    """
    backend = _normalize_backend(kwargs.get("backend", "template"))
    fallback = bool(kwargs.get("fallback_template", False))
    had_generator = kwargs.get("generator") is not None
    try:
        proposal = propose(user_text, **kwargs)
    except ConstrainedDecodeError:
        raise
    constrained = backend is not ProposeBackend.TEMPLATE
    source = "template"
    effective_backend = backend.value
    if backend is ProposeBackend.TEMPLATE:
        source = "template"
        constrained = False
        effective_backend = ProposeBackend.TEMPLATE.value
    elif had_generator:
        source = "injected"
        effective_backend = backend.value
    else:
        meta = proposal.get("metadata") or {}
        if isinstance(meta, dict) and meta.get("proposer") == "template" and fallback:
            source = "template"
            constrained = False
            # Report effective backend as template when fallback kicked in.
            effective_backend = ProposeBackend.TEMPLATE.value
        else:
            source = "grammar"
            effective_backend = backend.value
    return ProposeResult(
        proposal=proposal,
        backend=effective_backend,
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
    "CANONICAL_SYSTEM_PROMPT",
    "EXPERIMENTAL_BACKENDS",
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
