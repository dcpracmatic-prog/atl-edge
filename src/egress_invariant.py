"""ATL product invariant: the data plane never initiates outbound calls.

The rule, stated once so it can be quoted in a contract:

    An ATL node does not initiate network calls. It does not call paid model
    providers, agent APIs, or any remote service. It receives a proposal,
    decides, reads locally, seals an ATLP package, and stops. Whoever consumes
    the package is a separate process on the other side of the boundary.

Why this needs to be a tested invariant rather than a paragraph in a PDF:

- The commercial claim is "the node is not a client of a premium LLM". A buyer
  cannot verify that by reading marketing copy, and the failure mode is silent:
  one `import requests` plus one `POST` in an executor and the claim is false
  while every existing test still passes.
- It is also the claim that decides whether ATL is buyable in a regulated shop.
  "Your data never leaves and nothing here phones a vendor" is a different
  product from "we proxy your rows to someone else's model".

This module enforces the invariant two ways, and deliberately does NOT enforce
it by adding another rule to the gate:

1. `assert_policy_forbids_egress()` proves the *existing* allow-list already
   makes egress unreachable. The gate admits a closed set of tools
   (lookup/normalize/validate/publish); anything named `http`, `openai`,
   `premium`, `shell` and so on is rejected because it is not in that set, not
   because a deny-list happened to mention it. Checking the allow-list is
   strictly stronger than adding a deny-list: a deny-list only blocks the names
   somebody thought of.
2. `scan_sources_for_egress()` is a static check over the frozen files. The
   gate can only reject tool *names*; it cannot stop code from opening a socket
   directly. So the second half of the invariant is that the modules on the
   sealing path contain no outbound client at all.

`src/data_plane.py` is byte-frozen (see the go/no-go criteria), so none of this
lives inside it. The invariant is asserted from outside the thing it constrains,
which is the only arrangement a buyer has reason to trust.
"""
from __future__ import annotations

import ast
import pathlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

__all__ = [
    "INVARIANT_TEXT",
    "EGRESS_MODULES",
    "FORBIDDEN_TOOL_NAMES",
    "GUARDED_SOURCES",
    "EgressFinding",
    "assert_policy_forbids_egress",
    "scan_sources_for_egress",
    "check_invariant",
]

INVARIANT_TEXT = (
    "An ATL node does not initiate outbound network calls. It does not call "
    "paid model providers, agent APIs, or any remote service. It receives a "
    "proposal, decides, reads locally, seals an ATLP package, and stops."
)

# Modules that can reach the network. An import of any of these inside a guarded
# source is a violation regardless of whether a call is made -- the point is that
# the capability is absent, not merely unused today.
EGRESS_MODULES: Tuple[str, ...] = (
    "aiohttp",
    "anthropic",
    "boto3",
    "botocore",
    "cohere",
    "ftplib",
    "google.generativeai",
    "grpc",
    "http.client",
    "httplib2",
    "httpx",
    "imaplib",
    "litellm",
    "mistralai",
    "ollama",
    "openai",
    "paramiko",
    "poplib",
    "pycurl",
    "replicate",
    "requests",
    "smtplib",
    "socket",
    "socketserver",
    "telnetlib",
    "together",
    "urllib.request",
    "urllib3",
    "vertexai",
    "websocket",
    "websockets",
    "xmlrpc.client",
)

# Tool names that must never be accepted by the gate. This list is used to TEST
# the allow-list, not to extend it -- see the module docstring.
FORBIDDEN_TOOL_NAMES: Tuple[str, ...] = (
    "anthropic",
    "bash",
    "browser",
    "curl",
    "eval",
    "exec",
    "fetch",
    "gemini",
    "http",
    "https",
    "llm",
    "openai",
    "premium",
    "request",
    "shell",
    "subprocess",
    "webhook",
)

# The sealing path: everything between "a proposal arrives" and "a package
# exists". These are the files where an outbound client would break the claim.
GUARDED_SOURCES: Tuple[str, ...] = (
    "src/data_plane.py",
    "src/mvp.py",
    "src/proposal_gate.py",
    "src/result_packaging.py",
    "src/execution_ledger.py",
    "src/data_catalog.py",
    "src/atl_core.py",
)


@dataclass(frozen=True)
class EgressFinding:
    """One violation: a guarded file importing something that can leave the box."""

    path: str
    line: int
    module: str
    statement: str

    def __str__(self) -> str:  # pragma: no cover - formatting only
        return f"{self.path}:{self.line}: imports {self.module!r} -- {self.statement}"


def _repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _is_egress(module: str) -> str | None:
    """Return the matched egress module, or None.

    Matches on dotted prefixes so `urllib.request.urlopen` and
    `http.client.HTTPConnection` are caught, while plain `urllib.parse` (pure
    string manipulation, no I/O) is not.
    """
    for banned in EGRESS_MODULES:
        if module == banned or module.startswith(banned + "."):
            return banned
    return None


def scan_sources_for_egress(
    paths: Sequence[str] | None = None, root: pathlib.Path | None = None
) -> List[EgressFinding]:
    """Parse each guarded file and report imports that could reach the network.

    Uses `ast` rather than a regex so a mention inside a comment or docstring --
    for example this module's own list of banned names -- is not a false
    positive. Only real import statements count.
    """
    root = root or _repo_root()
    findings: List[EgressFinding] = []
    for rel in paths or GUARDED_SOURCES:
        f = root / rel
        if not f.exists():
            raise FileNotFoundError(
                f"guarded source is missing: {rel}. If it was renamed, update "
                f"GUARDED_SOURCES in src/egress_invariant.py -- do not silently "
                f"drop a file from the invariant."
            )
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    hit = _is_egress(alias.name)
                    if hit:
                        findings.append(
                            EgressFinding(rel, node.lineno, hit, f"import {alias.name}")
                        )
            elif isinstance(node, ast.ImportFrom):
                # level > 0 is a relative import inside the package: local, fine.
                if node.level:
                    continue
                mod = node.module or ""
                hit = _is_egress(mod)
                if hit:
                    names = ", ".join(a.name for a in node.names)
                    findings.append(
                        EgressFinding(rel, node.lineno, hit, f"from {mod} import {names}")
                    )
    return findings


def assert_policy_forbids_egress() -> Dict[str, object]:
    """Prove the shipped gate policy cannot admit an egress tool.

    Returns a small evidence dict for the data room. Raises AssertionError with
    a specific message on violation.
    """
    from src.proposal_gate import default_proposal_policy

    policy = default_proposal_policy()
    allow = tuple(policy.allow_tools)

    assert allow, "gate policy has an empty allow_tools: that is fail-open, not fail-closed"

    leaked = sorted(t for t in allow if _tool_looks_like_egress(t))
    assert not leaked, (
        f"gate policy admits tool(s) that look like outbound calls: {leaked}. "
        f"The product claim is that the node initiates nothing."
    )

    # And the concrete names a buyer will ask about must all be outside the set.
    admitted = sorted(t for t in FORBIDDEN_TOOL_NAMES if t in allow)
    assert not admitted, f"forbidden tools present in allow_tools: {admitted}"

    return {
        "policy_id": policy.policy_id,
        "policy_hash": policy.policy_hash,
        "allow_tools": sorted(allow),
        "forbidden_checked": len(FORBIDDEN_TOOL_NAMES),
    }


def _tool_looks_like_egress(tool: str) -> bool:
    t = tool.strip().lower()
    needles = (
        "http", "url", "fetch", "curl", "request", "webhook", "socket", "grpc",
        "openai", "anthropic", "gemini", "claude", "gpt", "llm", "model",
        "premium", "shell", "bash", "exec", "eval", "subprocess", "browser",
        "api_call", "remote", "upstream", "proxy",
    )
    return any(n in t for n in needles)


def check_invariant() -> Tuple[bool, Dict[str, object]]:
    """Run both halves. Returns (ok, evidence)."""
    evidence: Dict[str, object] = {"invariant": INVARIANT_TEXT}
    ok = True

    try:
        evidence["policy"] = assert_policy_forbids_egress()
        evidence["policy_ok"] = True
    except AssertionError as exc:
        evidence["policy_ok"] = False
        evidence["policy_error"] = str(exc)
        ok = False

    findings = scan_sources_for_egress()
    evidence["sources_scanned"] = list(GUARDED_SOURCES)
    evidence["egress_modules_checked"] = len(EGRESS_MODULES)
    evidence["findings"] = [str(f) for f in findings]
    evidence["sources_ok"] = not findings
    if findings:
        ok = False

    evidence["ok"] = ok
    return ok, evidence
