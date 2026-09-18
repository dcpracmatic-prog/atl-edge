#!/usr/bin/env python3
"""A passive MCP server over the ATL boundary. Exactly three tools, no chat.

Roadmap item 4. Its role is to **consume** ATLP packages. It is the seam an
existing agent stack (Claude Desktop, a Salesforce MCP client, any MCP host)
speaks to, and the direction of travel is the whole point:

    MCP host  ---->  this server  ---->  local ATL Edge (loopback)
                                          |
                                          +-- reads local data, seals ATLP

Nothing points outward. The node does not query Salesforce, does not call
OpenAI, does not hold a provider key. The host asks; the boundary decides; a
sealed package comes back. That is the inverse of the usual "give the agent a
database credential" integration, and it is the property being sold.

Deliberately absent
-------------------
There is no `query`, no `sql`, no `search`, no `chat`, no `describe_schema`.
The tool list is closed at three:

  propose        natural-language intent -> a schema-valid proposal (or refusal)
  execute        proposal -> ATLP package (or refusal, with the reason)
  open_package   ATLP package -> the projected rows, opened with the NODE key

A fourth tool is not a feature request, it is a change to the threat model.
`scripts/check_mcp_surface.py` fails CI if this list grows.

Transport is JSON-RPC 2.0 over stdio, hand-rolled against the MCP wire format
so the connector adds **no dependency** to the node. A buyer auditing what runs
next to their data reads one file.

Egress posture
--------------
This adapter does use `urllib.request`, which the egress guard forbids on the
sealing path -- so it is not on that path, and it is pinned to loopback at
runtime: a non-loopback Edge URL is refused at startup. The adapter cannot be
quietly repointed at a remote host and become the egress hole the invariant
says does not exist.

Run:
    ATL_NODE_KEY_HEX=... ATL_NODE_ID=... ATL_CONSOLE_TOKEN=... \\
      PYTHONPATH=. python src/mcp_server.py

    python src/mcp_server.py --selftest      # no Edge required
    python src/mcp_server.py --list-tools    # print the closed tool surface
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "atl-edge"
SERVER_VERSION = "0.1.0"

# The closed surface. Adding to this tuple is a threat-model change, not a
# feature; scripts/check_mcp_surface.py asserts it stays exactly this.
TOOL_NAMES: Tuple[str, ...] = ("propose", "execute", "open_package")

# Names this connector must never expose, however convenient. A chat-against-
# the-database tool would hand back precisely what the boundary exists to deny.
FORBIDDEN_TOOL_NAMES: Tuple[str, ...] = (
    "query", "sql", "raw_query", "search", "chat", "ask", "complete",
    "describe_schema", "list_tables", "dump", "export", "read_table",
    "issue_for_agent", "data_plane", "shell", "exec",
)


class MCPError(Exception):
    """A JSON-RPC error with a code."""

    def __init__(self, message: str, code: int = -32000):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Loopback pin
# ---------------------------------------------------------------------------

def assert_loopback(url: str) -> str:
    """Refuse any Edge URL that is not loopback.

    The product claim is that the node initiates nothing outbound. An adapter
    that can be pointed at an arbitrary host would make that claim false while
    every test still passed, so the check is at startup and is not optional.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise MCPError(f"Edge URL must be http(s), got {parsed.scheme!r}")
    host = parsed.hostname or ""
    if host == "localhost":
        return url
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise MCPError(
            f"Edge URL host {host!r} is not loopback. This connector consumes a "
            "LOCAL ATL Edge; pointing it at a remote host would create exactly "
            "the outbound path the product invariant denies."
        ) from exc
    if not ip.is_loopback:
        raise MCPError(
            f"Edge URL host {host} is not loopback (refusing to create an "
            "outbound path; see the product invariant in iva.md)."
        )
    return url


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

def tool_definitions() -> List[Dict[str, Any]]:
    return [
        {
            "name": "propose",
            "description": (
                "Turn a bounded natural-language intent into a schema-valid "
                "proposal, or refuse it. Refusal is a normal outcome: "
                "destructive, prose and unknown-tool intents fail closed here, "
                "before any data is touched. Returns the proposal for review; "
                "it does NOT execute."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Bounded operator intent, e.g. 'list stock "
                                       "levels with sku, description and qty_on_hand'.",
                    },
                    "resource": {
                        "type": "string",
                        "description": "Catalog asset id, e.g. 'inventory_positions'.",
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Explicit minimum field set. Without fields "
                                       "there is no seal.",
                    },
                },
                "required": ["text"],
            },
        },
        {
            "name": "execute",
            "description": (
                "Submit an approved proposal to the local Edge. On acceptance "
                "returns a sealed ATLP package containing ONLY the requested "
                "fields. On refusal returns the reason (policy, field not "
                "allowed, sensitivity, missing fields, duplicate request_id). "
                "The caller never receives the underlying rows."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "proposal": {
                        "type": "object",
                        "description": "A proposal as returned by `propose`.",
                    },
                    "request_id": {
                        "type": "string",
                        "description": "Idempotency boundary. Reusing one is refused.",
                    },
                    "ttl_seconds": {
                        "type": "integer",
                        "description": "Package lifetime. Default 120.",
                    },
                },
                "required": ["proposal"],
            },
        },
        {
            "name": "open_package",
            "description": (
                "Open a sealed ATLP package with the node key and return the "
                "projected rows plus the governance receipt (fields emitted, "
                "bytes retained, TTL, request_id). Requires ATL_NODE_KEY_HEX; "
                "the provisioning master key is never accepted here."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package_b64": {
                        "type": "string",
                        "description": "Base64 ATLP package as returned by `execute`.",
                    },
                },
                "required": ["package_b64"],
            },
        },
    ]


# ---------------------------------------------------------------------------
# Edge client (loopback only)
# ---------------------------------------------------------------------------

class EdgeClient:
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None,
                 timeout: float = 15.0):
        raw = base_url or os.environ.get("ATL_MCP_EDGE", "http://127.0.0.1:8790")
        self.base_url = assert_loopback(raw.rstrip("/"))
        self.token = token if token is not None else os.environ.get("ATL_CONSOLE_TOKEN", "")
        self.timeout = timeout

    def post(self, path: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base_url + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(raw or "{}")
            except json.JSONDecodeError:
                parsed = {"error": raw[:400]}
            # A 4xx is a governance decision, not a transport failure. Hand it
            # back so the host can show the operator WHY it was refused.
            return exc.code, parsed
        except urllib.error.URLError as exc:
            raise MCPError(
                f"local Edge unreachable at {self.base_url} ({exc.reason}). "
                "Start it with: bash scripts/start_stack.sh"
            ) from exc


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _text_result(payload: Any, is_error: bool = False) -> Dict[str, Any]:
    return {
        "content": [{"type": "text",
                     "text": json.dumps(payload, indent=2, ensure_ascii=False)}],
        "isError": bool(is_error),
    }


def _reject_host_supplied_records(args: Dict[str, Any]) -> None:
    """The MCP host must never be able to inject rows.

    The whole inversion is that the host names a resource and the node reads it
    locally. A host that could pass `records` would be choosing what the
    boundary minimises, which is the one thing it must not control.
    """
    for key in ("records", "rows", "data", "payload"):
        if key in args:
            raise MCPError(
                f"{key!r} is not accepted. The host names a resource; the node "
                "reads it locally. Supplying rows would let the caller choose "
                "what the boundary minimises."
            )


def tool_propose(args: Dict[str, Any], edge: EdgeClient) -> Dict[str, Any]:
    _reject_host_supplied_records(args)
    text = str(args.get("text") or "").strip()
    if not text:
        raise MCPError("`text` is required")
    resource = str(args.get("resource") or "").strip()
    # The Edge speaks `intent` / `default_resource` / `default_fields`.
    body: Dict[str, Any] = {"intent": text, "backend": "template"}
    if resource:
        body["default_resource"] = resource
    if args.get("fields"):
        body["default_fields"] = [str(f) for f in args["fields"]]
    status, payload = edge.post("/v1/propose", body)
    proposal = payload.get("proposal")
    refused = status >= 400 or not isinstance(proposal, dict)
    if not refused and resource:
        # Pin the asset to what the operator named, so a proposer default
        # cannot silently retarget the request at another resource.
        proposal = dict(proposal)
        proposal["resource"] = resource
    if not refused and args.get("fields"):
        proposal = dict(proposal)
        proposal["fields"] = [str(f) for f in args["fields"]]
    return _text_result({
        "http_status": status,
        "accepted": not refused,
        "proposal": proposal if not refused else None,
        "backend": payload.get("backend"),
        "constrained": payload.get("constrained"),
        "reason": payload.get("reason") or payload.get("error"),
        "note": ("Refused at the proposer boundary; no proposal was built and "
                 "no data was touched."
                 if refused else
                 "Review the fields, then call `execute`. Nothing has been read yet."),
    }, is_error=refused)


def local_records(resource: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Read rows from the node's OWN catalog. The host cannot influence this.

    Kept deliberately narrow: a resource this function does not know is refused
    rather than guessed at, so the connector cannot be talked into reading a
    file it was not configured for.
    """
    from src.inventory_catalog import (
        MOVEMENTS_ASSET,
        POSITIONS_ASSET,
        dataset_available,
        load_movements,
        load_positions,
    )

    loaders = {POSITIONS_ASSET: load_positions, MOVEMENTS_ASSET: load_movements}
    if resource not in loaders:
        raise MCPError(
            f"resource {resource!r} is not configured on this node. Known: "
            f"{sorted(loaders)}. The connector reads only what it was set up to "
            "read; it does not go looking."
        )
    if not dataset_available():
        raise MCPError(
            "the local dataset is not built. Run: "
            "python scripts/fetch_inventory_dataset.py"
        )
    return loaders[resource](limit=limit)


def tool_execute(args: Dict[str, Any], edge: EdgeClient) -> Dict[str, Any]:
    _reject_host_supplied_records(args)
    proposal = args.get("proposal")
    if not isinstance(proposal, dict):
        raise MCPError("`proposal` must be the object returned by `propose`")
    resource = str(proposal.get("resource") or "").strip()
    if not resource:
        raise MCPError("the proposal must name a `resource`")
    fields = [str(f) for f in (proposal.get("fields") or ())]
    if not fields:
        raise MCPError("no fields, no seal: the proposal must declare `fields`")

    records = local_records(resource, limit=int(proposal.get("limit") or 50))

    body: Dict[str, Any] = {
        "proposal": proposal,
        "records": records,
        "fields": fields,
        "purpose": "mcp-connector",
    }
    if args.get("request_id"):
        body["request_id"] = str(args["request_id"])
    status, payload = edge.post("/v1/execute", body)
    pkg = payload.get("package_b64")
    refused = status >= 400 or not pkg
    return _text_result({
        "http_status": status,
        "accepted": not refused,
        "package_b64": pkg,
        "metrics": payload.get("metrics"),
        "gate_decision": payload.get("gate_decision"),
        "request_id": payload.get("request_id") or body.get("request_id"),
        "rows_read_locally": len(records),
        "fields_requested": fields,
        "reason": payload.get("reason") or payload.get("error"),
        "note": ("Refused by the boundary; no package exists and the business "
                 "executor did not run."
                 if refused else
                 "Sealed package returned. It contains only the requested fields; "
                 "call `open_package` with the node key to read them."),
    }, is_error=refused)


def tool_open_package(args: Dict[str, Any], edge: EdgeClient) -> Dict[str, Any]:
    import base64

    b64 = str(args.get("package_b64") or "")
    if not b64:
        raise MCPError("`package_b64` is required")
    node_hex = os.environ.get("ATL_NODE_KEY_HEX", "").strip()
    if not node_hex:
        raise MCPError(
            "ATL_NODE_KEY_HEX is required to open a package. The provisioning "
            "master key is deliberately not accepted here."
        )
    if os.environ.get("ATL_MASTER_KEY_HEX"):
        raise MCPError(
            "ATL_MASTER_KEY_HEX is present in this process. A connector must "
            "hold only the derived node key; refusing to run."
        )
    try:
        package = base64.b64decode(b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise MCPError(f"package_b64 is not valid base64: {exc}") from exc

    from src.data_plane import CloudDecryptConnector

    node_id = os.environ.get("ATL_NODE_ID", "edge-node-1")
    try:
        connector = CloudDecryptConnector.from_env(node_id)
        opened = connector.open_package(package)
    except Exception as exc:  # noqa: BLE001
        # Opening failures are deliberately opaque about which check failed.
        return _text_result({
            "opened": False,
            "reason": f"package did not open: {type(exc).__name__}",
            "note": "Wrong node key, expired TTL, replay, or tampering. The "
                    "boundary does not disclose which.",
        }, is_error=True)

    rows = opened.get("rows") if isinstance(opened, dict) else opened
    rows = rows if isinstance(rows, list) else ([rows] if rows else [])
    emitted = sorted({k for r in rows if isinstance(r, dict) for k in r})
    return _text_result({
        "opened": True,
        "rows": rows,
        "row_count": len(rows),
        "fields_emitted": emitted,
        "receipt": {k: v for k, v in opened.items() if k != "rows"} if isinstance(opened, dict) else {},
        "note": "These are the only fields that left the node. Anything else in "
                "the source row was never in this package.",
    })


TOOL_IMPLS = {
    "propose": tool_propose,
    "execute": tool_execute,
    "open_package": tool_open_package,
}


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------

def handle_request(msg: Dict[str, Any], edge_factory=EdgeClient) -> Optional[Dict[str, Any]]:
    """Handle one JSON-RPC message. Returns None for notifications."""
    method = msg.get("method")
    msg_id = msg.get("id")

    def ok(result: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def err(message: str, code: int = -32000) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    if method == "initialize":
        return ok({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "This server consumes ATLP packages from a local ATL Edge. It "
                "exposes propose, execute and open_package only. There is no "
                "tool that queries the underlying database, and that is "
                "intentional: ask for fields, receive a sealed package, open it "
                "with the node key."
            ),
        })

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return ok({})

    if method == "tools/list":
        return ok({"tools": tool_definitions()})

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in TOOL_IMPLS:
            return err(
                f"unknown tool {name!r}; this connector exposes exactly "
                f"{list(TOOL_NAMES)} and will not grow a query tool",
                code=-32601,
            )
        try:
            edge = edge_factory()
            return ok(TOOL_IMPLS[name](args, edge))
        except MCPError as exc:
            return err(exc.message, code=exc.code)
        except Exception as exc:  # noqa: BLE001
            return err(f"{type(exc).__name__}: {exc}")

    if method == "shutdown":
        return ok({})

    return err(f"method not found: {method!r}", code=-32601)


def serve_stdio(stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32700, "message": "parse error"},
            }) + "\n")
            stdout.flush()
            continue
        response = handle_request(msg)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0


# ---------------------------------------------------------------------------
# Selftest (no Edge required)
# ---------------------------------------------------------------------------

def selftest() -> int:
    failures: List[str] = []

    def check(ok_: bool, label: str) -> None:
        print(f"  [{'PASS' if ok_ else 'FAIL'}] {label}")
        if not ok_:
            failures.append(label)

    print("=" * 72)
    print("MCP CONNECTOR — passive consumer, closed surface")
    print("=" * 72)

    print("\n-- the surface is closed at three tools -----------------------------")
    names = tuple(t["name"] for t in tool_definitions())
    check(names == TOOL_NAMES, f"tools are exactly {TOOL_NAMES} (got {names})")
    check(len(names) == 3, "exactly three tools")
    overlap = sorted(set(names) & set(FORBIDDEN_TOOL_NAMES))
    check(not overlap, f"no forbidden tool is exposed (overlap: {overlap})")
    for t in tool_definitions():
        check(bool(t.get("inputSchema", {}).get("properties")),
              f"{t['name']}: has an input schema")

    print("\n-- tools/list over the wire matches --------------------------------")
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    wire = tuple(t["name"] for t in resp["result"]["tools"])
    check(wire == TOOL_NAMES, f"wire tool list is {TOOL_NAMES} (got {wire})")

    print("\n-- unknown tools are refused, not improvised -----------------------")
    for bad in ("query", "sql", "chat", "issue_for_agent", "shell"):
        r = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                            "params": {"name": bad, "arguments": {}}})
        check("error" in r and r["error"]["code"] == -32601,
              f"tools/call {bad!r} -> method-not-found")

    print("\n-- initialize advertises only tools --------------------------------")
    init = handle_request({"jsonrpc": "2.0", "id": 3, "method": "initialize",
                           "params": {}})
    caps = init["result"]["capabilities"]
    check(list(caps) == ["tools"], f"capabilities are tools-only (got {list(caps)})")
    check(init["result"]["protocolVersion"] == PROTOCOL_VERSION, "protocol version set")

    print("\n-- the Edge URL is pinned to loopback ------------------------------")
    for good in ("http://127.0.0.1:8790", "http://localhost:8790", "http://[::1]:8790"):
        try:
            assert_loopback(good)
            check(True, f"accepts {good}")
        except MCPError as exc:
            check(False, f"accepts {good} (refused: {exc})")
    for bad in ("http://10.0.0.5:8790", "https://api.openai.com",
                "http://evil.example.com", "http://169.254.169.254"):
        try:
            assert_loopback(bad)
            check(False, f"REFUSES {bad} (it was accepted)")
        except MCPError:
            check(True, f"refuses {bad}")

    print("\n-- the host cannot inject rows -------------------------------------")
    for key in ("records", "rows", "data", "payload"):
        r = handle_request({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                            "params": {"name": "execute", "arguments": {
                                "proposal": {"resource": "inventory_positions",
                                             "fields": ["sku"]},
                                key: [{"sku": "FAKE", "stolen": "x"}]}}})
        check("error" in r and key in r["error"]["message"],
              f"execute refuses host-supplied {key!r}")
    r = handle_request({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                        "params": {"name": "execute", "arguments": {
                            "proposal": {"resource": "customers_table",
                                         "fields": ["sku"]}}}})
    check("error" in r and "not configured" in r["error"]["message"],
          "execute refuses a resource the node was not configured for")
    r = handle_request({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                        "params": {"name": "execute", "arguments": {
                            "proposal": {"resource": "inventory_positions"}}}})
    check("error" in r and "no fields, no seal" in r["error"]["message"],
          "execute refuses a proposal with no fields (no fields, no seal)")

    print("\n-- opening refuses to hold the master key --------------------------")
    saved = os.environ.get("ATL_MASTER_KEY_HEX")
    os.environ["ATL_MASTER_KEY_HEX"] = "00" * 32
    os.environ.setdefault("ATL_NODE_KEY_HEX", "11" * 32)
    try:
        r = handle_request({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                            "params": {"name": "open_package",
                                       "arguments": {"package_b64": "AA=="}}})
        check("error" in r and "ATL_MASTER_KEY_HEX" in r["error"]["message"],
              "refuses to open while the master key is in the process")
    finally:
        if saved is None:
            os.environ.pop("ATL_MASTER_KEY_HEX", None)
        else:
            os.environ["ATL_MASTER_KEY_HEX"] = saved

    print("\n-- no provider client is imported ---------------------------------")
    from src.egress_invariant import scan_sources_for_egress

    findings = scan_sources_for_egress(paths=("src/mcp_server.py",),
                                       allow=("urllib.request",))
    check(not findings,
          f"only the loopback transport is imported (findings: {findings})")

    print()
    print("=" * 72)
    if failures:
        print(f"MCP CONNECTOR SELFTEST: FAIL ({len(failures)})")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("MCP CONNECTOR SELFTEST: PASS — three tools, loopback-pinned, no query tool")
    print("=" * 72)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--list-tools", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.list_tools:
        print(json.dumps(tool_definitions(), indent=2))
        return 0
    return serve_stdio()


if __name__ == "__main__":
    sys.exit(main())
