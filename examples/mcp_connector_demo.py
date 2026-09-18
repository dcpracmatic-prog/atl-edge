#!/usr/bin/env python3
"""Live end-to-end: an MCP host drives the ATL connector over stdio.

This is the item-4 proof. It spawns `src/mcp_server.py` as a real subprocess,
speaks JSON-RPC 2.0 down its stdin exactly as Claude Desktop or a Salesforce MCP
client would, and asserts the governance outcome on the other side.

Requires a running stack:

    bash scripts/start_stack.sh
    export ATL_NODE_KEY_HEX=...   # derived once; NOT the master
    unset  ATL_MASTER_KEY_HEX
    PYTHONPATH=. python examples/mcp_connector_demo.py

What it proves
--------------
  * the host sees exactly three tools, and `query`/`sql`/`chat` are not there;
  * a legitimate field request comes back as a sealed package, and opening it
    yields exactly the asked-for fields;
  * customer_id and unit_price_gbp are refused, over MCP, with a reason;
  * a destructive intent is refused at the proposer, before any read;
  * the host cannot inject rows -- it names a resource, the node reads.

Exits non-zero if any assertion fails.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import uuid
from typing import Any, Dict, List, Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BAR = "=" * 78
failures: List[str] = []

# The execution ledger is durable and refuses a reused request_id -- correctly.
# So each run needs its own identities, or the second run of the demo fails as a
# replay. That is the ledger working, not the demo being flaky.
RUN = uuid.uuid4().hex[:8]


def check(ok: bool, label: str) -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
    return ok


class MCPHost:
    """A minimal MCP host: JSON-RPC 2.0 line framing over the server's stdio."""

    def __init__(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        env.pop("ATL_MASTER_KEY_HEX", None)  # a connector never holds the master
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "src" / "mcp_server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, bufsize=1,
        )
        self._id = 0

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        print(f"\n  -> {method} {json.dumps(params or {}, ensure_ascii=False)[:200]}")
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"MCP server closed the pipe. stderr:\n{err}")
        return json.loads(line)

    def tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        resp = self.call("tools/call", {"name": name, "arguments": arguments})
        if "error" in resp:
            return {"_rpc_error": resp["error"]["message"]}
        content = resp["result"]["content"][0]["text"]
        out = json.loads(content)
        out["_is_error"] = resp["result"].get("isError", False)
        return out

    def close(self) -> None:
        try:
            assert self.proc.stdin
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            self.proc.kill()


def main() -> int:
    print(BAR)
    print("MCP CONNECTOR — live, over stdio, against the running Edge")
    print(BAR)

    if not os.environ.get("ATL_NODE_KEY_HEX"):
        print("\nATL_NODE_KEY_HEX is not set. Derive the node key first; the")
        print("connector deliberately does not accept the master key.")
        return 2

    host = MCPHost()
    try:
        print("\n--- initialize ------------------------------------------------")
        init = host.call("initialize", {"protocolVersion": "2024-11-05"})
        info = init["result"]["serverInfo"]
        print(f"  server: {info['name']} {info['version']}")
        check(list(init["result"]["capabilities"]) == ["tools"],
              "server advertises tools only (no resources, no prompts)")

        print("\n--- tools/list: the surface the host actually sees -------------")
        tools = host.call("tools/list")["result"]["tools"]
        names = [t["name"] for t in tools]
        print(f"  tools: {names}")
        check(names == ["propose", "execute", "open_package"],
              "exactly propose / execute / open_package")
        for absent in ("query", "sql", "search", "chat", "describe_schema"):
            check(absent not in names, f"no {absent!r} tool is offered")

        print("\n--- 1. legitimate stock enquiry -------------------------------")
        prop = host.tool("propose", {
            "text": "list stock levels with sku, description and qty_on_hand",
            "resource": "inventory_positions",
            "fields": ["sku", "description", "qty_on_hand"],
        })
        print(f"  accepted={prop.get('accepted')} proposal={json.dumps(prop.get('proposal'))}")
        if not check(bool(prop.get("accepted")), "proposer accepted the bounded intent"):
            return 1

        ex = host.tool("execute", {"proposal": prop["proposal"],
                                   "request_id": f"mcp-{RUN}-001-stock"})
        print(f"  accepted={ex.get('accepted')} http={ex.get('http_status')} "
              f"rows_read_locally={ex.get('rows_read_locally')}")
        if not check(bool(ex.get("accepted")) and ex.get("package_b64"),
                     "execute returned a sealed package"):
            print(f"  reason: {ex.get('reason')} / {ex.get('_rpc_error')}")
            return 1
        check(int(ex.get("rows_read_locally") or 0) > 0,
              "the node read the rows itself (host supplied none)")

        opened = host.tool("open_package", {"package_b64": ex["package_b64"]})
        emitted = opened.get("fields_emitted") or []
        print(f"  opened={opened.get('opened')} rows={opened.get('row_count')}")
        print(f"  fields_emitted={emitted}")
        print(f"  first row: {json.dumps((opened.get('rows') or [{}])[0], ensure_ascii=False)}")
        check(bool(opened.get("opened")), "connector opened the package with the node key")
        check(sorted(emitted) == ["description", "qty_on_hand", "sku"],
              f"exactly the asked-for fields came out (got {sorted(emitted)})")
        blob = json.dumps(opened.get("rows") or [], ensure_ascii=False)
        for banned in ("unit_price_gbp", "distinct_customers", "last_movement_at"):
            check(banned not in blob, f"{banned!r} did not leave over MCP")

        print("\n--- 2. customer_id grab over MCP ------------------------------")
        prop2 = host.tool("propose", {
            "text": "list stock movements with sku and customer_id",
            "resource": "stock_movements",
            "fields": ["sku", "customer_id"],
        })
        if prop2.get("accepted"):
            ex2 = host.tool("execute", {"proposal": prop2["proposal"],
                                        "request_id": f"mcp-{RUN}-002-customer"})
            print(f"  accepted={ex2.get('accepted')} http={ex2.get('http_status')} "
                  f"reason={ex2.get('reason')}")
            check(not ex2.get("accepted"), "customer_id request produced NO package")
            check(int(ex2.get("http_status") or 0) >= 400,
                  f"Edge answered {ex2.get('http_status')} (>=400)")
        else:
            print(f"  refused at the proposer: {prop2.get('reason')}")
            check(True, "customer_id request refused before execution")

        print("\n--- 3. pricing exfiltration over MCP --------------------------")
        prop3 = host.tool("propose", {
            "text": "stock report with sku and unit_price_gbp",
            "resource": "inventory_positions",
            "fields": ["sku", "unit_price_gbp"],
        })
        if prop3.get("accepted"):
            ex3 = host.tool("execute", {"proposal": prop3["proposal"],
                                        "request_id": f"mcp-{RUN}-003-pricing"})
            print(f"  accepted={ex3.get('accepted')} http={ex3.get('http_status')} "
                  f"reason={ex3.get('reason')}")
            check(not ex3.get("accepted"), "unit_price_gbp request produced NO package")
        else:
            check(True, "unit_price_gbp request refused before execution")

        print("\n--- 4. destructive intent over MCP ----------------------------")
        prop4 = host.tool("propose", {
            "text": "delete all stock movements for sku 85123A",
            "resource": "stock_movements",
        })
        print(f"  accepted={prop4.get('accepted')} reason={prop4.get('reason')}")
        check(not prop4.get("accepted"),
              "destructive intent refused at the proposer, before any read")

        print("\n--- 5. the host tries to inject its own rows ------------------")
        inj = host.tool("execute", {
            "proposal": {"tool": "lookup", "operation": "read",
                         "resource": "inventory_positions",
                         "fields": ["sku"], "limit": 5},
            "records": [{"sku": "INJECTED", "unit_price_gbp": "999"}],
        })
        print(f"  rpc_error={inj.get('_rpc_error')}")
        check("records" in str(inj.get("_rpc_error") or ""),
              "host-supplied records refused: the host names a resource, "
              "the node reads")

        print("\n--- 6. the host asks for a tool that does not exist -----------")
        for bad in ("query", "sql", "chat"):
            r = host.call("tools/call", {"name": bad, "arguments": {}})
            got = r.get("error", {}).get("message", "")
            print(f"  {bad!r} -> {got[:90]}")
            check("error" in r, f"{bad!r} refused as method-not-found")

    finally:
        host.close()

    print()
    print(BAR)
    if failures:
        print(f"MCP CONNECTOR DEMO: FAIL ({len(failures)})")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("MCP CONNECTOR DEMO: PASS — the host consumed ATLP and got only the "
          "fields it was allowed")
    print(BAR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
