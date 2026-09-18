#!/usr/bin/env python3
"""CI guard: the MCP connector's tool surface stays closed at three.

The commercial claim for the connector is narrow and testable: it *consumes*
ATLP and offers no way to query the underlying data. That claim dies quietly the
first time someone adds a helpful `search` or `describe_schema` tool, and no
existing test would notice -- everything would still pass, the product would
just no longer be the product.

So this asserts, from the outside:

  1. the advertised tool list is EXACTLY propose / execute / open_package;
  2. none of the forbidden names appear, in the list or as an implementation;
  3. tools/call on a forbidden name is method-not-found, not improvised;
  4. `initialize` advertises tools only -- no resources/prompts surface that
     could hand back rows by another route;
  5. the Edge URL is pinned to loopback, so the adapter cannot become the
     outbound path the product invariant denies;
  6. the adapter imports no provider client (only the loopback transport);
  7. `--self-test` injects a forbidden tool and asserts THIS guard catches it,
     so a guard that silently stopped working cannot keep reporting PASS.

Usage:
    python scripts/check_mcp_surface.py
    python scripts/check_mcp_surface.py --self-test --json /tmp/mcp_surface.json
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

EXPECTED_TOOLS = ("propose", "execute", "open_package")
ADAPTER = "src/mcp_server.py"

failures: list[str] = []
results: list[dict] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")
    if detail:
        print(f"       {detail}")
    results.append({"ok": bool(ok), "label": label, "detail": detail})
    if not ok:
        failures.append(label)
    return ok


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args(argv)

    from src.mcp_server import (
        FORBIDDEN_TOOL_NAMES,
        TOOL_IMPLS,
        TOOL_NAMES,
        assert_loopback,
        handle_request,
        tool_definitions,
    )
    from src.egress_invariant import scan_sources_for_egress

    print("=" * 72)
    print("MCP SURFACE GUARD — three tools, no query tool, loopback only")
    print("=" * 72)

    # 1 + 2: the closed list.
    declared = tuple(t["name"] for t in tool_definitions())
    check(declared == EXPECTED_TOOLS,
          f"advertised tools are exactly {list(EXPECTED_TOOLS)}",
          f"got {list(declared)}")
    check(TOOL_NAMES == EXPECTED_TOOLS,
          "TOOL_NAMES constant matches the advertised list",
          f"got {list(TOOL_NAMES)}")
    check(tuple(TOOL_IMPLS) == EXPECTED_TOOLS,
          "implementations match the advertised list (no hidden handler)",
          f"got {list(TOOL_IMPLS)}")
    overlap = sorted(set(declared) & set(FORBIDDEN_TOOL_NAMES))
    check(not overlap, "no forbidden tool name is exposed", f"overlap: {overlap}")

    # 3: forbidden names are refused on the wire.
    refused_all = True
    for bad in FORBIDDEN_TOOL_NAMES:
        r = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": bad, "arguments": {}}})
        if "error" not in r or r["error"].get("code") != -32601:
            refused_all = False
            print(f"       {bad!r} was NOT refused as method-not-found: {r}")
    check(refused_all,
          f"all {len(FORBIDDEN_TOOL_NAMES)} forbidden names are method-not-found")

    # 4: initialize advertises tools only.
    init = handle_request({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                           "params": {}})
    caps = list(init["result"]["capabilities"])
    check(caps == ["tools"], "initialize advertises tools only", f"got {caps}")

    # 5: loopback pin.
    pin_ok = True
    for good in ("http://127.0.0.1:8790", "http://localhost:8790", "http://[::1]:8790"):
        try:
            assert_loopback(good)
        except Exception as exc:  # noqa: BLE001
            pin_ok = False
            print(f"       rejected a loopback URL {good}: {exc}")
    for bad in ("http://10.0.0.5:8790", "https://api.openai.com",
                "http://evil.example.com", "http://169.254.169.254",
                "http://metadata.google.internal"):
        try:
            assert_loopback(bad)
            pin_ok = False
            print(f"       ACCEPTED a non-loopback URL: {bad}")
        except Exception:  # noqa: BLE001,S110
            pass
    check(pin_ok, "Edge URL is pinned to loopback (remote hosts refused)")

    # 6: no provider client. urllib.request is the one allowed transport, and it
    # is allowed only because this adapter is not on the sealing path.
    findings = scan_sources_for_egress(paths=(ADAPTER,), allow=("urllib.request",))
    check(not findings,
          f"{ADAPTER} imports no provider client",
          f"findings: {[f.module for f in findings]}" if findings else "")

    # 7: does the guard actually catch a violation?
    if args.self_test:
        print()
        print("Guard self-test (does it fail when it should?)")
        src = (ROOT / ADAPTER).read_text(encoding="utf-8")
        caught = []

        # a) a forbidden tool added to the advertised list
        injected = src.replace(
            'TOOL_NAMES: Tuple[str, ...] = ("propose", "execute", "open_package")',
            'TOOL_NAMES: Tuple[str, ...] = ("propose", "execute", "open_package", "query")',
        )
        caught.append(("tool list grew a 'query' entry", injected != src))

        # b) the loopback pin removed
        injected2 = src.replace("    if not ip.is_loopback:", "    if False:")
        caught.append(("loopback pin removed", injected2 != src))

        for label, did_change in caught:
            print(f"  self-test  {label}: "
                  f"{'injectable' if did_change else 'ANCHOR MISSING'}")
            if not did_change:
                failures.append(f"self-test anchor missing: {label}")

        # Actually run the injected variant and confirm this guard fails on it.
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            (tmp / "src").mkdir()
            for f in (ROOT / "src").glob("*.py"):
                (tmp / "src" / f.name).write_text(f.read_text(encoding="utf-8"),
                                                 encoding="utf-8")
            (tmp / "scripts").mkdir()
            (tmp / "scripts" / "check_mcp_surface.py").write_text(
                (ROOT / "scripts" / "check_mcp_surface.py").read_text(encoding="utf-8"),
                encoding="utf-8")
            # Inject: advertise a query tool.
            adapter = tmp / "src" / "mcp_server.py"
            text = adapter.read_text(encoding="utf-8")
            text = text.replace(
                '            "name": "propose",',
                '            "name": "query",', 1)
            adapter.write_text(text, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "scripts/check_mcp_surface.py"],
                cwd=tmp, capture_output=True, text=True,
                env={**dict(PATH=str(pathlib.Path(sys.executable).parent)),
                     "PYTHONPATH": str(tmp)},
            )
            check(proc.returncode != 0,
                  "the guard FAILS when a query tool is advertised",
                  f"exit={proc.returncode}")

        # c) confirm the AST-level check would see an added implementation
        # A tool implementation is `tool_<name>` for a name in the registry.
        # `tool_definitions` shares the prefix without being one, so match on
        # the registry rather than on the prefix -- an over-broad pattern here
        # would report a violation that is not one, which is exactly the kind of
        # noise that gets a guard disabled.
        tree = ast.parse(src)
        defined = {
            n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
        }
        expected_impls = {f"tool_{name}" for name in EXPECTED_TOOLS}
        missing = sorted(expected_impls - defined)
        extra = sorted(
            n for n in defined
            if n.startswith("tool_")
            and n not in expected_impls
            and n != "tool_definitions"
        )
        check(not missing and not extra,
              "exactly the three expected tool implementations exist",
              f"missing={missing} unexpected={extra}")

    payload = {
        "expected_tools": list(EXPECTED_TOOLS),
        "advertised_tools": list(declared),
        "forbidden_names_checked": len(FORBIDDEN_TOOL_NAMES),
        "checks": results,
        "ok": not failures,
        "failures": failures,
    }
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(payload, indent=2),
                                               encoding="utf-8")

    print()
    if failures:
        print(f"MCP SURFACE: BROKEN ({len(failures)})")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("MCP SURFACE: CLOSED — propose / execute / open_package, loopback only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
