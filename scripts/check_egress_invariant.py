#!/usr/bin/env python3
"""CI guard for the ATL product invariant: the node initiates nothing.

Fails the build if either half of the invariant breaks:

  1. the shipped gate policy would admit a tool that looks like an outbound call;
  2. any module on the sealing path imports a client that can reach the network.

Run:  PYTHONPATH=. python scripts/check_egress_invariant.py [--json OUT]

Exit 0 when the invariant holds, 1 when it does not. Designed to be the job that
turns the commercial claim into something a buyer can re-run themselves, rather
than a sentence in a datasheet.

There is also a --self-test mode that injects a violation into a scratch copy of
the tree and asserts the guard catches it. A guard nobody has ever seen fail is
not evidence, so CI runs that too.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from src.egress_invariant import (  # noqa: E402
    EGRESS_MODULES,
    GUARDED_SOURCES,
    INVARIANT_TEXT,
    check_invariant,
    scan_sources_for_egress,
)


def _self_test() -> bool:
    """Prove the scanner fails on a real violation and ignores a benign one."""
    root = pathlib.Path(__file__).resolve().parent.parent
    ok = True
    with tempfile.TemporaryDirectory() as td:
        scratch = pathlib.Path(td) / "repo"
        (scratch / "src").mkdir(parents=True)
        for rel in GUARDED_SOURCES:
            shutil.copy2(root / rel, scratch / rel)

        must_trip = [
            ("src/mvp.py", "import requests"),
            ("src/result_packaging.py", "from urllib.request import urlopen"),
            ("src/atl_core.py", "import openai"),
            ("src/data_plane.py", "import socket"),
        ]
        for rel, stmt in must_trip:
            f = scratch / rel
            orig = f.read_text(encoding="utf-8")
            f.write_text(stmt + "\n" + orig, encoding="utf-8")
            found = [x for x in scan_sources_for_egress(root=scratch) if x.path == rel]
            status = "caught" if found else "MISSED"
            if not found:
                ok = False
            print(f"  self-test  {rel}: {stmt!r} -> {status}")
            f.write_text(orig, encoding="utf-8")

        # urllib.parse is pure string work; flagging it would make the guard noise.
        f = scratch / "src/mvp.py"
        orig = f.read_text(encoding="utf-8")
        f.write_text("import urllib.parse\n" + orig, encoding="utf-8")
        if scan_sources_for_egress(root=scratch):
            print("  self-test  urllib.parse -> FALSE POSITIVE")
            ok = False
        else:
            print("  self-test  urllib.parse -> correctly ignored")
        f.write_text(orig, encoding="utf-8")
    return ok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    print("=" * 74)
    print("ATL product invariant")
    print("=" * 74)
    print(INVARIANT_TEXT)
    print()

    ok, evidence = check_invariant()

    pol = evidence.get("policy") or {}
    if evidence.get("policy_ok"):
        print(f"[PASS] gate policy admits only: {pol.get('allow_tools')}")
        print(f"       policy_id={pol.get('policy_id')} hash={pol.get('policy_hash')}")
        print(f"       {pol.get('forbidden_checked')} egress tool names checked, none admitted")
    else:
        print(f"[FAIL] {evidence.get('policy_error')}")

    if evidence.get("sources_ok"):
        print(
            f"[PASS] no outbound client in {len(GUARDED_SOURCES)} sealing-path modules "
            f"({len(EGRESS_MODULES)} egress modules checked)"
        )
    else:
        print("[FAIL] outbound client on the sealing path:")
        for f in evidence.get("findings", []):
            print(f"       {f}")

    if args.self_test:
        print()
        print("Guard self-test (does it fail when it should?)")
        if _self_test():
            print("[PASS] guard detects injected violations and ignores benign imports")
            evidence["self_test_ok"] = True
        else:
            print("[FAIL] guard did not behave correctly on injected violations")
            evidence["self_test_ok"] = False
            ok = False

    evidence["ok"] = ok
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json_out}")

    print()
    print("INVARIANT:", "HOLDS" if ok else "VIOLATED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
