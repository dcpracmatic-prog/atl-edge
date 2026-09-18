#!/usr/bin/env python3
"""Node licence, not token licence — roadmap item 6.

The packaging claim is that the buyer licenses a NODE. That is only a claim
until something refuses a licence moved to a different node, so this asserts:

  * a licence bound to this node is accepted;
  * the same licence presented on another node is refused;
  * a licence signed with an EMPTY node_id -- which `verify_entitlement`
    accepts on any node, because it compares node_id only when the entitlement
    carries one -- is refused by the Edge. Without this, `max_nodes=1` is
    decoration and the licence is portable;
  * an expired licence is refused;
  * a tampered payload is refused;
  * the console still cannot issue a licence.

Run:  PYTHONPATH=. python testbench/node_licence_selftest.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.licensing import (  # noqa: E402
    Entitlement,
    EntitlementSigner,
    verify_entitlement,
)

BAR = "=" * 78
FAILURES: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def edge_accepts(signed, pub_pem: bytes, node_id: str) -> tuple[bool, str]:
    """Run the Edge's own entitlement path for `node_id`."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="atl-lic-"))
    ent_path = tmp / "entitlement.json"
    pub_path = tmp / "cp_public.pem"
    ent_path.write_text(json.dumps({"payload": signed.payload, "signature": signed.signature}))
    pub_path.write_bytes(pub_pem)

    saved = dict(os.environ)
    try:
        os.environ.update({
            "ATL_NODE_ID": node_id,
            "ATL_ENTITLEMENT_PATH": str(ent_path),
            "ATL_CONTROL_PLANE_PUBLIC_KEY_PATH": str(pub_path),
            "ATL_ALLOW_DEV_DEFAULTS": "1",  # so only the LICENCE can fail it
            "ATL_MASTER_KEY_HEX": "11" * 32,
        })
        os.environ.pop("ATL_LICENSE_ID", None)
        from src.edge_api_server import default_runtime_from_env
        default_runtime_from_env()
        return True, "accepted"
    except Exception as exc:  # noqa: BLE001 - the reason is the evidence
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        os.environ.clear()
        os.environ.update(saved)


def main() -> int:
    print(BAR)
    print("ATL — node licence enforcement (a licence that moves is not a node licence)")
    print(BAR)

    signer = EntitlementSigner.generate()
    pub = signer.public_key_pem()
    now = time.time()
    base = dict(license_id="lic-pilot-001", organization_id="org-buyer",
                plan="edge", issued_at=now - 60, expires_at=now + 86400,
                capabilities=("agent_access",))

    bound = signer.sign(Entitlement(**base, node_id="node-warehouse-01"))
    unbound = signer.sign(Entitlement(**base, node_id=""))
    expired = signer.sign(Entitlement(**dict(base, issued_at=now - 7200,
                                             expires_at=now - 3600),
                                      node_id="node-warehouse-01"))

    print("\n--- the licence the buyer is sold")
    ok, why = edge_accepts(bound, pub, "node-warehouse-01")
    check(ok, "licence bound to this node is accepted", why)

    print("\n--- the same file copied to a second node")
    ok, why = edge_accepts(bound, pub, "node-warehouse-02")
    check(not ok, "the same licence is REFUSED on another node", why[:110])

    print("\n--- a licence signed without a node_id")
    # verify_entitlement() alone lets this through on any node. That is the hole
    # this test exists for.
    portable = True
    for node in ("node-a", "node-b", "node-z"):
        try:
            verify_entitlement(unbound, pub, node_id=node)
        except ValueError:
            portable = False
    check(portable, "crypto layer alone would accept it on every node "
                    "(this is why the Edge must check)", "confirmed portable")
    ok, why = edge_accepts(unbound, pub, "node-a")
    check(not ok, "the Edge REFUSES an unbound entitlement", why[:130])
    check("node_id" in why, "the refusal names the reason the operator must fix",
          why[:90])

    print("\n--- expiry and tampering")
    ok, why = edge_accepts(expired, pub, "node-warehouse-01")
    check(not ok, "an expired licence is refused", why[:100])

    class Tampered:
        payload = dict(bound.payload, max_nodes=999, plan="enterprise")
        signature = bound.signature

    ok, why = edge_accepts(Tampered(), pub, "node-warehouse-01")
    check(not ok, "a tampered payload is refused (signature covers it)", why[:100])

    print("\n--- the console does not license")
    console_src = (ROOT / "src" / "web_console.py").read_text(encoding="utf-8")
    check("EntitlementSigner" not in console_src,
          "the console cannot sign an entitlement (no signer imported)")
    check("/api/licenses" not in console_src and "issue_entitlement" not in console_src,
          "the console exposes no licence-issuing route")

    print()
    print(BAR)
    if FAILURES:
        print(f"NODE LICENCE: FAIL ({len(FAILURES)})")
        for f in FAILURES:
            print(f"  - {f}")
        print(BAR)
        return 1
    print("NODE LICENCE: PASS — bound to one node, refused elsewhere, refused unbound")
    print(BAR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
