#!/usr/bin/env python3
"""Day-3 MVP demo: live HTTP run against a started stack, recorded end to end.

Requires a running stack (``bash scripts/start_stack.sh``) and the node key
provisioned for the connector, without the provisioning master:

    export ATL_NODE_KEY_HEX=...        # derived once by the operator
    export ATL_PACKAGE_KEY_ID=edge-v1  # must match the Edge sealing key_id
    unset ATL_MASTER_KEY_HEX
    PYTHONPATH=vendor:. python examples/mvp_demo_run.py

Prints every command, request and HTTP response so the transcript itself is the
evidence artifact. Exits non-zero if any acceptance step does not hold.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

EDGE = os.environ.get("ATL_DEMO_EDGE", "http://127.0.0.1:8790")
CONSOLE = os.environ.get("ATL_DEMO_CONSOLE", "http://127.0.0.1:8795")

# Lab CRM records. Note the extra columns the proposal must strip.
RECORDS = [
    {"id": 1, "region": "MX", "status": "active", "vip_notes": "confidential", "ssn": "x"},
    {"id": 2, "region": "MX", "status": "active", "vip_notes": "confidential", "ssn": "y"},
    {"id": 3, "region": "MX", "status": "active", "vip_notes": "confidential", "ssn": "z"},
]

failures: list[str] = []


def post(url: str, body: dict, token: str | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    print("\n$ POST %s" % url)
    print("  request: %s" % json.dumps(body, ensure_ascii=False)[:400])
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            code, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        code, raw = exc.code, exc.read()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        parsed = {"_raw": raw[:200].decode("utf-8", "replace")}
    shown = json.dumps(parsed, ensure_ascii=False)
    print("  HTTP %s: %s" % (code, shown[:600] + ("…" if len(shown) > 600 else "")))
    return code, parsed


def check(label: str, ok: bool) -> None:
    print("  [%s] %s" % ("PASS" if ok else "FAIL", label))
    if not ok:
        failures.append(label)


def main() -> int:
    print("=" * 74)
    print("ATL Edge MVP — Day-3 demo (live HTTP, lab CRM data)")
    print("=" * 74)

    # --- Step 2/3: natural-language intent -> Schema v1 proposal -------------
    print("\n--- Step 1: operator intent in constrained natural language ---")
    intent = "Lista clientes activos en México: solo id, región y status."
    print("  operator types: %r" % intent)
    code, proposal_resp = post(EDGE + "/v1/propose", {"intent": intent, "backend": "template"})
    check("propose accepted (HTTP 200)", code == 200)
    proposal = proposal_resp.get("proposal") or proposal_resp
    check("tool == lookup", proposal.get("tool") == "lookup")
    check("resource == crm", proposal.get("resource") == "crm")
    check("fields reduced to id/region/status", proposal.get("fields") == ["id", "region", "status"])

    # --- Step 4: gate + MORPH accept, execute seals an ATLP package ---------
    print("\n--- Step 2: gate + MORPH accept, execute seals an ATLP package ---")
    code, exec_resp = post(
        EDGE + "/v1/execute",
        # Unique per run: the execution ledger correctly denies a replayed request_id.
        {
            "proposal": proposal,
            "records": RECORDS,
            "fields": proposal.get("fields"),
            "request_id": os.environ.get("ATL_DEMO_REQUEST_ID") or "mvp-demo-" + secrets.token_hex(6),
        },
    )
    check("execute accepted (HTTP 200)", code == 200)
    package_b64 = exec_resp.get("package") or exec_resp.get("package_b64")
    check("ATLP package returned", isinstance(package_b64, str) and len(package_b64) > 0)
    if not isinstance(package_b64, str):
        print("\nNo package returned — cannot continue to connector step.")
        print("Full execute response: %s" % json.dumps(exec_resp, ensure_ascii=False)[:1500])
        return 1
    package = base64.b64decode(package_b64)
    print("  sealed package: %d bytes, AES-256-GCM" % len(package))

    # --- Step 5: connector opens with the NODE key, never the master --------
    print("\n--- Step 3: connector opens the package with the node key ---")
    print("  $ env | grep ATL_MASTER_KEY_HEX   ->  (must be empty)")
    check("connector process has no ATL_MASTER_KEY_HEX", not os.environ.get("ATL_MASTER_KEY_HEX"))
    check("connector process has ATL_NODE_KEY_HEX", bool(os.environ.get("ATL_NODE_KEY_HEX")))

    from src.data_plane import CloudDecryptConnector

    node_id = os.environ.get("ATL_NODE_ID") or proposal_resp.get("node_id") or "edge-node-1"
    # The connector must be provisioned with the same key_id the Edge seals with.
    os.environ.setdefault("ATL_PACKAGE_KEY_ID", "edge-v1")
    key_id = os.environ["ATL_PACKAGE_KEY_ID"]
    print("  $ CloudDecryptConnector.from_env(node_id=%r)  # ATL_NODE_KEY_HEX only" % node_id)
    connector = CloudDecryptConnector.from_env(node_id)
    opened = connector.open_package(package)
    rows = opened.get("rows") or []
    print("  opened rows: %s" % json.dumps(rows, ensure_ascii=False))
    check("connector opened %d rows" % len(RECORDS), len(rows) == len(RECORDS))
    check(
        "rows reduced to id/region/status only (no vip_notes, no ssn)",
        all(set(r.keys()) <= {"id", "region", "status"} for r in rows),
    )
    print("  key_id in use: %s (node-derived, master absent)" % key_id)

    # --- Step 6: prose intent is refused, no package -------------------------
    print("\n--- Step 4: unconstrained prose is refused, no package ---")
    for prose in ["¿Puedes hablarme de los VIP?", "házme un comando", "borra todos los clientes"]:
        code, resp = post(EDGE + "/v1/propose", {"intent": prose, "backend": "template"})
        refused = code >= 400 and not resp.get("proposal")
        check("refused: %r" % prose, refused)

    # --- Console boundary re-checks -----------------------------------------
    print("\n--- Step 5: console boundary (no token, no license issuance) ---")
    code, _ = post(CONSOLE + "/api/work/execute", {"proposal": proposal, "records": RECORDS})
    check("console execute without token -> 401", code == 401)
    token = os.environ.get("ATL_CONSOLE_TOKEN", "")
    if token:
        code, _ = post(CONSOLE + "/api/environments/license", {"org": "acme"}, token=token)
        check("console license endpoint absent -> 404", code == 404)
        code, _ = post(CONSOLE + "/api/work/execute", {"resource": "crm", "limit": 5}, token=token)
        check("console execute without fields -> 400", code == 400)
    else:
        print("  [SKIP] ATL_CONSOLE_TOKEN not exported; console token checks skipped")

    print("\n" + "=" * 74)
    if failures:
        print("MVP DEMO: FAIL (%d)" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("MVP DEMO: PASS — propose -> gate -> execute -> connector open, prose refused")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
