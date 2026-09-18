#!/usr/bin/env python3
"""Console governance proof — the visible half of roadmap item 5.

The transcript half is `examples/inventory_trade_demo.py`. This one covers the
claim that an operator sitting in front of the console can *see* the outcome:
accepted vs rejected, which fields were emitted, which were withheld, bytes
retained vs bytes of the record, TTL and request_id, and a destructive or
"give me everything" attempt coming back 4xx with no package.

The console renders that from the `receipt` object on the execute response, so
this asserts the receipt is correct and complete. A panel is only as honest as
the numbers behind it; if the receipt were wrong, the console would be a
convincing lie, which is worse than no panel at all.

Run:  PYTHONPATH=. python testbench/console_governance_selftest.py
"""
from __future__ import annotations

import json
import os
import pathlib
import secrets
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BAR = "=" * 78
FAILURES: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


# A record where most of the row is none of the agent's business.
RECORDS = [
    {"id": 1, "region": "MX", "status": "active",
     "vip_notes": "escalate to founder, churn risk, discussed pricing floor",
     "ssn": "000-00-0001"},
    {"id": 2, "region": "MX", "status": "active",
     "vip_notes": "renewal owner is the CFO, do not contact directly",
     "ssn": "000-00-0002"},
]

SCENARIOS = [
    ("legitimate request for id, status", "accept",
     {"tool": "lookup", "operation": "read", "resource": "crm",
      "fields": ["id", "status"]}, None),
    ("give me everything", "reject",
     {"tool": "lookup", "operation": "read", "resource": "crm",
      "fields": ["id", "region", "status", "vip_notes", "ssn"]}, None),
    ("targeted grab of the sensitive column", "reject",
     {"tool": "lookup", "operation": "read", "resource": "crm",
      "fields": ["id", "ssn"]}, None),
    ("destructive request", "reject",
     {"tool": "delete", "operation": "delete", "resource": "crm",
      "fields": ["id"]}, None),
    ("no fields declared (no fields, no seal)", "reject",
     {"tool": "lookup", "operation": "read", "resource": "crm",
      "fields": []}, []),
]


def post(url: str, token: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": raw.decode(errors="replace")[:200]}


def main() -> int:
    from src.web_console import ConsoleState, serve

    print(BAR)
    print("ATL — console governance proof (the operator can SEE the outcome)")
    print(BAR)

    token = secrets.token_urlsafe(24)
    os.environ.setdefault("ATL_ALLOW_DEV_DEFAULTS", "1")
    tmp = tempfile.mkdtemp(prefix="atl-console-gov-")
    state = ConsoleState(pathlib.Path(tmp), token=token)
    httpd = serve("127.0.0.1", 0, state=state)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    base = f"http://127.0.0.1:{port}"
    print(f"  console on {base} (ephemeral port, loopback only)\n")

    try:
        for label, expect, proposal, fields_override in SCENARIOS:
            print(f"--- {label}")
            body = {
                "proposal": dict(proposal, schema_version=1, arguments={}),
                "records": RECORDS,
                "request_id": f"gov-{secrets.token_hex(4)}",
                "ttl_seconds": 90,
            }
            if fields_override is not None:
                body["fields"] = fields_override
            status, resp = post(f"{base}/api/work/execute", token, body)

            if expect == "reject":
                check(status >= 400, f"{label}: refused with {status}", str(status))
                check("receipt" not in resp and "package_b64" not in resp,
                      f"{label}: no package and no receipt in the response")
                check(bool(resp.get("error")),
                      f"{label}: the console has a reason to display",
                      str(resp.get("error"))[:70])
                print()
                continue

            check(status == 200, f"{label}: accepted", str(status))
            r = resp.get("receipt") or {}
            check(bool(r), f"{label}: the console receives a receipt to render")
            if not r:
                print()
                continue

            # These are exactly the five things the roadmap asked to be visible.
            check(r.get("decision") == "ACCEPTED", "receipt states the decision",
                  str(r.get("decision")))
            check(sorted(r.get("fields_emitted") or []) == ["id", "status"],
                  "receipt lists the emitted fields",
                  str(r.get("fields_emitted")))
            check(sorted(r.get("fields_withheld") or []) == ["region", "ssn", "vip_notes"],
                  "receipt lists the withheld fields",
                  str(r.get("fields_withheld")))
            rb, be, br = r.get("record_bytes"), r.get("bytes_emitted"), r.get("bytes_retained")
            check(isinstance(rb, int) and rb > 0 and isinstance(be, int) and be > 0,
                  "receipt carries record bytes and emitted bytes",
                  f"record={rb} emitted={be}")
            check(br == rb - be and br > 0,
                  "bytes retained is arithmetically consistent and positive",
                  f"retained={br} ({round(100 * br / rb, 1)}% of the record)")
            # The panel draws ONE ratio. If it drew package-vs-record instead,
            # a small row would paint as 100% emitted -- the opposite of true --
            # so assert the drawn ratio is the retained share and is sane.
            rp = r.get("retained_pct")
            check(isinstance(rp, (int, float)) and 0 < rp < 100,
                  "retained_pct is the drawn ratio and lies in (0,100)", str(rp))
            check(abs(rp - 100.0 * br / rb) < 0.05,
                  "retained_pct matches bytes_retained / record_bytes",
                  f"{rp} vs {round(100.0 * br / rb, 1)}")
            # This field was mislabelled on the first attempt: it was wired to
            # the data plane's byte_reduction_pct, which is the SAME ratio as
            # retained_pct, so the panel showed one number under two names.
            # Assert it is genuinely a different, positive overhead figure.
            po = r.get("package_overhead_pct")
            check(isinstance(po, (int, float)) and po > 0 and abs(po - rp) > 1.0,
                  "package overhead is a distinct, positive figure (not a relabel)",
                  f"overhead=+{po}% vs retained={rp}%")
            check(r.get("ttl_seconds") == 90 and isinstance(r.get("expiry"), (int, float)),
                  "receipt carries TTL and an absolute expiry",
                  f"ttl={r.get('ttl_seconds')}s expiry={r.get('expiry')}")
            check(str(r.get("request_id", "")).startswith("gov-"),
                  "receipt carries the request_id", str(r.get("request_id")))
            check(bool(r.get("policy_id")), "receipt names the policy",
                  str(r.get("policy_id")))
            check(r.get("package_bytes", 0) > 0, "a sealed package exists",
                  f"{r.get('package_bytes')} bytes")

            # The strongest assertion available here: the withheld VALUES are
            # absent from everything the console hands to the operator.
            blob = json.dumps(resp)
            leaked = [v for rec in RECORDS for k, v in rec.items()
                      if k in ("vip_notes", "ssn") and str(v) in blob]
            check(not leaked, "no withheld VALUE appears in the console response",
                  f"leaked={leaked}" if leaked else "checked vip_notes and ssn")
            print()
    finally:
        httpd.shutdown()

    print(BAR)
    if FAILURES:
        print(f"CONSOLE GOVERNANCE: FAIL ({len(FAILURES)})")
        for f in FAILURES:
            print(f"  - {f}")
        print(BAR)
        return 1
    print("CONSOLE GOVERNANCE: PASS — decision, fields, bytes, TTL and request_id")
    print("                    are all visible, and refusals carry no package")
    print(BAR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
