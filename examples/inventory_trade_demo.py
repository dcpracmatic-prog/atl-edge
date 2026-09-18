#!/usr/bin/env python3
"""The inventory trade, end to end, on real data — with a governance receipt.

This is the one buyer flow. It is not a selftest with three invented columns: the
records are 1,690 real SKUs and 6,000 real transaction lines from a UK retailer's
2010-2011 ledger (UCI "Online Retail", CC BY 4.0 — see
`datasets/inventory/SOURCE.md`).

The success criterion is deliberately not "the model answered". It is:

    you asked for sku, description, qty_on_hand;
    the package contains exactly those;
    unit_price_gbp, distinct_customers, customer_id and country did not leave.

And the receipt has to make that *visible*, because the interesting property of
this product is not that it works, it is that you can see nobody got the table.
So the transcript prints, for every request: the decision, the fields emitted,
the bytes withheld against the bytes of the source row, the TTL, the request_id,
and what happened to the requests that should fail.

Run:
    PYTHONPATH=. python examples/inventory_trade_demo.py
    PYTHONPATH=. python examples/inventory_trade_demo.py --json /tmp/receipt.json

Exits non-zero if any governance assertion does not hold.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tempfile
from typing import Any, Dict, List, Sequence, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from src.data_plane import (  # noqa: E402
    CloudDecryptConnector,
    LocalDataPlane,
    OnPremAuditLog,
    PackageCrypto,
    node_key,
)
from src.inventory_catalog import (  # noqa: E402
    MOVEMENTS_ASSET,
    OPERATOR_VISIBLE_FIELDS,
    POSITIONS_ASSET,
    WITHHELD_BY_DESIGN,
    build_inventory_catalog,
    dataset_available,
    inventory_node_policy,
    load_movements,
    load_positions,
)
from src.mvp import ATLDataPlaneMVP  # noqa: E402
from src.proposal_gate import ProposalGate, default_proposal_policy  # noqa: E402
from src.proposer import ConstrainedDecodeError, propose_detailed  # noqa: E402

NODE_ID = "node-warehouse-01"
KEY_ID = "inv-demo-v1"

BAR = "=" * 78
failures: List[str] = []
receipt: Dict[str, Any] = {"requests": []}


def check(ok: bool, label: str) -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
    return ok


def build_stack(tmp: pathlib.Path) -> Tuple[ATLDataPlaneMVP, CloudDecryptConnector]:
    master = b"\x11" * 32
    crypto = PackageCrypto.from_master(master, NODE_ID, key_id=KEY_ID)
    audit = OnPremAuditLog(tmp / "audit.jsonl")
    dp = LocalDataPlane(crypto, audit)
    gate = ProposalGate(policy=default_proposal_policy())
    catalog = build_inventory_catalog()
    mvp = ATLDataPlaneMVP(
        gate,
        dp,
        catalog=catalog,
        node_access=inventory_node_policy(NODE_ID),
        require_fields=True,
        ledger_path=str(tmp / "ledger.sqlite3"),
    )
    # The connector is a SEPARATE identity holding only the derived node key.
    # It never sees `master`. This is the property the demo has to show, so the
    # connector is built from the node key rather than reusing `crypto`.
    connector = CloudDecryptConnector(
        PackageCrypto.from_node_key(node_key(master, NODE_ID), NODE_ID, key_id=KEY_ID)
    )
    return mvp, connector


def row_bytes(record: Dict[str, Any]) -> int:
    return len(json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode())


def run_request(
    mvp: ATLDataPlaneMVP,
    connector: CloudDecryptConnector,
    *,
    title: str,
    operator_text: str,
    resource: str,
    records: Sequence[Dict[str, Any]],
    expect_allowed: bool,
    request_id: str,
    ttl_seconds: int = 120,
    force_fields: Sequence[str] | None = None,
) -> None:
    print()
    print(BAR)
    print(f"REQUEST  {title}")
    print(BAR)
    print(f'  operator says: "{operator_text}"')

    # Declare the FULL column vocabulary, including the columns that must never
    # leave. Naming them is not permitting them -- it means a grab for
    # customer_id is refused by the access layer with an honest reason
    # (field_not_allowed) instead of being mistaken for an unknown API tool.
    vocabulary = sorted(set(records[0].keys()) | set(OPERATOR_VISIBLE_FIELDS[resource]))

    base_entry: Dict[str, Any] = {
        "title": title,
        "operator_text": operator_text,
        "request_id": request_id,
        "resource": resource,
        "expect_allowed": expect_allowed,
    }

    # The proposer is the FIRST boundary. A destructive or prose intent is
    # refused here, before a proposal object exists at all -- so nothing
    # downstream ever gets the chance to accept it.
    try:
        det = propose_detailed(
            operator_text,
            default_resource=resource,
            default_fields=list(OPERATOR_VISIBLE_FIELDS[resource]),
            known_fields=vocabulary,
        )
    except ConstrainedDecodeError as exc:
        print(f"  proposer:      REFUSED at the proposer boundary")
        print(f"  DECISION:      REJECTED — no proposal was ever built")
        print(f"                 {exc}")
        base_entry.update(decision="REJECTED", refused_at="proposer",
                          error=f"ConstrainedDecodeError: {exc}",
                          executor_ran=False, package_issued=False)
        check(not expect_allowed, f"{title}: rejected as expected (at the proposer)")
        receipt["requests"].append(base_entry)
        return

    proposal = dict(det.proposal)
    proposal["resource"] = resource
    if force_fields is not None:
        proposal["fields"] = list(force_fields)
    fields = list(proposal.get("fields") or ())

    print(f"  proposer:      backend={det.backend} constrained={det.constrained} source={det.source}")
    print(f"  proposal:      tool={proposal.get('tool')!r} operation={proposal.get('operation')!r} "
          f"resource={resource!r}")
    print(f"  fields asked:  {fields}")

    entry: Dict[str, Any] = dict(base_entry)
    entry.update(
        proposal_tool=proposal.get("tool"),
        proposal_operation=proposal.get("operation"),
        fields_requested=fields,
        refused_at=None,
    )

    ran = {"flag": False}

    def executor(p):  # noqa: ANN001
        ran["flag"] = True
        return {"rows": len(records)}

    try:
        result = mvp.execute_and_issue(
            proposal,
            list(records),
            executor=executor,
            fields=fields or None,
            request_id=request_id,
            ttl_seconds=ttl_seconds,
            requester="warehouse-console",
            purpose="stock-enquiry",
        )
    except Exception as exc:
        print(f"  DECISION:      REJECTED — {type(exc).__name__}: {exc}")
        entry.update(decision="REJECTED", refused_at="data-plane boundary",
                     error=f"{type(exc).__name__}: {exc}",
                     executor_ran=ran["flag"], package_issued=False)
        check(not expect_allowed, f"{title}: rejected as expected")
        check(not ran["flag"], f"{title}: business executor never ran")
        receipt["requests"].append(entry)
        return

    print("  DECISION:      ACCEPTED")
    if not expect_allowed:
        entry.update(decision="ACCEPTED", executor_ran=ran["flag"], package_issued=True)
        check(False, f"{title}: should have been rejected but a package was issued")
        receipt["requests"].append(entry)
        return

    issue = result.issue
    metrics = dict(issue.metrics)

    # The connector side: a separate identity, holding only the node key.
    payload = connector.open_package(issue.package)
    emitted_rows = payload.get("rows") if isinstance(payload, dict) else payload
    if isinstance(emitted_rows, dict):
        emitted_rows = [emitted_rows]
    emitted_rows = emitted_rows or []
    opened_blob = json.dumps(payload, ensure_ascii=False)

    emitted_fields = sorted({k for r in emitted_rows if isinstance(r, dict) for k in r})
    source_fields = sorted(records[0].keys())
    withheld = [f for f in source_fields if f not in emitted_fields]

    src_bytes = sum(row_bytes(r) for r in records)
    pkg_payload_bytes = int(metrics.get("predigest_chars", 0))
    raw_chars = int(metrics.get("raw_chars", src_bytes))
    retained = raw_chars - pkg_payload_bytes

    print()
    print("  --- GOVERNANCE RECEIPT " + "-" * 53)
    print(f"  request_id            {request_id}")
    print(f"  ttl_seconds           {ttl_seconds}")
    print(f"  policy_id             {result.gate.policy_id}")
    print(f"  asset / sensitivity   {metrics.get('asset_id')} / {metrics.get('effective_sensitivity')}")
    print(f"  protection_profile    {metrics.get('protection_profile')}")
    print(f"  classification_gate   {metrics.get('classification_gate')}")
    print(f"  rows in / rows out    {len(records)} / {len(emitted_rows)}"
          + (f"   (proposal limit={proposal.get('limit')} capped the result)"
             if len(emitted_rows) < len(records) else ""))
    print(f"  fields emitted        {emitted_fields}")
    print(f"  fields WITHHELD       {withheld}")
    print(f"  record bytes          {raw_chars:,}")
    print(f"  bytes emitted         {pkg_payload_bytes:,}")
    print(f"  bytes RETAINED        {retained:,}  ({metrics.get('byte_reduction_pct')}% of the record never left)")
    print(f"  sealed package        {metrics.get('package_bytes'):,} bytes")
    print(f"  opened by connector   node_id={NODE_ID} key_id={KEY_ID} (node key, not master)")
    print("  " + "-" * 76)

    entry.update(
        decision="ACCEPTED",
        executor_ran=ran["flag"],
        package_issued=True,
        ttl_seconds=ttl_seconds,
        policy_id=result.gate.policy_id,
        asset_id=metrics.get("asset_id"),
        effective_sensitivity=metrics.get("effective_sensitivity"),
        protection_profile=metrics.get("protection_profile"),
        rows_in=len(records),
        rows_out=len(emitted_rows),
        row_limit=proposal.get("limit"),
        fields_emitted=emitted_fields,
        fields_withheld=withheld,
        record_bytes=raw_chars,
        bytes_emitted=pkg_payload_bytes,
        bytes_retained=retained,
        byte_reduction_pct=metrics.get("byte_reduction_pct"),
        package_bytes=metrics.get("package_bytes"),
    )

    # The assertions that make this a proof rather than a printout.
    check(sorted(fields) == emitted_fields,
          f"{title}: emitted fields are exactly what was asked ({fields})")
    for banned in WITHHELD_BY_DESIGN[resource]:
        check(banned not in emitted_fields, f"{title}: {banned!r} did not leave")
    # Key absence is necessary but not sufficient -- a leak could arrive under a
    # renamed key. So also search the plaintext for the withheld VALUES.
    # Caveat stated plainly: this substring search is only meaningful for values
    # distinctive enough not to collide by chance. `distinct_customers` is a
    # single digit and occurs inside unrelated quantities, so testing it would
    # report a leak that is not one. Short values are covered by the key-absence
    # assertion above and by the field-equality assertion; only values of >=4
    # characters get the substring test.
    for banned in WITHHELD_BY_DESIGN[resource]:
        sample_vals = {
            str(r.get(banned)) for r in records
            if r.get(banned) not in (None, "") and len(str(r.get(banned))) >= 4
        }
        if not sample_vals:
            print(f"  [note] {banned!r}: values too short for a substring test; "
                  f"covered by key-absence assertion only")
            continue
        leaked = sorted(v for v in sample_vals if v in opened_blob)
        check(not leaked,
              f"{title}: no {banned!r} VALUE appears anywhere in the plaintext"
              + (f" (leaked: {leaked[:3]})" if leaked else ""))
    check(retained > 0, f"{title}: bytes were actually retained, not just relabelled")

    receipt["requests"].append(entry)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args(argv)

    print(BAR)
    print("ATL — inventory trade on real data (UCI Online Retail, CC BY 4.0)")
    print(BAR)

    if not dataset_available():
        print("\nDataset missing. Build it first:")
        print("  python scripts/fetch_inventory_dataset.py")
        return 2

    positions = load_positions(limit=50)
    movements = load_movements(limit=50)
    print(f"  loaded {len(positions)} inventory positions, {len(movements)} stock movements")
    print(f"  a source position row: {json.dumps(positions[0], ensure_ascii=False)}")
    print(f"  a source movement row: {json.dumps(movements[0], ensure_ascii=False)}")
    print("\n  Note both source rows carry unit_price_gbp, and movements carry a real")
    print("  customer_id and country. Nothing below filters them on the way in --")
    print("  the boundary has to do it, or the demo proves nothing.")

    receipt["dataset"] = {
        "source": "UCI Online Retail (dataset 352)",
        "url": "https://archive.ics.uci.edu/dataset/352/online+retail",
        "licence": "CC BY 4.0",
        "positions_loaded": len(positions),
        "movements_loaded": len(movements),
        "position_source_fields": sorted(positions[0].keys()),
        "movement_source_fields": sorted(movements[0].keys()),
    }

    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        mvp, connector = build_stack(tmp)

        # 1. The legitimate stock enquiry.
        run_request(
            mvp, connector,
            title="Stock enquiry (legitimate)",
            operator_text="list stock levels with sku, description and qty_on_hand, limit 50",
            resource=POSITIONS_ASSET,
            records=positions,
            expect_allowed=True,
            request_id="inv-001-stock-enquiry",
            force_fields=["sku", "description", "qty_on_hand"],
        )

        # 2. Movement history: the row holds a real customer_id, which must not come out.
        run_request(
            mvp, connector,
            title="Movement history (legitimate, row contains personal data)",
            operator_text="show recent stock movements with sku, qty and moved_at",
            resource=MOVEMENTS_ASSET,
            records=movements,
            expect_allowed=True,
            request_id="inv-002-movements",
            force_fields=["sku", "qty", "moved_at"],
        )

        # 3. "Give me everything."
        run_request(
            mvp, connector,
            title='"Give me everything" (must be refused)',
            operator_text="give me the full movements table, every column",
            resource=MOVEMENTS_ASSET,
            records=movements,
            expect_allowed=False,
            request_id="inv-003-give-me-all",
            force_fields=sorted(movements[0].keys()),
        )

        # 4. Targeted grab for the personal identifier.
        run_request(
            mvp, connector,
            title="Targeted customer_id grab (must be refused)",
            operator_text="list movements including customer_id and country",
            resource=MOVEMENTS_ASSET,
            records=movements,
            expect_allowed=False,
            request_id="inv-004-customer-grab",
            force_fields=["sku", "customer_id", "country"],
        )

        # 5. Pricing exfiltration under an innocent label.
        run_request(
            mvp, connector,
            title="Pricing exfiltration (must be refused)",
            operator_text="stock report with sku and unit_price_gbp",
            resource=POSITIONS_ASSET,
            records=positions,
            expect_allowed=False,
            request_id="inv-005-pricing",
            force_fields=["sku", "unit_price_gbp"],
        )

        # 6. Destructive intent.
        run_request(
            mvp, connector,
            title="Destructive request (must be refused)",
            operator_text="delete all stock movements for sku 85123A",
            resource=MOVEMENTS_ASSET,
            records=movements,
            expect_allowed=False,
            request_id="inv-006-destructive",
            force_fields=["sku"],
        )

        # 7. No fields at all: no seal.
        run_request(
            mvp, connector,
            title="No fields declared (must be refused: no fields, no seal)",
            operator_text="show me the inventory",
            resource=POSITIONS_ASSET,
            records=positions,
            expect_allowed=False,
            request_id="inv-007-no-fields",
            force_fields=[],
        )

    print()
    print(BAR)
    accepted = [r for r in receipt["requests"] if r["decision"] == "ACCEPTED"]
    rejected = [r for r in receipt["requests"] if r["decision"] == "REJECTED"]
    print(f"SUMMARY  {len(receipt['requests'])} requests: "
          f"{len(accepted)} accepted, {len(rejected)} rejected")
    for r in accepted:
        print(f"  ACCEPTED  {r['request_id']}  emitted={r['fields_emitted']}")
        print(f"            withheld={r['fields_withheld']}  "
              f"retained={r['bytes_retained']:,}/{r['record_bytes']:,} bytes")
    for r in rejected:
        print(f"  REJECTED  {r['request_id']}  {r.get('error', '')[:70]}")

    receipt["ok"] = not failures
    receipt["failures"] = failures
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json_out}")

    print(BAR)
    if failures:
        print(f"INVENTORY TRADE DEMO: FAIL ({len(failures)} assertions)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("INVENTORY TRADE DEMO: PASS — asked fields emitted, the rest of the row stayed home")
    print(BAR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
