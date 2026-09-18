#!/usr/bin/env python3
"""Build the inventory dataset for the buyer flow from a real, openly licensed source.

Source: UCI Machine Learning Repository, "Online Retail" (dataset 352).
        https://archive.ics.uci.edu/dataset/352/online+retail
        Licence: Creative Commons Attribution 4.0 International (CC BY 4.0).
        541,909 transaction lines from a UK online retailer, 2010-2011.

Why this dataset and not a generated one: the whole point of the flow is to show
that fields a caller did NOT ask for stayed behind. That is only interesting if
the withheld fields are real commercial data with real shapes -- actual customer
identifiers, actual unit prices, actual country distribution. A generated table
proves the code path works; it does not answer "would this hold on my data".

Honest framing, stated here so it is not overclaimed downstream: this is a
retailer's *transaction log*, reshaped into an inventory position view. It is
real data, not synthetic. It is not a WMS export, so there are no warehouse
locations, no supplier records and no purchase costs -- UnitPrice is a sale
price, not a cost. No column here is invented. Anything the source does not
contain is simply absent rather than filled in with plausible noise.

Two resources are produced:

  stock_movements       one row per source line: movement_id, sku, description,
                        qty, moved_at, invoice_no, unit_price_gbp, customer_id,
                        country
  inventory_positions   aggregated per SKU: sku, description, qty_on_hand,
                        last_movement_at, unit_price_gbp, distinct_customers

`qty_on_hand` is the net sum of movements for that SKU (the source encodes
cancellations as negative quantities), so it is a real net position over the
period, not a stock level anybody counted in a warehouse.

Usage:
    python scripts/fetch_inventory_dataset.py            # build the extract
    python scripts/fetch_inventory_dataset.py --full     # also write full CSVs
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import pathlib
import sys
import urllib.request
import zipfile
from collections import defaultdict

SOURCE_URL = "https://archive.ics.uci.edu/static/public/352/online+retail.zip"
SOURCE_PAGE = "https://archive.ics.uci.edu/dataset/352/online+retail"
MEMBER = "Online Retail.xlsx"

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "datasets" / "inventory"

# The committed extract. Small enough to keep the repo light and CI hermetic,
# large enough that the withheld-field evidence is not a toy.
EXTRACT_MOVEMENTS = 6000

MOVEMENT_COLS = [
    "movement_id", "sku", "description", "qty", "moved_at",
    "invoice_no", "unit_price_gbp", "customer_id", "country",
]
POSITION_COLS = [
    "sku", "description", "qty_on_hand", "last_movement_at",
    "unit_price_gbp", "distinct_customers",
]


def _download(cache: pathlib.Path) -> pathlib.Path:
    if cache.exists() and cache.stat().st_size > 1_000_000:
        print(f"using cached {cache} ({cache.stat().st_size:,} bytes)")
        return cache
    print(f"downloading {SOURCE_URL}")
    cache.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(SOURCE_URL, timeout=300) as r:
        blob = r.read()
    print(f"  {len(blob):,} bytes")
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = z.namelist()
        if MEMBER not in names:
            raise SystemExit(f"expected {MEMBER!r} in the archive, found {names}")
        cache.write_bytes(z.read(MEMBER))
    return cache


def _read_rows(xlsx: pathlib.Path):
    try:
        import openpyxl
    except ImportError:  # pragma: no cover
        raise SystemExit("openpyxl is required to read the source workbook: pip install openpyxl")
    wb = openpyxl.load_workbook(xlsx, read_only=True, data_only=True)
    ws = wb.active
    it = ws.iter_rows(values_only=True)
    header = [str(c).strip() for c in next(it)]
    expected = ["InvoiceNo", "StockCode", "Description", "Quantity",
                "InvoiceDate", "UnitPrice", "CustomerID", "Country"]
    if header != expected:
        raise SystemExit(f"source schema changed.\n  expected {expected}\n  found    {header}")
    for row in it:
        yield dict(zip(header, row))


def build(full: bool) -> None:
    xlsx = _download(ROOT / ".cache" / MEMBER)

    movements = []
    skipped = 0
    for i, r in enumerate(_read_rows(xlsx)):
        sku = str(r["StockCode"] or "").strip()
        desc = str(r["Description"] or "").strip()
        qty = r["Quantity"]
        when = r["InvoiceDate"]
        if not sku or qty is None or when is None:
            skipped += 1
            continue
        cust = r["CustomerID"]
        movements.append({
            "movement_id": f"mv-{i:07d}",
            "sku": sku,
            "description": desc,
            "qty": int(qty),
            "moved_at": when.isoformat(sep=" ") if hasattr(when, "isoformat") else str(when),
            "invoice_no": str(r["InvoiceNo"] or "").strip(),
            "unit_price_gbp": f"{float(r['UnitPrice'] or 0):.2f}",
            "customer_id": "" if cust is None else str(int(cust)),
            "country": str(r["Country"] or "").strip(),
        })

    print(f"parsed {len(movements):,} movements ({skipped:,} rows skipped: missing sku/qty/date)")

    def positions(rows):
        agg = defaultdict(lambda: {"qty": 0, "desc": "", "last": "", "prices": [], "custs": set()})
        for m in rows:
            a = agg[m["sku"]]
            a["qty"] += m["qty"]
            if m["description"] and len(m["description"]) > len(a["desc"]):
                a["desc"] = m["description"]
            if m["moved_at"] > a["last"]:
                a["last"] = m["moved_at"]
            a["prices"].append(float(m["unit_price_gbp"]))
            if m["customer_id"]:
                a["custs"].add(m["customer_id"])
        out = []
        for sku, a in sorted(agg.items()):
            out.append({
                "sku": sku,
                "description": a["desc"],
                "qty_on_hand": a["qty"],
                "last_movement_at": a["last"],
                "unit_price_gbp": f"{sum(a['prices'])/len(a['prices']):.2f}",
                "distinct_customers": len(a["custs"]),
            })
        return out

    OUT.mkdir(parents=True, exist_ok=True)

    def write(path: pathlib.Path, cols, rows):
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"  wrote {path.relative_to(ROOT)}  {len(rows):,} rows  sha256:{digest[:16]}")
        return digest

    extract = movements[:EXTRACT_MOVEMENTS]
    write(OUT / "stock_movements.csv", MOVEMENT_COLS, extract)
    write(OUT / "inventory_positions.csv", POSITION_COLS, positions(extract))

    if full:
        write(OUT / "stock_movements.full.csv", MOVEMENT_COLS, movements)
        write(OUT / "inventory_positions.full.csv", POSITION_COLS, positions(movements))

    print("\nSource:", SOURCE_PAGE)
    print("Licence: CC BY 4.0 -- redistribution allowed with attribution.")
    print("See datasets/inventory/SOURCE.md")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="also write the full 541k-row CSVs")
    args = ap.parse_args(argv)
    build(args.full)
    return 0


if __name__ == "__main__":
    sys.exit(main())
