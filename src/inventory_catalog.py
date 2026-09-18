"""The inventory trade: catalogue, node policy and record loading.

This is the one buyer flow ATL demonstrates end to end. It replaces the
synthetic three-column `crm` asset used by the selftests, which proved the code
path worked but could not answer "would this hold on my data".

Records come from a real, openly licensed dataset: UCI "Online Retail"
(CC BY 4.0), a UK retailer's 2010-2011 transaction log reshaped into two
resources. See `datasets/inventory/SOURCE.md` for attribution and, more
importantly, for what the data is *not* — it is a transaction log, not a WMS
export, and `unit_price_gbp` is a sale price rather than a cost.

The success criterion for this flow is not "the model answered". It is:

    you asked for sku, description, qty_on_hand;
    the package contains exactly those;
    unit_price_gbp, customer_id, country and the rest of the row did not leave.

Nothing here touches the sealing path. This module only declares what exists,
how sensitive it is, and what this node may see.
"""
from __future__ import annotations

import csv
import pathlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from src.data_catalog import (
    DataAsset,
    DataCatalog,
    NodeAccessPolicy,
    Sensitivity,
)

__all__ = [
    "INVENTORY_DIR",
    "POSITIONS_ASSET",
    "MOVEMENTS_ASSET",
    "OPERATOR_VISIBLE_FIELDS",
    "WITHHELD_BY_DESIGN",
    "build_inventory_catalog",
    "inventory_node_policy",
    "load_positions",
    "load_movements",
    "dataset_available",
]

INVENTORY_DIR = pathlib.Path(__file__).resolve().parent.parent / "datasets" / "inventory"

POSITIONS_ASSET = "inventory_positions"
MOVEMENTS_ASSET = "stock_movements"

# What a stock enquiry is allowed to see. Everything else in the row is not
# merely unrequested -- the node policy refuses to emit it.
OPERATOR_VISIBLE_FIELDS: Dict[str, Tuple[str, ...]] = {
    POSITIONS_ASSET: ("sku", "description", "qty_on_hand", "last_movement_at"),
    MOVEMENTS_ASSET: ("movement_id", "sku", "description", "qty", "moved_at"),
}

# Named explicitly so the demo can assert on them, and so a reviewer can see the
# claim being made rather than inferring it from a diff.
WITHHELD_BY_DESIGN: Dict[str, Tuple[str, ...]] = {
    POSITIONS_ASSET: ("unit_price_gbp", "distinct_customers"),
    MOVEMENTS_ASSET: ("invoice_no", "unit_price_gbp", "customer_id", "country"),
}

_POSITION_FIELDS: Dict[str, Sensitivity] = {
    "sku": Sensitivity.PUBLIC,
    "description": Sensitivity.PUBLIC,
    "qty_on_hand": Sensitivity.INTERNAL,
    "last_movement_at": Sensitivity.INTERNAL,
    # Realised selling price per SKU over a period is pricing strategy.
    "unit_price_gbp": Sensitivity.CONFIDENTIAL,
    # Customer concentration per SKU: reveals dependence on a few buyers.
    "distinct_customers": Sensitivity.CONFIDENTIAL,
}

_MOVEMENT_FIELDS: Dict[str, Sensitivity] = {
    "movement_id": Sensitivity.PUBLIC,
    "sku": Sensitivity.PUBLIC,
    "description": Sensitivity.PUBLIC,
    "qty": Sensitivity.INTERNAL,
    "moved_at": Sensitivity.INTERNAL,
    "invoice_no": Sensitivity.CONFIDENTIAL,
    "unit_price_gbp": Sensitivity.CONFIDENTIAL,
    # A real, stable identifier linking every purchase one person ever made.
    # Calling this pseudonymous would be a stretch within this dataset.
    "customer_id": Sensitivity.SENSITIVE,
    "country": Sensitivity.CONFIDENTIAL,
}


def dataset_available() -> bool:
    return (INVENTORY_DIR / f"{POSITIONS_ASSET}.csv").exists() and (
        INVENTORY_DIR / f"{MOVEMENTS_ASSET}.csv"
    ).exists()


def _require_dataset() -> None:
    if not dataset_available():
        raise FileNotFoundError(
            f"inventory dataset not found in {INVENTORY_DIR}.\n"
            f"Build it with: python scripts/fetch_inventory_dataset.py"
        )


def build_inventory_catalog(catalog: DataCatalog | None = None) -> DataCatalog:
    """Register both inventory resources with their real field classification."""
    catalog = catalog or DataCatalog()
    catalog.register(
        DataAsset(
            asset_id=POSITIONS_ASSET,
            name="Inventory positions (net per SKU)",
            sensitivity=Sensitivity.INTERNAL,
            fields=dict(_POSITION_FIELDS),
            tags=["inventory", "uci-online-retail", "cc-by-4.0"],
        )
    )
    catalog.register(
        DataAsset(
            asset_id=MOVEMENTS_ASSET,
            name="Stock movements (one row per transaction line)",
            sensitivity=Sensitivity.CONFIDENTIAL,
            fields=dict(_MOVEMENT_FIELDS),
            tags=["inventory", "uci-online-retail", "cc-by-4.0", "contains-personal-data"],
        )
    )
    return catalog


def inventory_node_policy(node_id: str) -> NodeAccessPolicy:
    """The stock-enquiry node: both resources, capped below SENSITIVE.

    `max_sensitivity=CONFIDENTIAL` is what stops `customer_id` at the boundary.
    The field allow-list stops the rest. Two independent reasons for the same
    outcome, because a single mechanism is a single mistake away from failing.
    """
    return NodeAccessPolicy(
        node_id=node_id,
        allowed_assets=(POSITIONS_ASSET, MOVEMENTS_ASSET),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
        allowed_fields={k: tuple(v) for k, v in OPERATOR_VISIBLE_FIELDS.items()},
    )


def _load_csv(name: str, limit: int | None, int_fields: Sequence[str]) -> List[Dict[str, Any]]:
    _require_dataset()
    rows: List[Dict[str, Any]] = []
    with (INVENTORY_DIR / f"{name}.csv").open(newline="", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if limit is not None and i >= limit:
                break
            for k in int_fields:
                if row.get(k) not in (None, ""):
                    row[k] = int(row[k])
            rows.append(row)
    return rows


def load_positions(limit: int | None = None) -> List[Dict[str, Any]]:
    """Full inventory-position rows, every field included.

    Deliberately returns the complete row. The boundary has to do the reducing;
    if the loader pre-filtered, the demo would be proving nothing.
    """
    return _load_csv(POSITIONS_ASSET, limit, ("qty_on_hand", "distinct_customers"))


def load_movements(limit: int | None = None) -> List[Dict[str, Any]]:
    """Full stock-movement rows, including customer_id and country."""
    return _load_csv(MOVEMENTS_ASSET, limit, ("qty",))
