# Inventory dataset — source and attribution

## Attribution (required by the licence)

> **Online Retail** [Dataset]. Chen, D. (2015). UCI Machine Learning Repository.
> <https://doi.org/10.24432/C5BW33>
> Licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

Source page: <https://archive.ics.uci.edu/dataset/352/online+retail>

CC BY 4.0 permits redistribution and adaptation for any purpose, including
commercial, provided attribution is given. The CSVs in this directory are an
adaptation (a subset, reshaped into two resources) and are redistributed under
the same licence with the attribution above.

## What this is

541,909 transaction lines from a UK-based online retailer, December 2010 to
December 2011. Real commercial data: real product codes, real customer
identifiers, real prices, real country distribution.

The files committed here are an extract — the first 6,000 movement lines and the
1,690 SKUs they cover. Rebuild the full set with:

```bash
python scripts/fetch_inventory_dataset.py --full
```

## What this is not

Stated plainly so nothing downstream overclaims it:

- **It is a transaction log, not a WMS export.** There are no warehouse
  locations, no bin numbers, no supplier records, no purchase orders.
- **`unit_price_gbp` is a sale price, not a cost.** The source has no cost
  column, so margin cannot be derived from this data.
- **`qty_on_hand` is a net position over the period**, computed as the sum of
  movements per SKU (the source encodes cancellations as negative quantities).
  Nobody counted this in a warehouse. It is a real number derived from real
  movements, which is a different claim from "this is the stock level".
- **No column is invented.** Anything the source lacks is absent rather than
  filled with plausible-looking noise. A field that looks real but is not would
  make the withheld-field evidence worthless, because the interesting question
  is whether the boundary holds on *actual* data shapes.

## Resources and classification

`src/inventory_catalog.py` registers these with the sensitivity classes below.
The classification is a judgement about this dataset, not a legal opinion.

### `inventory_positions` — 1,690 rows

| Field | Class | Why |
|---|---|---|
| `sku` | public | A product code. Printed on catalogues. |
| `description` | public | A product name. |
| `qty_on_hand` | internal | Operationally useful, commercially uninteresting alone. |
| `last_movement_at` | internal | Timing of activity. |
| `unit_price_gbp` | confidential | Realised selling price per SKU. Aggregated across a period this is pricing strategy. |
| `distinct_customers` | confidential | Customer concentration per SKU. Reveals dependence on a few buyers. |

### `stock_movements` — 6,000 rows

| Field | Class | Why |
|---|---|---|
| `movement_id` | public | Synthetic row identifier assigned by the loader. |
| `sku` | public | |
| `description` | public | |
| `qty` | internal | |
| `moved_at` | internal | |
| `invoice_no` | confidential | Ties a movement to a specific commercial transaction. |
| `unit_price_gbp` | confidential | Price on that specific line. |
| `customer_id` | **sensitive** | A real, stable identifier for an individual customer. Not pseudonymous in any meaningful sense within this dataset: it links every purchase that customer ever made. |
| `country` | confidential | Customer location. Combined with `customer_id` and `moved_at` it is re-identifying. |

`customer_id` is the field that makes this flow worth demonstrating. A caller
asking "what do I have in stock" has no business receiving it, and the point of
the demo is that it does not come out — not because the query happened not to
select it, but because the boundary refuses to emit it.
