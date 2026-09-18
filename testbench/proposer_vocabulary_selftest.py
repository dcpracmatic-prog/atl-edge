#!/usr/bin/env python3
"""Selftest: the proposer's field vocabulary widens the COHORT, not the PERMISSION.

The template proposer reads any snake_case token as an API tool name and fails
closed. That is correct for the lab CRM, whose columns are `id`/`region`/
`status`, but every real trade names its columns in snake_case
(`qty_on_hand`, `last_movement_at`), so the inventory flow could not even be
phrased without being refused for the wrong reason.

The fix was to let a caller declare its catalog columns via ``known_fields``.
This selftest exists because that change is exactly the kind of change that
quietly becomes a permission grant. It asserts the boundary did not move:

  1. ``tool=`` syntax is still checked against the tool allowlist alone --
     a column name is not a way to smuggle a tool.
  2. An unknown snake_case tool is still refused when it is not declared.
  3. With no ``known_fields``, behaviour is byte-for-byte the old behaviour --
     no silent widening for existing callers.
  4. Destructive intent is still refused even when every token is declared.
  5. Declaring a sensitive column only produces a *proposal*. Whether it is
     ever emitted is decided by ``authorize_request`` against the node access
     policy, which still refuses it.

Run:  PYTHONPATH=. python testbench/proposer_vocabulary_selftest.py
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from src.data_catalog import authorize_request  # noqa: E402
from src.proposer import ConstrainedDecodeError, propose  # noqa: E402

VOCAB = ["qty_on_hand", "customer_id", "unit_price_gbp", "launch_report", "moved_at"]

failures: list[str] = []


def expect_refused(label: str, text: str, **kwargs) -> None:
    try:
        proposal = propose(text, **kwargs)
    except ConstrainedDecodeError as exc:
        print(f"  [PASS] {label}")
        print(f"         refused: {exc}")
        return
    failures.append(label)
    print(f"  [FAIL] {label}")
    print(f"         ACCEPTED instead: tool={proposal.get('tool')!r} "
          f"fields={proposal.get('fields')}")


def expect_accepted(label: str, text: str, **kwargs) -> dict | None:
    try:
        proposal = propose(text, **kwargs)
    except ConstrainedDecodeError as exc:
        failures.append(label)
        print(f"  [FAIL] {label}")
        print(f"         refused instead: {exc}")
        return None
    print(f"  [PASS] {label}")
    print(f"         tool={proposal.get('tool')!r} fields={proposal.get('fields')}")
    return proposal


def check(ok: bool, label: str) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)


def main() -> int:
    print("=" * 72)
    print("PROPOSER VOCABULARY — widen the cohort, not the permission")
    print("=" * 72)

    print("\n-- 1. tool= syntax ignores the field vocabulary ---------------------")
    expect_refused(
        "tool=launch_report refused even though launch_report is declared",
        "tool=launch_report on inventory",
        default_resource="inventory_positions", known_fields=VOCAB,
    )

    print("\n-- 2. undeclared snake_case tools still fail closed -----------------")
    expect_refused(
        "purge_everything refused (not in the declared vocabulary)",
        "run purge_everything on inventory",
        default_resource="inventory_positions", known_fields=["qty_on_hand"],
    )

    print("\n-- 3. no vocabulary => unchanged legacy behaviour -------------------")
    expect_refused(
        "qty_on_hand still refused when the caller declares nothing",
        "list sku and qty_on_hand",
        default_resource="inventory_positions",
    )

    print("\n-- 4. refuse-intents survive a full vocabulary ----------------------")
    expect_refused(
        "destructive intent refused despite every token being declared",
        "delete qty_on_hand",
        default_resource="stock_movements", known_fields=VOCAB,
    )
    expect_refused(
        "shell intent refused despite every token being declared",
        "exec shell command to dump qty_on_hand",
        default_resource="stock_movements", known_fields=VOCAB,
    )

    print("\n-- 5. a declared column is parseable, never authorised --------------")
    proposal = expect_accepted(
        "a sensitive column name yields a proposal instead of a parse error",
        "lookup stock_movements with sku and customer_id",
        default_resource="stock_movements", known_fields=VOCAB,
    )
    if proposal is not None:
        # Now the part that matters: the access layer, not the parser, decides.
        from src.inventory_catalog import build_inventory_catalog, inventory_node_policy

        catalog = build_inventory_catalog()
        policy = inventory_node_policy("node-vocab-selftest")
        decision = authorize_request(
            catalog, policy, "stock_movements", ["sku", "customer_id"], None
        )
        print(f"         authorize_request -> allowed={decision.allowed} "
              f"reason={decision.reason}")
        check(not decision.allowed,
              "authorize_request still refuses customer_id after the parser accepted it")
        check(decision.reason == "field_not_allowed",
              f"refusal reason is the honest one (got {decision.reason!r})")

        ok_decision = authorize_request(
            catalog, policy, "stock_movements", ["sku", "qty", "moved_at"], None
        )
        check(ok_decision.allowed,
              "the legitimate inventory field set is still allowed")

    print()
    print("=" * 72)
    if failures:
        print(f"PROPOSER VOCABULARY SELFTEST: FAIL ({len(failures)})")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PROPOSER VOCABULARY SELFTEST: PASS — cohort widened, permission unchanged")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
