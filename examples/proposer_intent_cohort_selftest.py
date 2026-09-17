#!/usr/bin/env python3
"""Run the ~12-intent proposer cohort with backend=template (CI-safe)."""
from __future__ import annotations

import json
from pathlib import Path

from src.proposer import ConstrainedDecodeError, propose

COHORT = Path(__file__).with_name("proposer_intent_cohort.json")


def main() -> int:
    cases = json.loads(COHORT.read_text(encoding="utf-8"))
    assert len(cases) >= 20
    for case in cases:
        intent = case["intent"]
        expect = case["expect"]
        try:
            proposal = propose(intent, backend="template")
            if expect != "accept":
                raise AssertionError(f"expected refuse for {intent!r}, got {proposal}")
            assert proposal.get("schema_version") == 1
        except ConstrainedDecodeError:
            if expect != "refuse":
                raise AssertionError(f"expected accept for {intent!r}") from None
    print(f"proposer_intent_cohort: PASS ({len(cases)} cases, backend=template)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
