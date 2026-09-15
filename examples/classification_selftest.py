#!/usr/bin/env python3
"""Self-test for ATL data classification/access/minimal result packaging."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data_catalog import (
    DataAsset, DataCatalog, NodeAccessPolicy, Sensitivity,
    authorize_request, catalog_hash,
)
from src.result_packaging import package_requested_fields


def main() -> int:
    catalog = DataCatalog()
    catalog.register(DataAsset(
        asset_id="hr-payroll",
        name="Payroll",
        sensitivity=Sensitivity.CONFIDENTIAL,
        fields={
            "name": Sensitivity.INTERNAL,
            "salary": Sensitivity.SENSITIVE,
            "rfc": Sensitivity.SENSITIVE,
            "account": Sensitivity.SENSITIVE,
        },
        tags=["hr", "finance"],
    ))

    sample = {"name": "Juan", "salary": 5580, "rfc": "ABCJ850101AB1", "account": "1234567890123456"}
    manifest = catalog.effective_record("hr-payroll", sample)
    assert manifest["fields"]["salary"]["effective"] == "sensitive"
    assert manifest["fields"]["rfc"]["effective"] == "sensitive"
    assert manifest["fields"]["account"]["effective"] == "sensitive"

    low = NodeAccessPolicy(node_id="agent-low", allowed_assets=("hr-payroll",), max_sensitivity=Sensitivity.CONFIDENTIAL)
    d = authorize_request(catalog, low, "hr-payroll", ["salary"], sample)
    assert not d.allowed and d.reason == "sensitivity_exceeds_node_policy"

    high = NodeAccessPolicy(node_id="agent-hr", allowed_assets=("hr-payroll",), max_sensitivity=Sensitivity.SENSITIVE)
    d = authorize_request(catalog, high, "hr-payroll", ["salary", "rfc", "account"], sample)
    assert d.allowed and d.protection_profile == "ATLP_FIELD_MINIMUM"

    rid = "req-test-1"
    _, payload = package_requested_fields(rid, ["salary", "rfc", "account"], sample)
    assert [x["sequence"] for x in payload["fields"]] == [1, 2, 3]
    assert [x["field_id"] for x in payload["fields"]] == ["salary", "rfc", "account"]
    assert payload["complete"] is True

    print("classification=reclassify-upward")
    print("authorization=sensitivity-aware")
    print("packaging=ordered-minimum-fields")
    print("catalog_hash=" + catalog_hash(catalog))
    print("classification selftest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
