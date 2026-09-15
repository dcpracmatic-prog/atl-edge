"""Minimal ordered result packaging for ATL requests.

The wire representation carries only requested values plus sequencing metadata.
Semantic field names can stay in the authenticated request/manifest so the
response itself does not need to repeat unnecessary context.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple


@dataclass(frozen=True)
class ResultField:
    sequence: int
    field_id: str
    value: Any


@dataclass(frozen=True)
class ResultManifest:
    request_id: str
    total: int
    fields: Tuple[str, ...]

    def canonical_bytes(self) -> bytes:
        return json.dumps({"request_id": self.request_id, "total": self.total, "fields": list(self.fields)}, separators=(",", ":"), sort_keys=True).encode()

    @property
    def manifest_hash(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()


def package_requested_fields(request_id: str, requested_fields: Sequence[str], record: Mapping[str, Any]) -> Tuple[ResultManifest, Dict[str, Any]]:
    fields = tuple(requested_fields)
    values = []
    for i, field in enumerate(fields, start=1):
        if field not in record:
            raise KeyError(field)
        values.append({"sequence": i, "field_id": field, "value": record[field]})
    manifest = ResultManifest(request_id=request_id, total=len(values), fields=fields)
    payload = {
        "manifest_hash": manifest.manifest_hash,
        "request_id": request_id,
        "total": len(values),
        "fields": values,
        "complete": True,
    }
    return manifest, payload
