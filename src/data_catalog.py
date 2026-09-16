"""ATL local data catalog, classification and access decision layer.

MVP goals:
- Keep an inventory of datasets/fields and their sensitivity class.
- Detect obvious sensitive values when labels are missing or wrong.
- Reclassify upward conservatively; never downgrade automatically.
- Decide whether a node may access a requested field/class.
- Attach a protection profile so public/internal data can take a fast path while
  confidential/sensitive/restricted data uses ATLP and stricter checks.

This is a deterministic MVP classifier, not a legal/compliance DLP engine.
Organizations should extend the detectors and policy mapping for their domain.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, asdict
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class Sensitivity(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SENSITIVE = 3
    RESTRICTED = 4


_LEVEL_NAMES = {x.value: x.name.lower() for x in Sensitivity}


def level_name(level: Sensitivity | int) -> str:
    return _LEVEL_NAMES[int(level)]


def max_sensitivity(*levels: Sensitivity | int) -> Sensitivity:
    return Sensitivity(max(int(x) for x in levels)) if levels else Sensitivity.PUBLIC


# Conservative field-name hints. Values are separately inspected where possible.
_FIELD_HINTS: Dict[Sensitivity, Tuple[str, ...]] = {
    Sensitivity.RESTRICTED: (
        "password", "passwd", "secret", "private_key", "access_token", "api_key",
    ),
    Sensitivity.SENSITIVE: (
        "salary", "wage", "payroll", "rfc", "curp", "ssn", "tax_id", "account",
        "bank_account", "card_number", "credit_card", "debit_card", "phone", "email",
        "address", "dob", "birth", "medical", "health",
    ),
    Sensitivity.CONFIDENTIAL: (
        "contract", "internal", "cost", "expense", "consumption", "customer", "employee",
        "revenue", "margin", "forecast", "vendor",
    ),
}

_RE_RFC = re.compile(r"^[A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{2,3}$", re.I)
_RE_CURP = re.compile(r"^[A-Z][AEIOUX][A-Z]{2}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$", re.I)
_RE_CARD = re.compile(r"^\d{13,19}$")
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_PHONE = re.compile(r"^\+?[0-9 ()-]{8,20}$")


def classify_field_name(name: str) -> Sensitivity:
    n = name.strip().lower().replace("-", "_").replace(" ", "_")
    for level in (Sensitivity.RESTRICTED, Sensitivity.SENSITIVE, Sensitivity.CONFIDENTIAL):
        if any(h in n for h in _FIELD_HINTS[level]):
            return level
    return Sensitivity.INTERNAL


def classify_value(value: Any) -> Sensitivity:
    if value is None or isinstance(value, (bool, int, float)):
        return Sensitivity.PUBLIC
    if not isinstance(value, str):
        return Sensitivity.INTERNAL
    s = value.strip()
    if not s:
        return Sensitivity.PUBLIC
    if _RE_RFC.fullmatch(s) or _RE_CURP.fullmatch(s):
        return Sensitivity.SENSITIVE
    if _RE_CARD.fullmatch(s.replace(" ", "")):
        return Sensitivity.SENSITIVE
    if _RE_EMAIL.fullmatch(s):
        return Sensitivity.SENSITIVE
    if _RE_PHONE.fullmatch(s):
        return Sensitivity.SENSITIVE
    # Long opaque credentials/secrets: do not attempt to identify the secret itself.
    if len(s) >= 24 and ("=" in s or s.startswith(("sk-", "AKIA", "eyJ"))):
        return Sensitivity.RESTRICTED
    return Sensitivity.PUBLIC


@dataclass(frozen=True)
class Classification:
    declared: Sensitivity
    detected: Sensitivity
    effective: Sensitivity
    reasons: Tuple[str, ...] = ()

    @property
    def reclassified(self) -> bool:
        return self.effective > self.declared


@dataclass
class DataAsset:
    asset_id: str
    name: str
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    fields: Dict[str, Sensitivity] = None  # type: ignore[assignment]
    tags: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.fields = dict(self.fields or {})
        self.tags = list(self.tags or [])


class DataCatalog:
    """Local registry. Metadata only; it does not copy the underlying records."""

    def __init__(self) -> None:
        self.assets: Dict[str, DataAsset] = {}

    def register(self, asset: DataAsset) -> None:
        self.assets[asset.asset_id] = asset

    def get(self, asset_id: str) -> DataAsset:
        if asset_id not in self.assets:
            raise KeyError(asset_id)
        return self.assets[asset_id]

    def classify_record(self, asset_id: str, record: Mapping[str, Any]) -> Dict[str, Classification]:
        asset = self.get(asset_id)
        out: Dict[str, Classification] = {}
        for key, value in record.items():
            declared = Sensitivity(asset.fields.get(key, asset.sensitivity))
            name_level = classify_field_name(key)
            value_level = classify_value(value)
            detected = max_sensitivity(name_level, value_level)
            effective = max_sensitivity(declared, detected)
            reasons: List[str] = []
            if name_level > declared:
                reasons.append("field_name_detector")
            if value_level > declared:
                reasons.append("value_detector")
            out[key] = Classification(declared, detected, effective, tuple(reasons))
        return out

    def effective_record(self, asset_id: str, record: Mapping[str, Any]) -> Dict[str, Any]:
        """Return a classification manifest, not the raw record."""
        classes = self.classify_record(asset_id, record)
        return {
            "asset_id": asset_id,
            "fields": {
                k: {
                    "declared": level_name(v.declared),
                    "detected": level_name(v.detected),
                    "effective": level_name(v.effective),
                    "reclassified": v.reclassified,
                    "reasons": list(v.reasons),
                }
                for k, v in classes.items()
            },
            "effective_asset_level": level_name(max_sensitivity(*(v.effective for v in classes.values()))),
        }


@dataclass(frozen=True)
class NodeAccessPolicy:
    node_id: str
    allowed_assets: Tuple[str, ...] = ()
    max_sensitivity: Sensitivity = Sensitivity.INTERNAL
    allowed_fields: Mapping[str, Tuple[str, ...]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_assets", tuple(self.allowed_assets))
        object.__setattr__(self, "allowed_fields", dict(self.allowed_fields or {}))


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    asset_id: str
    node_id: str
    requested_fields: Tuple[str, ...]
    effective_level: Sensitivity
    protection_profile: str
    reason: str


def protection_profile(level: Sensitivity | int) -> str:
    level = Sensitivity(level)
    if level <= Sensitivity.INTERNAL:
        return "FAST_LOCAL"
    if level == Sensitivity.CONFIDENTIAL:
        return "ATLP_STANDARD"
    if level == Sensitivity.SENSITIVE:
        return "ATLP_FIELD_MINIMUM"
    return "ATLP_RESTRICTED"


def authorize_request(
    catalog: DataCatalog,
    policy: NodeAccessPolicy,
    asset_id: str,
    requested_fields: Sequence[str],
    record_sample: Optional[Mapping[str, Any]] = None,
) -> AccessDecision:
    if asset_id not in catalog.assets:
        return AccessDecision(False, asset_id, policy.node_id, tuple(requested_fields), Sensitivity.RESTRICTED, "ATLP_RESTRICTED", "unknown_asset")
    if policy.allowed_assets and asset_id not in policy.allowed_assets:
        return AccessDecision(False, asset_id, policy.node_id, tuple(requested_fields), Sensitivity.RESTRICTED, "ATLP_RESTRICTED", "asset_not_allowed")
    asset = catalog.get(asset_id)
    fields = tuple(requested_fields)
    if not fields:
        return AccessDecision(False, asset_id, policy.node_id, fields, asset.sensitivity, protection_profile(asset.sensitivity), "no_fields")
    for field in fields:
        if field not in asset.fields:
            return AccessDecision(False, asset_id, policy.node_id, fields, Sensitivity.RESTRICTED, "ATLP_RESTRICTED", f"unknown_field:{field}")
    allowed_for_asset = policy.allowed_fields.get(asset_id, ()) if policy.allowed_fields else ()
    if allowed_for_asset and any(f not in allowed_for_asset for f in fields):
        return AccessDecision(False, asset_id, policy.node_id, fields, Sensitivity.RESTRICTED, "ATLP_RESTRICTED", "field_not_allowed")
    levels = [asset.fields[f] for f in fields]
    if record_sample:
        classes = catalog.classify_record(asset_id, record_sample)
        levels.extend(classes[f].effective for f in fields if f in classes)
    effective = max_sensitivity(asset.sensitivity, *levels)
    if effective > policy.max_sensitivity:
        return AccessDecision(False, asset_id, policy.node_id, fields, effective, protection_profile(effective), "sensitivity_exceeds_node_policy")
    return AccessDecision(True, asset_id, policy.node_id, fields, effective, protection_profile(effective), "allowed")


def catalog_hash(catalog: DataCatalog) -> str:
    payload = []
    for aid in sorted(catalog.assets):
        a = catalog.assets[aid]
        payload.append({"asset_id": a.asset_id, "name": a.name, "sensitivity": int(a.sensitivity), "fields": {k: int(a.fields[k]) for k in sorted(a.fields)}, "tags": sorted(a.tags)})
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
