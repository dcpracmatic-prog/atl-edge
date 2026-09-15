#!/usr/bin/env python3
"""
Data plane MVP — predigestión on-prem + paquete AEAD de vida corta + conector cloud.

Hardening vs revisión adversarial:
  - open() normaliza TODO fallo de parseo/política a ValueError("INERT") genérico
    hacia el llamador externo; el detalle solo va a audit local opcional.
  - Subclave por nodo vía HKDF(master, salt=node_id) — node_claim deja de ser
    etiqueta de cortesía sobre una clave global.
  - Anti-replay: caché de request_id vistos (TTL = expiry del paquete).
  - from_env() falla duro sin ATL_PACKAGE_KEY_HEX salvo dev=True explícito.
  - La cifra de reducción de tokens es métrica de *este* dataset, no claim universal.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import struct
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

MAGIC = b"ATLP"
VERSION = 1
INERT = "INERT"  # único mensaje hacia el exterior


# ---------------------------------------------------------------------------
# HKDF-SHA256 (stdlib-only subset) — subclave por nodo
# ---------------------------------------------------------------------------

def _hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Extract + Expand (RFC 5869) with SHA-256, single block (length <= 32)."""
    if length > 32:
        raise ValueError("this helper only supports length <= 32")
    if not salt:
        salt = bytes(32)  # zeros per RFC if salt omitted
    import hmac
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # T(1) = HMAC(PRK, info | 0x01)
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def derive_transport_key(node_key_bytes: bytes) -> bytes:
    """Derive the transport-authentication (HMAC) key from a node's ATLP key.

    Deliberately a *different* key than the AES-GCM key used to seal/open
    packages: reusing one raw secret as both an AEAD key and a MAC key is a
    classic key-reuse smell, even when the two operations look unrelated.
    HKDF with a distinct `info` label gives cryptographic domain separation
    for effectively free, so the transport layer (`src/transport.py`) and
    the payload layer never share literal key material.
    """
    if len(node_key_bytes) != 32:
        raise ValueError("node_key_bytes must be 32 bytes")
    return _hkdf_sha256(
        node_key_bytes,
        salt=b"atl-transport-v1",
        info=b"atl-transport-auth",
        length=32,
    )


def node_key(master_key: bytes, node_id: str) -> bytes:
    """Derive a deterministic per-node AES key from the provisioning master."""
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    if not node_id or not isinstance(node_id, str):
        raise ValueError("node_id required")
    return _hkdf_sha256(
        master_key,
        salt=b"atl-node-v1",
        info=b"atl-package-node:" + node_id.encode("utf-8"),
        length=32,
    )


# ---------------------------------------------------------------------------
# Package header / wire format
# ---------------------------------------------------------------------------

@dataclass
class PackageHeader:
    request_id: str
    policy_id: str
    key_id: str
    node_claim: str
    expiry: float
    created_at: float
    policy_hash: str = ""
    proposal_hash: str = ""
    principal_id: str = ""
    content_type: str = "application/json"
    predigest_chars: int = 0
    raw_chars: int = 0
    result_manifest_hash: str = ""
    license_id: str = ""

    def to_json_bytes(self) -> bytes:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass
class SealResult:
    package: bytes
    header: PackageHeader
    audit_record: Dict[str, Any]


# ---------------------------------------------------------------------------
# Anti-replay store (in-memory; optional persist via JSONL path)
# ---------------------------------------------------------------------------

import threading

class ReplayCache:
    """request_id → expiry. Reject second open of same id while not expired."""

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        dead = [k for k, exp in self._seen.items() if exp <= now]
        for k in dead:
            del self._seen[k]

    def check_and_record(self, request_id: str, expiry: float, now: Optional[float] = None) -> None:
        t = time.time() if now is None else now
        with self._lock:
            self._purge(t)
            if request_id in self._seen:
                raise ValueError(INERT)  # generic — was replay
            self._seen[request_id] = float(expiry)


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

class PackageCrypto:
    """
    AES-256-GCM. Prefer constructing with node-derived key via from_master().
    open() never leaks which check failed to the caller — only INERT.
    Optional on_reject(detail) for local audit only.
    """

    def __init__(
        self,
        key: bytes,
        key_id: str,
        node_id: str,
        *,
        replay: Optional[ReplayCache] = None,
        on_reject: Optional[Callable[[str], None]] = None,
    ):
        if len(key) != 32:
            raise ValueError("key must be 32 bytes (AES-256)")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.key = key
        self.key_id = key_id
        self.node_id = node_id
        self._aes = AESGCM(key)
        self.replay = replay if replay is not None else ReplayCache()
        self.on_reject = on_reject

    @classmethod
    def from_master(
        cls,
        master_key: bytes,
        node_id: str,
        key_id: str = "master-v1",
        **kwargs: Any,
    ) -> "PackageCrypto":
        return cls(node_key(master_key, node_id), key_id=key_id, node_id=node_id, **kwargs)

    @classmethod
    def from_node_key(
        cls,
        node_key_bytes: bytes,
        node_id: str,
        key_id: str,
        **kwargs: Any,
    ) -> "PackageCrypto":
        """Construct directly from a provisioned per-node AES-256 key.

        Preferred for cloud/premium connectors: the root/master key never
        needs to exist on the connector host.
        """
        return cls(node_key_bytes, key_id=key_id, node_id=node_id, **kwargs)

    def _reject(self, detail: str) -> None:
        if self.on_reject:
            try:
                self.on_reject(detail)
            except Exception:
                pass
        raise ValueError(INERT)

    def seal(
        self,
        plaintext: bytes,
        *,
        policy_id: str,
        ttl_seconds: int,
        raw_chars: int = 0,
        content_type: str = "application/json",
        request_id: Optional[str] = None,
        policy_hash: str = "",
        proposal_hash: str = "",
        principal_id: str = "",
        result_manifest_hash: str = "",
        license_id: str = "",
    ) -> SealResult:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        now = time.time()
        header = PackageHeader(
            request_id=request_id or str(uuid.uuid4()),
            policy_id=policy_id,
            key_id=self.key_id,
            node_claim=self.node_id,  # sealed for THIS node key
            expiry=now + int(ttl_seconds),
            created_at=now,
            policy_hash=policy_hash,
            proposal_hash=proposal_hash,
            principal_id=principal_id,
            content_type=content_type,
            predigest_chars=len(plaintext),
            raw_chars=raw_chars or len(plaintext),
            result_manifest_hash=result_manifest_hash,
            license_id=license_id,
        )
        hdr = header.to_json_bytes()
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, plaintext, hdr)
        pkg = MAGIC + bytes([VERSION]) + struct.pack(">I", len(hdr)) + hdr + nonce + ct
        audit = {
            "ts": now,
            "event": "seal",
            "request_id": header.request_id,
            "policy_id": policy_id,
            "node_claim": self.node_id,
            "key_id": self.key_id,
            "expiry": header.expiry,
            "raw_chars": header.raw_chars,
            "predigest_chars": header.predigest_chars,
            "package_bytes": len(pkg),
            "result_manifest_hash": header.result_manifest_hash,
            "license_id": header.license_id,
        }
        return SealResult(package=pkg, header=header, audit_record=audit)

    def open(self, package: bytes, *, now: Optional[float] = None) -> bytes:
        """
        Opens package or raises ValueError("INERT") with no reason string for the caller.
        Detail only via on_reject callback (local audit).
        """
        t = time.time() if now is None else now

        if len(package) < 4 + 1 + 4 + 12 + 16:
            self._reject("truncated")
        if package[:4] != MAGIC or package[4] != VERSION:
            self._reject("bad_magic_or_version")

        try:
            hdr_len = struct.unpack(">I", package[5:9])[0]
        except struct.error:
            self._reject("bad_header_len")

        if hdr_len < 2 or hdr_len > 65536 or 9 + hdr_len + 12 + 16 > len(package):
            self._reject("bad_header_len")

        hdr = package[9 : 9 + hdr_len]
        rest = package[9 + hdr_len :]
        nonce, ct = rest[:12], rest[12:]

        # --- header parse: MUST not leak JSONDecodeError / KeyError ---
        try:
            meta = json.loads(hdr.decode("utf-8"))
            if not isinstance(meta, dict):
                raise ValueError("header not object")
            expiry = float(meta["expiry"])
            created_at = float(meta["created_at"])
            request_id = str(meta["request_id"])
            key_id = str(meta["key_id"])
            node_claim = str(meta["node_claim"])
            if not request_id or not key_id or not node_claim or not math.isfinite(expiry) or not math.isfinite(created_at):
                raise ValueError("invalid required header values")
            if created_at > expiry:
                raise ValueError("created_at after expiry")
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, ValueError):
            self._reject("malformed_header")

        if t >= expiry:
            self._reject("ttl_expired")
        if node_claim != self.node_id:
            self._reject("node_claim_mismatch")
        if key_id != self.key_id:
            self._reject("key_id_mismatch")

        # Authenticate before consuming the request_id. Otherwise an attacker
        # can poison the replay cache with a forged package and cause a later
        # legitimate package with the same request_id to be rejected (DoS).
        try:
            plaintext = self._aes.decrypt(nonce, ct, hdr)
        except Exception:
            self._reject("auth_fail")

        try:
            self.replay.check_and_record(request_id, expiry, now=t)
        except ValueError:
            self._reject("replay")

        return plaintext


# ---------------------------------------------------------------------------
# Predigest + metrics (dataset-specific; not a universal marketing number)
# ---------------------------------------------------------------------------

def predigest_records(
    records: Sequence[Dict[str, Any]],
    *,
    fields: Optional[Sequence[str]] = None,
    max_records: int = 20,
) -> Dict[str, Any]:
    fields = list(fields) if fields else None
    rows = []
    for rec in list(records)[:max_records]:
        if fields:
            rows.append({k: rec.get(k) for k in fields if k in rec})
        else:
            rows.append(dict(rec))
    return {"n_in": len(records), "n_out": len(rows), "fields": fields, "rows": rows}


def estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


# ---------------------------------------------------------------------------
# On-prem audit + local plane
# ---------------------------------------------------------------------------

class OnPremAuditLog:
    """Append-only local JSONL with tamper-evident hash chaining.

    This detects modification/deletion/reordering of records when the chain
    head is protected externally. It is not itself immutable storage.
    """
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        if not self.path.exists():
            return ""
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if not lines:
                return ""
            obj = json.loads(lines[-1])
            return str(obj.get("event_hash", ""))
        except Exception:
            # Fail closed for audit continuity: a corrupt audit file must not
            # silently start a new chain.
            raise RuntimeError("audit log corrupt or unreadable")

    def append(self, record: Dict[str, Any]) -> None:
        with self._lock:
            body = dict(record)
            body["previous_hash"] = self._last_hash
            canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            body["event_hash"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
            line = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._last_hash = body["event_hash"]

    def verify(self) -> bool:
        previous = ""
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            obj = json.loads(line)
            claimed = obj.pop("event_hash", None)
            if obj.get("previous_hash", "") != previous:
                return False
            canonical = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
            if claimed != expected:
                return False
            previous = claimed
        return True


@dataclass
class LocalIssueResult:
    package: bytes
    header: PackageHeader
    metrics: Dict[str, Any]
    audit_path: str


class LocalDataPlane:
    def __init__(self, crypto: PackageCrypto, audit: OnPremAuditLog):
        self.crypto = crypto
        self.audit = audit

    def issue_for_agent(
        self,
        records: Sequence[Dict[str, Any]],
        *,
        policy_id: str,
        ttl_seconds: int = 120,
        fields: Optional[Sequence[str]] = None,
        requester: str = "local-agent",
        purpose: str = "premium-agent-task",
        request_id: Optional[str] = None,
        policy_hash: str = "",
        proposal_hash: str = "",
        result_manifest_hash: str = "",
        license_id: str = "",
    ) -> LocalIssueResult:
        raw = json.dumps(list(records), ensure_ascii=False, separators=(",", ":"))
        digested = predigest_records(records, fields=fields)
        plain = json.dumps(digested, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        sealed = self.crypto.seal(
            plain,
            policy_id=policy_id,
            ttl_seconds=ttl_seconds,
            raw_chars=len(raw),
            request_id=request_id,
            policy_hash=policy_hash,
            proposal_hash=proposal_hash,
            principal_id=requester,
            result_manifest_hash=result_manifest_hash,
            license_id=license_id,
        )
        metrics = {
            "raw_chars": len(raw),
            "predigest_chars": len(plain),
            "package_bytes": len(sealed.package),
            "raw_tokens_est": estimate_tokens(raw),
            "predigest_tokens_est": estimate_tokens(plain.decode("utf-8")),
            "token_reduction_pct": round(
                100.0 * (1.0 - estimate_tokens(plain.decode("utf-8")) / max(1, estimate_tokens(raw))),
                1,
            ),
            "byte_reduction_pct": round(100.0 * (1.0 - len(plain) / max(1, len(raw))), 1),
            "note": "reduction is for this input only; not a universal claim",
        }
        self.audit.append({
            **sealed.audit_record,
            "requester": requester,
            "purpose": purpose,
            "metrics": metrics,
        })
        return LocalIssueResult(
            package=sealed.package,
            header=sealed.header,
            metrics=metrics,
            audit_path=str(self.audit.path),
        )


# ---------------------------------------------------------------------------
# Cloud connector
# ---------------------------------------------------------------------------

class CloudDecryptConnector:
    def __init__(self, crypto: PackageCrypto):
        self.crypto = crypto

    @classmethod
    def from_node_key(
        cls,
        node_key_bytes: bytes,
        node_id: str,
        *,
        key_id: str = "node-v1",
        replay: Optional[ReplayCache] = None,
        on_reject: Optional[Callable[[str], None]] = None,
    ) -> "CloudDecryptConnector":
        return cls(PackageCrypto.from_node_key(node_key_bytes, node_id, key_id=key_id, replay=replay, on_reject=on_reject))

    @classmethod
    def from_env(
        cls,
        node_id: str,
        *,
        dev: bool = False,
        replay: Optional[ReplayCache] = None,
        on_reject: Optional[Callable[[str], None]] = None,
    ) -> "CloudDecryptConnector":
        """Build a connector from a provisioned *per-node* key.

        Production connectors must use ATL_NODE_KEY_HEX. The root/master key
        is deliberately not accepted here, preventing accidental placement
        of the provisioning root on a cloud instance.
        """
        node_hex = os.environ.get("ATL_NODE_KEY_HEX", "").strip()
        key_id = os.environ.get("ATL_PACKAGE_KEY_ID", "node-v1")
        if node_hex:
            try:
                node_key_bytes = bytes.fromhex(node_hex)
            except ValueError as exc:
                raise RuntimeError("ATL_NODE_KEY_HEX must be hex") from exc
            if len(node_key_bytes) != 32:
                raise RuntimeError("ATL_NODE_KEY_HEX must decode to 32 bytes")
            return cls(PackageCrypto.from_node_key(node_key_bytes, node_id, key_id=key_id, replay=replay, on_reject=on_reject))
        if not dev:
            raise RuntimeError("ATL_NODE_KEY_HEX is required; master keys are not accepted by cloud connectors")
        master = hashlib.sha256(b"atl-dev-only-not-for-production").digest()
        return cls(PackageCrypto.from_master(master, node_id, key_id="dev-fallback", replay=replay, on_reject=on_reject))

    def open_package(self, package: bytes) -> Dict[str, Any]:
        plain = self.crypto.open(package)
        return json.loads(plain.decode("utf-8"))


# ---------------------------------------------------------------------------
# Selftest (adversarial cases included)
# ---------------------------------------------------------------------------

def run_selftest(audit_path: Path) -> bool:
    print("=" * 72)
    print("DATA PLANE MVP — hardened open / HKDF node / replay / env")
    print("=" * 72)

    rejects: List[str] = []
    master = hashlib.sha256(b"atl-dev-only-not-for-production").digest()
    node = "cloud-instance-dev"
    crypto = PackageCrypto.from_master(
        master, node, key_id="master-v1", on_reject=lambda d: rejects.append(d)
    )
    audit = OnPremAuditLog(audit_path)
    local = LocalDataPlane(crypto, audit)

    records = [
        {"customer_id": i, "region": "MX", "status": "active", "note": f"long free text {i} " * 20}
        for i in range(50)
    ]
    issued = local.issue_for_agent(
        records,
        policy_id="crm.read.summary",
        ttl_seconds=60,
        fields=["customer_id", "region", "status"],
        requester="db-agent-1",
        purpose="premium-support-agent",
    )
    print("metrics:", json.dumps(issued.metrics, indent=2))

    # happy path
    data = crypto.open(issued.package)
    assert b"customer_id" in data
    print("open OK")

    # replay
    try:
        crypto.open(issued.package)
        print("REPLAY: FAIL (second open should INERT)")
        return False
    except ValueError as e:
        assert str(e) == INERT
        print("replay INERT: OK  detail_audit=", rejects[-1] if rejects else None)

    # forged package must NOT poison replay cache before AEAD authentication.
    issued_poison = local.issue_for_agent(
        records[:1], policy_id="poison-test", ttl_seconds=60, fields=["customer_id"], request_id="fixed-replay-id"
    )
    forged = bytearray(issued_poison.package)
    forged[-1] ^= 0x01
    try:
        crypto.open(bytes(forged))
        print("AUTH-POISON: FAIL")
        return False
    except ValueError as e:
        assert str(e) == INERT
    # The legitimate package with the same request_id must still open.
    data_poison = crypto.open(issued_poison.package)
    assert b"customer_id" in data_poison
    print("auth failure does not poison replay: OK")

    # fresh package for remaining tests
    issued2 = local.issue_for_agent(
        records[:5], policy_id="crm.read.summary", ttl_seconds=60, fields=["customer_id"]
    )

    # TTL
    try:
        crypto.open(issued2.package, now=time.time() + 99999)
        print("TTL: FAIL")
        return False
    except ValueError as e:
        assert str(e) == INERT
        print("TTL INERT: OK  detail=", rejects[-1])

    # wrong node key (different HKDF)
    other = PackageCrypto.from_master(master, "other-node", key_id="master-v1")
    issued3 = local.issue_for_agent(
        records[:3], policy_id="p", ttl_seconds=60, fields=["customer_id"]
    )
    try:
        other.open(issued3.package)
        print("NODE KEY: FAIL")
        return False
    except ValueError as e:
        assert str(e) == INERT
        print("wrong-node key INERT: OK")

    # adversarial: garbage header of plausible length
    # build: magic+ver+len + garbage + fake nonce/ct
    garbage_hdr = b"\xff" * 64
    bad = MAGIC + bytes([VERSION]) + struct.pack(">I", 64) + garbage_hdr + os.urandom(12 + 32)
    try:
        crypto.open(bad)
        print("GARBAGE HEADER: FAIL")
        return False
    except ValueError as e:
        assert str(e) == INERT
        print("garbage header INERT: OK  detail=", rejects[-1])
    except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as e:
        print("GARBAGE HEADER leaked", type(e).__name__, e)
        return False

    # adversarial: valid JSON missing expiry
    bad_json = json.dumps({"request_id": "x", "key_id": "master-v1", "node_claim": node}).encode()
    bad2 = MAGIC + bytes([VERSION]) + struct.pack(">I", len(bad_json)) + bad_json + os.urandom(12 + 32)
    try:
        crypto.open(bad2)
        print("MISSING expiry: FAIL")
        return False
    except ValueError as e:
        assert str(e) == INERT
        print("missing expiry INERT: OK  detail=", rejects[-1])
    except KeyError as e:
        print("MISSING expiry leaked KeyError", e)
        return False

    # from_env hard fail
    os.environ.pop("ATL_PACKAGE_KEY_HEX", None)
    try:
        CloudDecryptConnector.from_env(node, dev=False)
        print("from_env hard fail: FAIL")
        return False
    except RuntimeError:
        print("from_env without key raises: OK")

    conn = CloudDecryptConnector.from_env(node, dev=True)
    # need new package for this connector's replay cache
    issued4 = LocalDataPlane(
        PackageCrypto.from_master(master, node, key_id="dev-fallback"),
        audit,
    ).issue_for_agent(records[:2], policy_id="p", ttl_seconds=30, fields=["customer_id"])
    # key_id mismatch: sealed with master-v1 path above vs dev-fallback — use matching
    crypto_dev = PackageCrypto.from_master(master, node, key_id="dev-fallback")
    local_dev = LocalDataPlane(crypto_dev, audit)
    issued4 = local_dev.issue_for_agent(records[:2], policy_id="p", ttl_seconds=30, fields=["customer_id"])
    conn = CloudDecryptConnector(crypto_dev)
    out = conn.open_package(issued4.package)
    assert out["n_out"] == 2
    print("dev connector open: OK")

    print("=" * 72)
    print("RESULTADO: PASS")
    print("=" * 72)
    return True


if __name__ == "__main__":
    ok = run_selftest(Path("/tmp/atl_onprem_audit.jsonl"))
    raise SystemExit(0 if ok else 1)
