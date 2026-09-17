"""ATL licensing and node provisioning primitives.

The annual API key is an activation credential, not an ATLP data-encryption key.
A production control plane should exchange it for a signed entitlement. The
Edge verifies the entitlement locally and uses separate per-node material for
ATLP/Connector traffic.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_api_key(prefix: str = "atl_live") -> str:
    """Generate an opaque activation key. Do not use it as a data-plane secret."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


@dataclass(frozen=True)
class Entitlement:
    license_id: str
    organization_id: str
    plan: str
    issued_at: float
    expires_at: float
    max_nodes: int = 1
    max_agents: int = 1
    capabilities: tuple[str, ...] = ("agent_access",)
    node_id: str = ""
    instance_id: str = ""
    key_id: str = ""
    agent_id: str = ""

    def canonical_bytes(self) -> bytes:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True).encode()


@dataclass(frozen=True)
class SignedEntitlement:
    payload: Dict[str, Any]
    signature: str

    def to_json(self) -> str:
        return json.dumps({"payload": self.payload, "signature": self.signature}, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "SignedEntitlement":
        obj = json.loads(text)
        if not isinstance(obj, dict) or not isinstance(obj.get("payload"), dict) or not isinstance(obj.get("signature"), str):
            raise ValueError("invalid entitlement")
        return cls(payload=obj["payload"], signature=obj["signature"])


class EntitlementSigner:
    """Control-plane signer. The private key must remain outside customer packages."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self.private_key = private_key

    @classmethod
    def generate(cls) -> "EntitlementSigner":
        return cls(Ed25519PrivateKey.generate())

    def public_key_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, entitlement: Entitlement) -> SignedEntitlement:
        payload = asdict(entitlement)
        payload["capabilities"] = list(entitlement.capabilities)
        sig = self.private_key.sign(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        return SignedEntitlement(payload=payload, signature=_b64e(sig))


def verify_entitlement(signed: SignedEntitlement, public_key_pem: bytes, *, now: Optional[float] = None,
                       organization_id: Optional[str] = None, node_id: Optional[str] = None) -> Entitlement:
    public = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("invalid entitlement public key")
    raw = json.dumps(signed.payload, separators=(",", ":"), sort_keys=True).encode()
    try:
        public.verify(_b64d(signed.signature), raw)
    except Exception as exc:
        raise ValueError("invalid entitlement signature") from exc
    try:
        ent = Entitlement(
            license_id=str(signed.payload["license_id"]),
            organization_id=str(signed.payload["organization_id"]),
            plan=str(signed.payload["plan"]),
            issued_at=float(signed.payload["issued_at"]),
            expires_at=float(signed.payload["expires_at"]),
            max_nodes=int(signed.payload["max_nodes"]),
            max_agents=int(signed.payload["max_agents"]),
            capabilities=tuple(str(x) for x in signed.payload.get("capabilities", [])),
            node_id=str(signed.payload.get("node_id", "")),
            instance_id=str(signed.payload.get("instance_id", "")),
            key_id=str(signed.payload.get("key_id", "")),
            agent_id=str(signed.payload.get("agent_id", "")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid entitlement payload") from exc
    t = time.time() if now is None else now
    if t < ent.issued_at or t >= ent.expires_at:
        raise ValueError("license expired or not yet active")
    if organization_id and ent.organization_id != organization_id:
        raise ValueError("organization mismatch")
    if node_id and ent.node_id and ent.node_id != node_id:
        raise ValueError("node mismatch")
    return ent


@dataclass(frozen=True)
class NodeIdentity:
    organization_id: str
    node_id: str
    instance_id: str
    agent_id: str
    key_id: str
    node_key_hex: str

    @classmethod
    def generate(cls, organization_id: str, node_id: str, instance_id: str, agent_id: str, key_id: Optional[str] = None) -> "NodeIdentity":
        return cls(
            organization_id=organization_id,
            node_id=node_id,
            instance_id=instance_id,
            agent_id=agent_id,
            key_id=key_id or "node-" + secrets.token_hex(8),
            node_key_hex=secrets.token_bytes(32).hex(),
        )

    def public_config(self) -> Dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "node_key_env": "ATL_NODE_KEY_HEX",
        }


def write_node_identity(identity: NodeIdentity, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    (directory / "node.json").write_text(json.dumps(identity.public_config(), indent=2, sort_keys=True) + "\n")
    secret = directory / "node-key.hex"
    secret.write_text(identity.node_key_hex + "\n")
    os.chmod(secret, 0o600)


def activation_fingerprint(api_key: str) -> str:
    """Audit handle for a high-entropy API key — not password storage.

    SHA-256 is appropriate here: the input is a 256-bit random token, not a
    user-chosen password. Do not switch to PBKDF2; that would break existing
    entitlement fingerprints.

    codeql[py/weak-sensitive-data-hashing]
    """
    # lgtm[py/weak-sensitive-data-hashing]
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
