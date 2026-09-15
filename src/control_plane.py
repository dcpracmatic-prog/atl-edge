"""Reference ATL Control Plane.

`docs/licensing-production.md` describes the intended commercial boundary
(API key -> signed Entitlement -> Edge verifies locally) but, until now, the
issuer side of that boundary did not exist anywhere in this package — only
the Edge-side verification primitives in `licensing.py` did. This module is
a real, runnable reference issuer: it persists licenses, enforces
`max_nodes`, signs entitlements with Ed25519, and supports revocation.

Storage is pluggable (`src/control_plane_storage.py`): `ControlPlane(...)`
defaults to `SQLiteBackend` (zero external dependencies, one file on disk —
right for an MVP or single-process pilot), or pass `backend=PostgresBackend(dsn)`
for a real multi-process/multi-host deployment. Both backends give the same
atomicity guarantee for the operation that actually needs it — "read the
node count for this license, then insert only if there's room" — so
switching backends does not change `ControlPlane`'s behavior, only its
concurrency characteristics under load. See `control_plane_storage.py`'s
module docstring for the concrete difference (whole-database lock vs.
per-license row lock).

It is explicitly still a *reference* implementation, not the final
production service:
  - The Ed25519 signing private key is persisted to a local file (0600).
    Production should hold it in a KMS/HSM and never let it touch a
    general-purpose filesystem at rest.
  - There is no admin authentication layer here (`issue_license` is a plain
    method call, not gated behind an auth token) — the assumption is that
    whatever process embeds this module (an internal admin tool, a billing
    webhook handler) already authenticates the caller before reaching it.

None of that changes the customer-facing contract: the opaque API key is
still never a data-plane secret, and the signed Entitlement is still the
only thing an Edge trusts.
"""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .control_plane_storage import LicenseRow, SQLiteBackend, StorageBackend, StorageError
from .licensing import (
    Entitlement,
    EntitlementSigner,
    SignedEntitlement,
    activation_fingerprint,
    generate_api_key,
)

DEFAULT_PLAN_CAPABILITIES = ("agent_access",)


class LicenseError(ValueError):
    """Any control-plane-level rejection. Deliberately one exception type;
    a customer-facing API should collapse this to a generic 4xx same as the
    Edge collapses ATLP failures to INERT — no oracle for enumeration.
    """


@dataclass(frozen=True)
class LicenseSummary:
    license_id: str
    organization_id: str
    plan: str
    issued_at: float
    expires_at: float
    max_nodes: int
    max_agents: int
    capabilities: List[str]
    revoked: bool
    node_count: int


class ControlPlane:
    def __init__(self, state_dir: Path, *, backend: Optional[StorageBackend] = None):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        self._signing_key_path = self.state_dir / "signing-key.pem"
        self._signer = self._load_or_create_signer()
        self.backend: StorageBackend = backend or SQLiteBackend(self.state_dir / "control_plane.sqlite3")
        self.backend.init_schema()

    @classmethod
    def with_postgres(cls, state_dir: Path, dsn: str) -> "ControlPlane":
        """Convenience constructor: signing key still lives under
        `state_dir` (see module docstring re: KMS/HSM in production), but
        license/node state goes to Postgres instead of SQLite.
        """
        from .control_plane_storage import PostgresBackend
        return cls(state_dir, backend=PostgresBackend(dsn))

    # -- signer lifecycle --------------------------------------------------

    def _load_or_create_signer(self) -> EntitlementSigner:
        if self._signing_key_path.exists():
            data = self._signing_key_path.read_bytes()
            key = serialization.load_pem_private_key(data, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise LicenseError("stored signing key is not Ed25519")
            return EntitlementSigner(key)
        signer = EntitlementSigner.generate()
        pem = signer.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._signing_key_path.write_bytes(pem)
        os.chmod(self._signing_key_path, 0o600)
        return signer

    def public_key_pem(self) -> bytes:
        return self._signer.public_key_pem()

    # -- admin operations ------------------------------------------------

    def issue_license(self, organization_id: str, plan: str, *, duration_days: int = 365,
                       max_nodes: int = 1, max_agents: int = 1,
                       capabilities: Optional[List[str]] = None) -> dict:
        """Create a new license and return the opaque API key ONCE.

        Only the SHA-256 fingerprint of the key is persisted — same
        principle as a password hash. If the caller loses the returned key,
        the only remedy is issuing a new one; the control plane cannot
        recover it.
        """
        api_key = generate_api_key("atl_live")
        license_id = "lic-" + uuid.uuid4().hex[:16]
        now = time.time()
        row = LicenseRow(
            license_id=license_id, organization_id=organization_id, plan=plan,
            api_key_fingerprint=activation_fingerprint(api_key),
            issued_at=now, expires_at=now + duration_days * 86400,
            max_nodes=max_nodes, max_agents=max_agents,
            capabilities=list(capabilities or DEFAULT_PLAN_CAPABILITIES), revoked=False,
        )
        self.backend.insert_license(row)
        return {"license_id": license_id, "api_key": api_key}

    def revoke_license(self, license_id: str) -> None:
        if not self.backend.set_revoked(license_id):
            raise LicenseError("unknown license")

    def get_license(self, license_id: str) -> LicenseSummary:
        row = self.backend.get_by_id(license_id)
        if row is None:
            raise LicenseError("unknown license")
        return _row_to_summary(row, self.backend.node_count(license_id))

    # -- customer-facing operation -----------------------------------------

    def activate(self, api_key: str, *, node_id: str, instance_id: str, agent_id: str) -> SignedEntitlement:
        """Exchange an API key for a signed, node-bound Entitlement.

        Re-activating with the same node_id is idempotent. A *new* node_id
        is only accepted while the registered node count is below
        `max_nodes` — enforced atomically by the storage backend (see
        `control_plane_storage.StorageBackend.register_node_atomic`), not
        by this method doing its own read-then-write.
        """
        fp = activation_fingerprint(api_key)
        row = self.backend.get_by_fingerprint(fp)
        if row is None:
            raise LicenseError("invalid api key")
        if row.revoked:
            raise LicenseError("license revoked")
        now = time.time()
        if now >= row.expires_at:
            raise LicenseError("license expired")

        try:
            self.backend.register_node_atomic(row.license_id, node_id, instance_id, now, row.max_nodes)
        except StorageError:
            raise LicenseError("max_nodes exceeded")

        entitlement = Entitlement(
            license_id=row.license_id, organization_id=row.organization_id,
            plan=row.plan, issued_at=now, expires_at=row.expires_at,
            max_nodes=row.max_nodes, max_agents=row.max_agents,
            capabilities=tuple(row.capabilities),
            node_id=node_id, instance_id=instance_id,
            key_id="node-" + uuid.uuid4().hex[:12],
        )
        return self._signer.sign(entitlement)


def _row_to_summary(row: LicenseRow, node_count: int) -> LicenseSummary:
    return LicenseSummary(
        license_id=row.license_id, organization_id=row.organization_id, plan=row.plan,
        issued_at=row.issued_at, expires_at=row.expires_at,
        max_nodes=row.max_nodes, max_agents=row.max_agents,
        capabilities=row.capabilities, revoked=row.revoked, node_count=node_count,
    )
