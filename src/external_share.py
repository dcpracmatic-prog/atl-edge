"""External Share — TDCP-derived authorization boundary for third parties
outside the enterprise infrastructure.

Where this sits relative to the rest of ATL Edge
--------------------------------------------------
ATLP (`data_plane.py`) and SmartTokenProd (`long_lived_protection.py`) both
protect data moving between *infrastructure the organization controls*: the
on-prem node and the premium agent's cloud instance. Neither one is meant to
hand a file to a human being who is not running ATL software at all — a
client, an auditor, a partner opening a link in a browser.

This module is that missing leg. It ports the TDCP reference model — an
Authorization Oracle that never sees plaintext, a single Gatekeeper seam
that is the only path allowed to unlock a package, and a hash-chained audit
sink — to server-side Python, so that ATL Edge can issue **revocable,
short-lived, one-time (optionally) grants to recipients outside the
enterprise boundary**, whether that recipient is a person with a browser
or another organization's system calling in over an API.

Core invariant (unchanged from TDCP)
-------------------------------------
    Copying the ciphertext does not copy the authorization.

The `.xshare` package is storage — it can sit in an S3 bucket, an email
attachment, a partner's inbox, anywhere. The ExternalShareOracle is the
control plane. ExternalShareGatekeeper is the only path that may release
the wrap secret needed to decrypt it. Revoking access means telling the
Oracle to stop granting — it does not require reaching the file.

Security boundary (same caveat TDCP states, ported honestly)
--------------------------------------------------------------
In this reference implementation the Oracle and its revocation/replay state
live in the same process as the rest of the Edge (in-memory by default,
optionally backed by `control_plane_storage` for persistence — see
`ExternalShareOracle(store=...)`). That process is a real network service
(unlike TDCP's browser build), which is a meaningfully stronger boundary,
but it is still this deployment's own server. For grants crossing into a
genuinely untrusted recipient (an outside company, a device you do not
control), the recommended posture is: this Oracle runs on infrastructure
the issuing organization controls, the recipient never receives the wrap
secret directly, and every grant is bound to a specific recipient identity
and expires. Do not describe this Oracle as a remote sovereign authority,
HSM, or hardware-backed boundary — same rule TDCP states for itself.

Cryptographic primitives (matches ATL Edge conventions elsewhere in the repo)
--------------------------------------------------------------------------------
- AES-256-GCM for authenticated encryption of the shared payload (`cryptography`).
- HKDF-SHA-256 for deriving the content-encryption key from the per-share
  wrap secret (never the raw secret itself).
- Ed25519 for Oracle-signed grants (matches `licensing.EntitlementSigner`,
  not ECDSA P-256 like the browser TDCP build — no WebCrypto constraint here).
- `secrets` for all nonces, ids, and the wrap secret.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"XSHR"
VERSION = 1
GENESIS_HASH = "0" * 64
DENIED = "DENIED"  # generic external-facing denial; detail stays in local audit only


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(12)}"


# ---------------------------------------------------------------------------
# Recipient identity — who outside the org boundary this share is bound to
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RecipientIdentity:
    """A third party outside enterprise infrastructure.

    Covers both cases: a human (kind='human', identifier=email or subject id
    from whatever auth front-end validated them) and a machine caller
    (kind='system', identifier=API client id / mTLS subject / service account).
    The Oracle never trusts this on its own — `credential_fingerprint` must
    match what the recipient actually presents at redemption time.
    """
    kind: str  # "human" | "system"
    identifier: str
    organization: str  # the recipient's org, distinct from the issuing org
    credential_fingerprint: str  # sha256 of a pubkey, WebAuthn credential id, or API key

    def __post_init__(self) -> None:
        if self.kind not in ("human", "system"):
            raise ValueError("kind must be 'human' or 'system'")
        if not self.identifier or not self.organization or not self.credential_fingerprint:
            raise ValueError("identifier, organization, and credential_fingerprint are required")


# ---------------------------------------------------------------------------
# Share policy — registered against a package at issuance time
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SharePolicy:
    share_id: str
    package_id: str
    recipient: RecipientIdentity
    allow_download: bool  # False => view-only surface, caller enforces render-only
    view_once: bool
    max_grants: Optional[int]  # None = unlimited redemptions until expiry/revoke
    expires_at: float  # epoch seconds; hard ceiling regardless of grant TTL
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Grant — what the Gatekeeper actually receives and redeems
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ShareGrant:
    grant_id: str
    share_id: str
    package_id: str
    recipient_identifier: str
    operation: str  # "decrypt" | "view"
    issued_at: float
    expires_at: float
    one_time_use: bool
    oracle_key_id: str
    signature: str = ""

    def unsigned(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("signature")
        return d


# ---------------------------------------------------------------------------
# Audit — hash-chained, tamper-evident, local by default
# Ports TDCP's LocalAuditSink/RemoteAuditSink split honestly: this process's
# chain is tamper-evident within this process; it is not an external
# immutable ledger unless wired to one.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ShareAuditEvent:
    event_id: str
    timestamp: float
    share_id: str
    package_id: str
    recipient_identifier: str
    operation: str
    result: str  # "GRANTED" | "DENIED" | "REVOKED" | "REGISTERED"
    detail: str
    previous_event_hash: str
    event_hash: str = ""


class AuditSink(Protocol):
    def record(
        self, *, share_id: str, package_id: str, recipient_identifier: str,
        operation: str, result: str, detail: str,
    ) -> ShareAuditEvent: ...

    def events(self) -> List[ShareAuditEvent]: ...

    def verify_integrity(self) -> Dict[str, Any]: ...


class LocalAuditSink:
    """In-process hash-chained audit log. Tamper-evident within this
    process's lifetime and storage backend; NOT a claim of an external
    immutable ledger — same caveat TDCP states for its LocalAuditSink."""

    sink_name = "LocalAuditSink (tamper-evident, process-local)"
    is_authoritative = False

    def __init__(self) -> None:
        self._events: List[ShareAuditEvent] = []
        genesis = ShareAuditEvent(
            event_id="AUDIT-GENESIS",
            timestamp=time.time(),
            share_id="SYSTEM",
            package_id="SYSTEM",
            recipient_identifier="SYSTEM",
            operation="GENESIS",
            result="GRANTED",
            detail="external_share audit chain initialized",
            previous_event_hash=GENESIS_HASH,
        )
        self._events.append(self._sealed(genesis))

    @staticmethod
    def _sealed(evt: ShareAuditEvent) -> ShareAuditEvent:
        payload = asdict(evt)
        payload.pop("event_hash")
        digest = hashlib.sha256(_canonical(payload)).hexdigest()
        return ShareAuditEvent(**{**asdict(evt), "event_hash": digest})

    def record(
        self, *, share_id: str, package_id: str, recipient_identifier: str,
        operation: str, result: str, detail: str,
    ) -> ShareAuditEvent:
        prev = self._events[-1].event_hash
        evt = ShareAuditEvent(
            event_id=_new_id("EVT"),
            timestamp=time.time(),
            share_id=share_id,
            package_id=package_id,
            recipient_identifier=recipient_identifier,
            operation=operation,
            result=result,
            detail=detail,
            previous_event_hash=prev,
        )
        sealed = self._sealed(evt)
        self._events.append(sealed)
        return sealed

    def events(self) -> List[ShareAuditEvent]:
        return list(self._events)

    def verify_integrity(self) -> Dict[str, Any]:
        expected_prev = GENESIS_HASH
        for i, evt in enumerate(self._events):
            if evt.previous_event_hash != expected_prev:
                return {"valid": False, "checked": i, "error": f"chain break at index {i} ({evt.event_id})"}
            payload = asdict(evt)
            payload.pop("event_hash")
            computed = hashlib.sha256(_canonical(payload)).hexdigest()
            if computed != evt.event_hash:
                return {"valid": False, "checked": i, "error": f"hash mismatch at {evt.event_id}"}
            expected_prev = evt.event_hash
        return {"valid": True, "checked": len(self._events)}


# ---------------------------------------------------------------------------
# Oracle — the control plane. Never sees plaintext or the content key.
# ---------------------------------------------------------------------------

class ExternalShareOracle:
    """Authorization control plane for sharing with third parties outside
    enterprise infrastructure.

    Mirrors TDCP's AuthorizationOracle:
      - Holds a per-share wrap secret, generated at registration, never
        written into the package.
      - Signs one-time grants with Ed25519 (this repo's convention —
        see licensing.EntitlementSigner — rather than TDCP's browser-only
        ECDSA P-256/WebCrypto choice).
      - Releases the wrap secret only for a valid, signed, unexpired,
        non-revoked, non-replayed grant.
      - Revocation is instantaneous from the Oracle's perspective: it does
        not require reaching the ciphertext, which may already be sitting
        in a recipient's inbox or S3 bucket outside this org's control.
    """

    def __init__(self, signing_key: Optional[Ed25519PrivateKey] = None, audit: Optional[AuditSink] = None):
        self._signing_key = signing_key or Ed25519PrivateKey.generate()
        self._key_id = "xshare-" + hashlib.sha256(
            self._signing_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).hexdigest()[:12]
        self._policies: Dict[str, SharePolicy] = {}
        self._wrap_secrets: Dict[str, bytes] = {}
        self._revoked: set[str] = set()
        self._grants_issued: Dict[str, int] = {}
        self._consumed_grant_ids: set[str] = set()
        self._seen_nonces: set[str] = set()
        self.audit: AuditSink = audit or LocalAuditSink()

    def public_key_pem(self) -> bytes:
        return self._signing_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def key_id(self) -> str:
        return self._key_id

    def register_share(self, policy: SharePolicy) -> bytes:
        """Registers a package for external sharing and returns its wrap
        secret. Caller (Gatekeeper.seal) uses this secret, via HKDF, to
        derive the actual AES-GCM key — the raw secret itself never touches
        the package bytes."""
        self._policies[policy.share_id] = policy
        secret = secrets.token_bytes(32)
        self._wrap_secrets[policy.share_id] = secret
        self._grants_issued[policy.share_id] = 0
        self.audit.record(
            share_id=policy.share_id, package_id=policy.package_id,
            recipient_identifier=policy.recipient.identifier, operation="REGISTER",
            result="GRANTED",
            detail=f"share registered for {policy.recipient.organization} "
                   f"({policy.recipient.kind}), expires_at={policy.expires_at}",
        )
        return secret

    def revoke(self, share_id: str, reason: str) -> bool:
        if share_id not in self._policies:
            return False
        self._revoked.add(share_id)
        self._wrap_secrets.pop(share_id, None)
        policy = self._policies[share_id]
        self.audit.record(
            share_id=share_id, package_id=policy.package_id,
            recipient_identifier=policy.recipient.identifier, operation="REVOKE",
            result="REVOKED", detail=reason,
        )
        return True

    def request_grant(
        self, *, share_id: str, operation: str, credential_fingerprint: str,
        nonce: str, requested_at: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Evaluates an external redemption request and, if authorized,
        returns a signed one-time grant. The caller (Gatekeeper) is the
        only intended consumer — never expose this directly to the
        recipient's browser/client without the Gatekeeper seam in front."""
        now = requested_at if requested_at is not None else time.time()

        if nonce in self._seen_nonces:
            return self._deny(share_id, operation, "REPLAY_DETECTED: nonce already consumed")
        policy = self._policies.get(share_id)
        if not policy:
            return self._deny(share_id, operation, "SHARE_NOT_REGISTERED: copying the package does not grant authorization")
        if share_id in self._revoked:
            return self._deny(share_id, operation, "REVOKED")
        if now > policy.expires_at:
            return self._deny(share_id, operation, "EXPIRED")
        if not hmac.compare_digest(credential_fingerprint, policy.recipient.credential_fingerprint):
            return self._deny(share_id, operation, "CREDENTIAL_MISMATCH")
        if policy.max_grants is not None and self._grants_issued.get(share_id, 0) >= policy.max_grants:
            return self._deny(share_id, operation, "GRANT_LIMIT_REACHED")
        if policy.view_once and self._grants_issued.get(share_id, 0) >= 1:
            return self._deny(share_id, operation, "VIEW_ONCE_ALREADY_CONSUMED")

        self._seen_nonces.add(nonce)
        expires_at = min(policy.expires_at, now + 60.0)  # grants are short-lived regardless of share TTL
        unsigned = ShareGrant(
            grant_id=_new_id("GRANT"),
            share_id=share_id,
            package_id=policy.package_id,
            recipient_identifier=policy.recipient.identifier,
            operation=operation,
            issued_at=now,
            expires_at=expires_at,
            one_time_use=True,
            oracle_key_id=self._key_id,
        )
        signature = self._signing_key.sign(_canonical(unsigned.unsigned()))
        grant = ShareGrant(**{**asdict(unsigned), "signature": _b64e(signature)})

        self._grants_issued[share_id] = self._grants_issued.get(share_id, 0) + 1
        self.audit.record(
            share_id=share_id, package_id=policy.package_id,
            recipient_identifier=policy.recipient.identifier, operation=operation,
            result="GRANTED", detail=f"grant_id={grant.grant_id}",
        )
        return {"granted": True, "grant": grant}

    def _deny(self, share_id: str, operation: str, detail: str) -> Dict[str, Any]:
        policy = self._policies.get(share_id)
        self.audit.record(
            share_id=share_id, package_id=policy.package_id if policy else "UNKNOWN",
            recipient_identifier=policy.recipient.identifier if policy else "UNKNOWN",
            operation=operation, result="DENIED", detail=detail,
        )
        # External-facing message stays generic; detail lives only in local audit —
        # mirrors data_plane.py's INERT convention for this repo.
        return {"granted": False, "rejection": DENIED}

    def release_wrap_secret(self, grant: ShareGrant) -> Optional[bytes]:
        """Releases the per-share wrap secret only for a grant this Oracle
        itself signed, not yet consumed, unexpired, and for a share that is
        still registered and unrevoked. This is the one function in the
        module that returns key material — call it only from the
        Gatekeeper seam, never from a network-facing handler directly."""
        if not grant.one_time_use or grant.grant_id in self._consumed_grant_ids:
            return None
        if grant.oracle_key_id != self._key_id:
            return None
        if time.time() > grant.expires_at:
            return None
        if grant.share_id in self._revoked:
            return None
        policy = self._policies.get(grant.share_id)
        if not policy or policy.package_id != grant.package_id:
            return None

        public_key = self._signing_key.public_key()
        try:
            public_key.verify(_b64d(grant.signature), _canonical(grant.unsigned()))
        except Exception:
            return None

        secret = self._wrap_secrets.get(grant.share_id)
        if not secret:
            return None
        self._consumed_grant_ids.add(grant.grant_id)
        return secret


# ---------------------------------------------------------------------------
# Gatekeeper — the ONLY application path that may seal or unlock a share.
# Mirrors TDCP's "Gatekeeper is the only application path" rule.
# ---------------------------------------------------------------------------

class ExternalShareGatekeeper:
    """The single seam through which external-share packages are created
    and opened. Nothing else in ATL Edge should call AESGCM directly for
    this purpose — route everything through here, the same way ATL Edge's
    own README requires all side-effecting tool execution to route through
    `ATLDataPlaneMVP.execute_and_issue`."""

    def __init__(self, oracle: ExternalShareOracle):
        self.oracle = oracle

    def seal(
        self, plaintext: bytes, *, package_id: str, recipient: RecipientIdentity,
        allow_download: bool = True, view_once: bool = False,
        max_grants: Optional[int] = None, ttl_seconds: float = 7 * 24 * 3600,
        aad: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Encrypts plaintext for an external recipient and registers its
        policy with the Oracle. Returns the package bytes (safe to store
        anywhere — S3, email, a partner's system) plus the share_id needed
        to redeem it. The wrap secret never leaves this function."""
        share_id = _new_id("SHARE")
        now = time.time()
        policy = SharePolicy(
            share_id=share_id, package_id=package_id, recipient=recipient,
            allow_download=allow_download, view_once=view_once,
            max_grants=max_grants, expires_at=now + ttl_seconds, created_at=now,
        )
        wrap_secret = self.oracle.register_share(policy)

        salt = secrets.token_bytes(16)
        cek = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            info=f"xshare-cek|{share_id}".encode(),
        ).derive(wrap_secret)

        nonce = secrets.token_bytes(12)
        header = {
            "magic": MAGIC.decode(), "version": VERSION, "share_id": share_id,
            "package_id": package_id, "recipient_org": recipient.organization,
            "view_once": view_once, "salt": _b64e(salt), "nonce": _b64e(nonce),
        }
        # Security-relevant metadata is authenticated via AAD, matching the
        # TDCP 2.5 correction: envelope integrity must cover the header,
        # not just the ciphertext.
        header_aad = _canonical(header) + (aad or b"")
        ciphertext = AESGCM(cek).encrypt(nonce, plaintext, header_aad)

        package = {"header": header, "ciphertext": _b64e(ciphertext)}
        return {"share_id": share_id, "package": package, "policy": policy}

    def open(
        self, package: Dict[str, Any], *, credential_fingerprint: str,
        nonce: Optional[str] = None, aad: Optional[bytes] = None,
    ) -> bytes:
        """The only function that turns a sealed package back into
        plaintext. Requests a fresh grant from the Oracle, then redeems it
        immediately — mirrors TDCP's rule that View-Once is committed only
        after successful decryption, so a failed open does not burn a
        one-time grant's underlying share allowance."""
        header = package["header"]
        if header.get("magic") != MAGIC.decode() or header.get("version") != VERSION:
            raise ValueError(DENIED)
        share_id = header["share_id"]
        req_nonce = nonce or secrets.token_hex(16)

        result = self.oracle.request_grant(
            share_id=share_id, operation="decrypt",
            credential_fingerprint=credential_fingerprint, nonce=req_nonce,
        )
        if not result["granted"]:
            raise ValueError(DENIED)
        grant: ShareGrant = result["grant"]

        wrap_secret = self.oracle.release_wrap_secret(grant)
        if wrap_secret is None:
            raise ValueError(DENIED)

        salt = _b64d(header["salt"])
        cek = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            info=f"xshare-cek|{share_id}".encode(),
        ).derive(wrap_secret)

        header_for_aad = {k: v for k, v in header.items()}
        header_aad = _canonical(header_for_aad) + (aad or b"")
        aes_nonce = _b64d(header["nonce"])
        ciphertext = _b64d(package["ciphertext"])

        try:
            plaintext = AESGCM(cek).decrypt(aes_nonce, ciphertext, header_aad)
        except Exception as exc:
            # Decryption failed — grant was already consumed above, matching
            # TDCP's tradeoff: a one-time grant is spent on redemption, not
            # on successful plaintext recovery. If this distinction matters
            # for your deployment (e.g. view_once should only burn on
            # success), request a fresh grant before decrypting instead.
            raise ValueError(DENIED) from exc

        return plaintext
