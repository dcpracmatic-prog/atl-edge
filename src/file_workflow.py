"""On-disk file workflow for ATL Edge.

Prior to this module, the whole data plane only moved `bytes` in memory
between function calls. That is fine for a single-process selftest, but it
means there was no answer to: "where does a sealed package live between the
moment the Edge issues it and the moment the Cloud Connector picks it up?",
and "if a raw file is dropped for the Edge to predigest, how does it avoid
being read half-written, processed twice, or lost on a crash?".

This module answers both with two directories rooted at a per-deployment
`data_dir`:

  inbox/<source>/<uuid>__<original_name> (+ .meta.json sidecar)
      Raw input dropped for the Edge to predigest (an exported CSV, a PDF, a
      text dump). Landing is a write-to-temp + os.replace() so a concurrent
      reader never observes a half-written file, and a sidecar records
      provenance (source, sha256, received_at) without needing to open the
      file to know what it is.

  outbox/<node_id>/<request_id>.atlp (+ <request_id>.meta.json sidecar)
      Sealed ATLP packages ready for the Cloud Connector installed on the
      premium agent's instance. The sidecar is what a connector polls: it
      never contains key material or plaintext, only enough metadata
      (policy_id, expiry, size, sha256) to decide whether to fetch.

Discovery contract for the calling agent's connector:
  1. Outbox.list_ready(node_id)   -> ordered, not-yet-expired entries
  2. Outbox.read_package(entry)   -> bytes, feed to CloudDecryptConnector.open_package
  3. Outbox.ack(entry)            -> removes/archives the package (idempotent)

Expired entries are swept rather than handed out: a connector that fetched
one would just get ATLP's generic INERT back, so there is no reason to pay
the transfer cost.

This intentionally does NOT implement a distributed queue or cross-host
locking: it is one Edge process writing to local disk that it owns. Getting
packages from this Outbox to a Cloud Connector on a different host is the
job of `src/transport.py`, layered on top.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".part-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomic within the same filesystem


def _safe_name(name: str) -> str:
    """Collapse a caller-provided identifier to a single path segment.

    Never trust source/request identifiers for path traversal: this is the
    only thing standing between an attacker-influenced request_id and
    `outbox/../../etc/passwd`.
    """
    cleaned = Path(str(name)).name
    return cleaned or "unnamed"


# ---------------------------------------------------------------------------
# Inbox — raw files handed to the Edge for predigestion
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InboxItem:
    source: str
    item_id: str
    original_name: str
    path: Path
    received_at: float
    sha256: str
    size_bytes: int


class Inbox:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def receive(self, source: str, original_name: str, data: bytes) -> InboxItem:
        source = _safe_name(source)
        item_id = uuid.uuid4().hex
        fname = f"{item_id}__{_safe_name(original_name)}"
        dest = self.root / source / fname
        _atomic_write(dest, data)
        os.chmod(dest, 0o600)
        item = InboxItem(
            source=source, item_id=item_id, original_name=original_name,
            path=dest, received_at=time.time(),
            sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data),
        )
        meta_path = dest.with_name(dest.name + ".meta.json")
        _atomic_write(meta_path, json.dumps({
            "source": item.source, "item_id": item.item_id,
            "original_name": item.original_name, "received_at": item.received_at,
            "sha256": item.sha256, "size_bytes": item.size_bytes,
        }, indent=2, sort_keys=True).encode())
        os.chmod(meta_path, 0o600)
        return item

    def list_pending(self, source: Optional[str] = None) -> List[InboxItem]:
        base = (self.root / _safe_name(source)) if source else self.root
        out: List[InboxItem] = []
        if not base.exists():
            return out
        for meta_path in sorted(base.rglob("*.meta.json")):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            data_path = meta_path.with_name(meta_path.name[: -len(".meta.json")])
            if not data_path.exists():
                continue
            out.append(InboxItem(
                source=meta["source"], item_id=meta["item_id"],
                original_name=meta["original_name"], path=data_path,
                received_at=meta["received_at"], sha256=meta["sha256"],
                size_bytes=meta.get("size_bytes", 0),
            ))
        out.sort(key=lambda i: i.received_at)
        return out

    def archive(self, item: InboxItem, archive_root: Path) -> None:
        """Move a processed item out of the pending set. Idempotent: a
        missing source file (already archived by a concurrent worker) is not
        an error.
        """
        dest_dir = Path(archive_root) / item.source
        dest_dir.mkdir(parents=True, exist_ok=True)
        meta_src = item.path.with_name(item.path.name + ".meta.json")
        if item.path.exists():
            os.replace(item.path, dest_dir / item.path.name)
        if meta_src.exists():
            os.replace(meta_src, dest_dir / meta_src.name)


# ---------------------------------------------------------------------------
# Outbox — sealed ATLP packages ready for the Cloud Connector
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OutboxEntry:
    node_id: str
    request_id: str
    policy_id: str
    expiry: float
    created_at: float
    package_path: Path
    package_bytes: int
    package_sha256: str


class Outbox:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _node_dir(self, node_id: str) -> Path:
        d = self.root / _safe_name(node_id)
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        return d

    def deposit(self, node_id: str, request_id: str, package: bytes, *,
                policy_id: str, expiry: float, created_at: Optional[float] = None) -> OutboxEntry:
        rid = _safe_name(request_id)
        node_dir = self._node_dir(node_id)
        pkg_path = node_dir / f"{rid}.atlp"
        _atomic_write(pkg_path, package)
        os.chmod(pkg_path, 0o600)
        entry = OutboxEntry(
            node_id=node_id, request_id=request_id, policy_id=policy_id,
            expiry=expiry, created_at=created_at if created_at is not None else time.time(),
            package_path=pkg_path, package_bytes=len(package),
            package_sha256=hashlib.sha256(package).hexdigest(),
        )
        meta_path = node_dir / f"{rid}.meta.json"
        _atomic_write(meta_path, json.dumps({
            "node_id": entry.node_id, "request_id": entry.request_id,
            "policy_id": entry.policy_id, "expiry": entry.expiry,
            "created_at": entry.created_at, "package_bytes": entry.package_bytes,
            "package_sha256": entry.package_sha256,
        }, indent=2, sort_keys=True).encode())
        os.chmod(meta_path, 0o600)
        return entry

    def list_ready(self, node_id: str, *, now: Optional[float] = None) -> List[OutboxEntry]:
        t = time.time() if now is None else now
        node_dir = self._node_dir(node_id)
        out: List[OutboxEntry] = []
        for meta_path in sorted(node_dir.glob("*.meta.json")):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            pkg_path = node_dir / f"{meta['request_id']}.atlp"
            if not pkg_path.exists():
                meta_path.unlink(missing_ok=True)
                continue
            if meta["expiry"] <= t:
                self._sweep(meta_path, pkg_path)
                continue
            out.append(OutboxEntry(
                node_id=meta["node_id"], request_id=meta["request_id"],
                policy_id=meta["policy_id"], expiry=meta["expiry"],
                created_at=meta["created_at"], package_path=pkg_path,
                package_bytes=meta["package_bytes"], package_sha256=meta["package_sha256"],
            ))
        out.sort(key=lambda e: e.created_at)
        return out

    def read_package(self, entry: OutboxEntry) -> bytes:
        return entry.package_path.read_bytes()

    def ack(self, entry: OutboxEntry, *, archive_root: Optional[Path] = None) -> None:
        """Remove (or archive) a delivered package. Idempotent: safe to call
        twice, and safe if the transport already deleted the files.
        """
        rid = _safe_name(entry.request_id)
        meta_path = self._node_dir(entry.node_id) / f"{rid}.meta.json"
        if archive_root is not None:
            dest_dir = Path(archive_root) / _safe_name(entry.node_id)
            dest_dir.mkdir(parents=True, exist_ok=True)
            if entry.package_path.exists():
                os.replace(entry.package_path, dest_dir / entry.package_path.name)
            if meta_path.exists():
                os.replace(meta_path, dest_dir / meta_path.name)
        else:
            entry.package_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)

    def _sweep(self, meta_path: Path, pkg_path: Path) -> None:
        meta_path.unlink(missing_ok=True)
        pkg_path.unlink(missing_ok=True)
