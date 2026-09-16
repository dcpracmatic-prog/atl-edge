"""Authenticated transport between the Edge (physical/on-prem node) and the
Cloud Connector (installed on the premium agent's instance).

Why this exists: `CloudDecryptConnector` already authenticates the *payload*
(AES-GCM over the header) and `PackageCrypto.open` already rejects wrong
node/expired/replayed packages. But before any of that runs, something has
to move bytes from the Edge's disk (`src/file_workflow.Outbox`) to the
Cloud Connector's process, over a network neither side fully controls. That
hop needs its own authentication — otherwise anyone who can reach the
Connector's ingest port can feed it arbitrary bytes, or anyone who can watch
the wire can replay an old (still-technically-valid-until-TTL) request.

Design, deliberately small:

  - The Edge is the one that dials out (POST). This matches the enterprise
    reality assumed by the pitch: on-prem networks commonly block *inbound*
    connections but allow *outbound* HTTPS, so the Connector's ingest
    endpoint is the thing with a stable, reachable address (typically inside
    the cloud VPC where the premium agent instance runs), not the Edge.
  - Every request is signed with HMAC-SHA256 over
      method "\n" path "\n" timestamp "\n" nonce "\n" sha256(body)
    using `derive_transport_key(node_key)` — a key derived from, but
    distinct from, the ATLP payload key (see data_plane.derive_transport_key).
  - Timestamp window + nonce cache reject replay *at the transport layer*,
    independently of ATLP's own request_id replay cache. Two independent
    replay checks in two different layers is intentional defense in depth,
    not redundancy to delete.
  - TLS termination is assumed to happen in front of this (a real reverse
    proxy / load balancer with a real certificate). This module does not
    implement TLS itself — see docs/licensing-production.md and the note in
    this module's __doc__ for what MVP vs production covers.

This module intentionally does not run retries-with-backoff as a background
daemon itself; `push_ready()` is a single sweep, and `RetryScheduler.run_once()`
(below) is a single scheduling pass with persistent backoff state — both are
meant to be invoked by whatever scheduler the deployment already has
(systemd timer, cron, a supervised loop). What they guarantee: a failed push
leaves the package in the Outbox untouched (safe to retry), a successful
push acks it exactly once, and `RetryScheduler` dead-letters (never silently
drops) anything that exceeds `max_attempts`.
"""
from __future__ import annotations
import threading

import hashlib
import hmac
import json
import random
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from .data_plane import derive_transport_key
from .file_workflow import Outbox, OutboxEntry

TIMESTAMP_WINDOW_SECONDS = 300  # generous enough for clock skew, small enough to bound replay
SIGNATURE_HEADER = "X-ATL-Signature"
NODE_HEADER = "X-ATL-Node-Id"
TIMESTAMP_HEADER = "X-ATL-Timestamp"
NONCE_HEADER = "X-ATL-Nonce"


def _canonical_string(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path, timestamp, nonce, body_hash]).encode("utf-8")


def sign_request(transport_key: bytes, method: str, path: str, body: bytes,
                  *, timestamp: Optional[float] = None, nonce: Optional[str] = None) -> dict:
    """Return the headers a caller must attach to an authenticated request."""
    ts = str(int(timestamp if timestamp is not None else time.time()))
    nc = nonce or secrets.token_hex(16)
    mac = hmac.new(transport_key, _canonical_string(method, path, ts, nc, body), hashlib.sha256).hexdigest()
    return {
        TIMESTAMP_HEADER: ts,
        NONCE_HEADER: nc,
        SIGNATURE_HEADER: mac,
    }


class ReplayError(ValueError):
    """Transport-layer replay/forgery rejection. Deliberately generic message
    for anything returned to the network; detail stays server-side only.
    """


class NonceCache:
    """In-memory (nonce -> expiry) set, purged lazily. Bounds transport-layer
    replay to the timestamp window, independent of ATLP's own replay cache.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, float] = {}

    def check_and_record(self, nonce: str, now: float) -> None:
        with self._lock:
            dead = [k for k, exp in self._seen.items() if exp <= now]
            for k in dead:
                del self._seen[k]
            if nonce in self._seen:
                raise ReplayError("nonce replay")
            self._seen[nonce] = now + TIMESTAMP_WINDOW_SECONDS


def verify_request(transport_key: bytes, method: str, path: str, body: bytes,
                    headers: dict, nonce_cache: NonceCache, *, now: Optional[float] = None) -> None:
    """Raise ReplayError/ValueError on any failure. Never distinguishes which
    check failed to the caller — mirrors ATLP's own INERT-only contract so a
    network attacker gets no oracle either.
    """
    t = time.time() if now is None else now
    try:
        ts = float(headers[TIMESTAMP_HEADER])
        nonce = str(headers[NONCE_HEADER])
        sig = str(headers[SIGNATURE_HEADER])
        if not nonce or not sig:
            raise ValueError("missing")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("malformed transport headers") from exc

    if abs(t - ts) > TIMESTAMP_WINDOW_SECONDS:
        raise ValueError("timestamp outside window")

    expected = hmac.new(
        transport_key, _canonical_string(method, path, headers[TIMESTAMP_HEADER], nonce, body), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("bad signature")

    nonce_cache.check_and_record(nonce, t)


@dataclass(frozen=True)
class PushResult:
    entry: OutboxEntry
    delivered: bool
    status: Optional[int]
    error: Optional[str] = None


def push_ready(outbox: Outbox, node_id: str, connector_ingest_url: str, node_key_bytes: bytes,
                *, timeout: float = 10.0, archive_root: Optional[Path] = None,
                ssl_context=None) -> list:
    """One sweep: push every ready Outbox entry for `node_id` to the Connector.

    Acks (removes/archives) only entries the Connector actually returned 200
    for. Anything else is left in place for the next scheduled sweep.

    `ssl_context`: pass a context from `src.dev_tls.client_context(...)` when
    `connector_ingest_url` is `https://` and the Connector's certificate
    isn't in the system trust store (e.g. a dev self-signed cert). Left as
    `None`, `urllib` uses the system default verification for `https://` —
    which is exactly what you want against a real production certificate.
    """
    transport_key = derive_transport_key(node_key_bytes)
    results: list[PushResult] = []
    for entry in outbox.list_ready(node_id):
        package = outbox.read_package(entry)
        path = f"/ingest/{entry.node_id}/{entry.request_id}"
        url = connector_ingest_url.rstrip("/") + path
        headers = sign_request(transport_key, "POST", path, package)
        headers[NODE_HEADER] = node_id
        headers["Content-Type"] = "application/octet-stream"
        req = urllib.request.Request(url, data=package, headers=headers, method="POST")
        try:
            open_kwargs = {"timeout": timeout}
            if ssl_context is not None:
                open_kwargs["context"] = ssl_context
            with urllib.request.urlopen(req, **open_kwargs) as resp:
                status = resp.getcode()
                ok = status == 200
        except urllib.error.HTTPError as exc:
            status = exc.code
            ok = False
        except urllib.error.URLError as exc:
            results.append(PushResult(entry=entry, delivered=False, status=None, error=str(exc)))
            continue

        if ok:
            outbox.ack(entry, archive_root=archive_root)
            results.append(PushResult(entry=entry, delivered=True, status=status))
        else:
            results.append(PushResult(entry=entry, delivered=False, status=status, error="rejected"))
    return results


# ---------------------------------------------------------------------------
# Retry scheduler — persistent backoff state, dead-lettering after too many
# failures. `push_ready()` above is a single sweep with no memory between
# calls; this wraps it with the memory a real deployment needs so a
# transient network blip doesn't either hot-loop the Connector or silently
# strand a package forever.
# ---------------------------------------------------------------------------


@dataclass
class RetryState:
    attempts: int
    next_attempt_at: float
    last_error: str = ""


class RetryScheduler:
    """Wraps `push_ready` with per-entry exponential backoff (with jitter)
    and a dead-letter path for entries that exceed `max_attempts`.

    State is persisted to `<outbox_root>/<node_id>/_retry_state.json` so it
    survives process restarts — a systemd timer invoking `run_once()` every
    minute behaves the same as a long-lived loop calling it in a sleep loop;
    neither has to keep attempt counts in memory.

    This does not run a background thread itself: call `run_once()` from
    whatever scheduler the deployment already has (cron, systemd timer, a
    supervised loop). That mirrors `push_ready()`'s own contract and keeps
    this module free of daemon/signal-handling concerns.
    """

    def __init__(self, outbox: Outbox, node_id: str, connector_ingest_url: str, node_key_bytes: bytes,
                 *, max_attempts: int = 8, base_delay: float = 2.0, max_delay: float = 300.0,
                 dead_letter_root: Optional[Path] = None, archive_root: Optional[Path] = None,
                 ssl_context=None):
        self.outbox = outbox
        self.node_id = node_id
        self.connector_ingest_url = connector_ingest_url
        self.node_key_bytes = node_key_bytes
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.dead_letter_root = Path(dead_letter_root) if dead_letter_root else outbox.root.parent / "outbox-dead-letter"
        self.archive_root = archive_root
        self.ssl_context = ssl_context
        self._state_path = outbox._node_dir(node_id) / "_retry_state.json"

    def _load_state(self) -> Dict[str, RetryState]:
        if not self._state_path.exists():
            return {}
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        return {k: RetryState(**v) for k, v in raw.items()}

    def _save_state(self, state: Dict[str, RetryState]) -> None:
        payload = {k: {"attempts": v.attempts, "next_attempt_at": v.next_attempt_at, "last_error": v.last_error}
                   for k, v in state.items()}
        tmp = self._state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self._state_path)

    def _backoff_seconds(self, attempts: int) -> float:
        delay = min(self.max_delay, self.base_delay * (2 ** max(0, attempts - 1)))
        return delay * (0.5 + random.random())  # full jitter within [0.5x, 1.5x)

    def _dead_letter(self, entry: OutboxEntry, reason: str) -> None:
        dest_dir = self.dead_letter_root / entry.node_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        if entry.package_path.exists():
            entry.package_path.replace(dest_dir / entry.package_path.name)
        meta = {"request_id": entry.request_id, "node_id": entry.node_id, "policy_id": entry.policy_id,
                 "expiry": entry.expiry, "created_at": entry.created_at, "reason": reason}
        (dest_dir / f"{entry.request_id}.deadletter.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8"
        )
        self.outbox.ack(entry)  # clears the (now stale) sidecar from the live outbox

    def run_once(self, *, now: Optional[float] = None) -> Dict[str, int]:
        """One scheduling pass: push every ready entry whose backoff has
        elapsed, update attempt counters, dead-letter anything that has
        exhausted `max_attempts`. Returns a small summary dict for logging.
        """
        t = time.time() if now is None else now
        state = self._load_state()
        summary = {"delivered": 0, "deferred": 0, "dead_lettered": 0}

        due_now = []
        for entry in self.outbox.list_ready(self.node_id, now=t):
            st = state.get(entry.request_id)
            if st is None or st.next_attempt_at <= t:
                due_now.append(entry)
            else:
                summary["deferred"] += 1

        if due_now:
            # push_ready() sweeps *everything* ready; temporarily restrict to
            # what's actually due by pushing one at a time so entries still
            # in backoff are not retried early.
            for entry in due_now:
                results = _push_one(self.outbox, entry, self.connector_ingest_url, self.node_key_bytes,
                                     archive_root=self.archive_root, ssl_context=self.ssl_context)
                result = results[0]
                if result.delivered:
                    summary["delivered"] += 1
                    state.pop(entry.request_id, None)
                    continue
                st = state.get(entry.request_id, RetryState(attempts=0, next_attempt_at=0.0))
                st.attempts += 1
                st.last_error = result.error or f"status={result.status}"
                if st.attempts >= self.max_attempts:
                    self._dead_letter(entry, st.last_error)
                    state.pop(entry.request_id, None)
                    summary["dead_lettered"] += 1
                else:
                    st.next_attempt_at = t + self._backoff_seconds(st.attempts)
                    state[entry.request_id] = st

        self._save_state(state)
        return summary


def _push_one(outbox: Outbox, entry: OutboxEntry, connector_ingest_url: str, node_key_bytes: bytes,
              *, timeout: float = 10.0, archive_root: Optional[Path] = None, ssl_context=None) -> list:
    """Push exactly one already-selected entry. Shares wire logic with
    `push_ready` but does not re-derive the ready set, so `RetryScheduler`
    can push only entries whose backoff has elapsed.
    """
    transport_key = derive_transport_key(node_key_bytes)
    package = outbox.read_package(entry)
    path = f"/ingest/{entry.node_id}/{entry.request_id}"
    url = connector_ingest_url.rstrip("/") + path
    headers = sign_request(transport_key, "POST", path, package)
    headers[NODE_HEADER] = entry.node_id
    headers["Content-Type"] = "application/octet-stream"
    req = urllib.request.Request(url, data=package, headers=headers, method="POST")
    try:
        open_kwargs = {"timeout": timeout}
        if ssl_context is not None:
            open_kwargs["context"] = ssl_context
        with urllib.request.urlopen(req, **open_kwargs) as resp:
            status = resp.getcode()
            ok = status == 200
    except urllib.error.HTTPError as exc:
        status = exc.code
        ok = False
    except urllib.error.URLError as exc:
        return [PushResult(entry=entry, delivered=False, status=None, error=str(exc))]

    if ok:
        outbox.ack(entry, archive_root=archive_root)
        return [PushResult(entry=entry, delivered=True, status=status)]
    return [PushResult(entry=entry, delivered=False, status=status, error="rejected")]
