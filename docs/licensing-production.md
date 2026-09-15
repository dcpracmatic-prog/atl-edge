# ATL Licensing / Activation Contract

This document fixes the intended production boundary for the MVP.

## Distribution

The ATL Edge package is distributed as one generic installable package. The
package may be downloaded and installed before licensing, but it starts in
`LOCKED` state.

## Activation

The customer purchases an annual ATL license through the ATL Control Plane and
receives an opaque API key. The API key is an activation credential only. It is
not an ATLP encryption key and must not be used as one.

The production Control Plane exchanges the API key for a signed entitlement.
The Edge verifies the entitlement locally using ATL's public verification key.
The Control Plane private signing key never ships in the customer package.

## Provisioning

After activation, the Edge creates or registers a unique node identity and
provisions customer-specific Connector/SDK configuration for authorized agent
instances. Generated bundles contain configuration and integration code, not
the Control Plane signing key and not an ATL master encryption key.

Per-node secrets are stored separately in the node secret store. They are not
embedded in source code, SDK files, or the generic distribution archive.

## Production replacement of the MVP authority

The repository now contains a real, runnable reference issuer
(`src/control_plane.py` + `src/control_plane_server.py`), not only Edge-side
verification primitives. It issues licenses, signs entitlements, and
enforces `max_nodes` over real HTTP (`atlctl request-license` is the
Edge-side client). Storage is pluggable
(`src/control_plane_storage.py`): the default `SQLiteBackend` needs nothing
beyond `requirements.txt` and is right for an MVP or single-process pilot;
`ControlPlane.with_postgres(state_dir, dsn)` swaps in `PostgresBackend` for
a real multi-process/multi-host deployment, with per-license row locking
(`SELECT ... FOR UPDATE`) instead of SQLite's whole-database lock — proven
against a real Postgres instance in
`examples/control_plane_postgres_selftest.py`. Both this server and the
Cloud Connector's ingest server (`connector/cloud_runtime.py`) also
terminate real TLS (`src/dev_tls.py`, `examples/tls_selftest.py`), so
neither the signed entitlement nor a sealed ATLP package needs to travel
in the clear. It is still explicitly a *reference* implementation: the
signing key is persisted to a local file instead of a KMS/HSM, the TLS
certificates the selftests use are self-signed dev throwaways instead of
real-CA-issued production certs, and there is no admin-auth layer gating
license issuance (so issuance is a Python-level call, not an HTTP
endpoint — wire it into whatever already-authenticated admin tool a real
deployment has). None of that changes the wire contract: the Edge still
only ever sees an opaque API key and a signed `Entitlement`, exactly as
below.

Either way, the Control Plane's secrets — the signing private key, and the
Postgres credentials if that backend is used — belong outside the
repository and outside the customer package.

The `.gitignore` therefore excludes local activation state, API keys, signed
entitlements, node secrets, private signing material, and generated
customer-specific bundles. The `.gitignore` itself should remain in production;
it is not necessary to remove it. Production deployment replaces the
 development issuer with the real Control Plane service and injects the
 corresponding public verification key/configuration.

## Enforcement at the orchestration layer

`ATLDataPlaneMVP(..., require_license=False)` (the plain constructor) is for
local dev/test wiring only — nothing stops it from running with no
entitlement at all. `ATLDataPlaneMVP.production(gate, data_plane,
entitlement, ...)` is the intended production entry point: it always sets
`require_license=True` and validates the entitlement (present, has
`agent_access`, node-bound to the same node as the data plane's crypto
context) **at construction time**, not lazily on the first request. A
misconfigured deployment should fail loudly at boot, not on whichever
request happens to arrive first.

## Security boundary

- API key: commercial activation credential.
- Signed entitlement: authorization/capability statement.
- Node identity/key: data-plane/Connector identity material.
- ATLP: authenticated encryption, TTL, node/context binding and replay controls.
- Transport (Edge → Connector): HMAC-signed push, keyed by a value *derived
  from* the node key (`derive_transport_key`) but distinct from it — never
  the raw ATLP key reused as a MAC key.
- Policy/Data Catalog: data authorization and classification.
- MORPH: structural/procedural validation; it is not the licensing authority.

A stolen API key must not by itself provide access to enterprise plaintext.
Likewise, copying a Connector bundle must not reveal the per-node secret,
and compromising the transport signing key must not reveal the ATLP AES key
(or vice versa) — they are cryptographically distinct by construction.
