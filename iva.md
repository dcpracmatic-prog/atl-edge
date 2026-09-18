# IVA — Información de versión actual

Este documento describe el **estado operativo de la versión en `main`**: qué está implementado, qué se cerró en red-team/CI, y qué límites siguen siendo reales.

La **visión de producto** (qué es, qué resuelve, fundamentos, capacidades) está en **[README.md](README.md)**.

| | |
|--|--|
| **Línea** | ATL Edge SmartToken Hardened v2 |
| **SmartTokenProd** | 0.10.3, instalado desde `git+https://github.com/dcpracmatic-prog/Smart-Token-Prod.git@v0.10.4` (Argon2id + binding AES ↔ master_secret ↔ public_label + lock por inodo + DENIED opaco) |
| **Tronco** | https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened |
| **Licencia** | Elastic License 2.0 — [LICENSE](LICENSE), [NOTICE](NOTICE) |

---

ATL Data Plane is an on-prem data intermediary for premium/cloud agents: do repetitive work near the database, predigest the minimum useful data, seal it in a short-lived AES-GCM package bound to a node-derived key, and keep request telemetry on-prem.

The current MVP has one canonical path:

```text
Local Llama + Skills
        |
        v
Proposal Schema v1
        |
        v
MORPH-8 Structural Gate + Policy
   | ACCEPT/REPAIR | REJECT
   v               X
local execution    no side effect
        |
        v
local predigest
        |
        v
ATLP AES-256-GCM + TTL + node-derived key + anti-replay
        |
        v
premium-agent connector
```

The coherence layer remains complementary: primary telemetry, DSP regime signature, SWAR/AOM observation, AgentGuard shadow, and AdaptiveTrustLoop can detect disagreement between observed behavior and the declared proposal/state. They are not a replacement for authorization or the cryptographic data plane.

## What is connected now

- **Local proposer / constrained decoding** (`src/proposer.py`) — proposer constrains format; gate constrains semantics; catalog constrains fields: turns operator/agent text into a Proposal Schema v1 **dict** via outlines, xgrammar, or llama.cpp GBNF (optional deps), or a deterministic template. Missing grammar support fails closed or falls back to template — never unconstrained free-form LLM prose. Feeds `ProposalGate.check` / `ATLDataPlaneMVP.execute_and_issue`.
- **Proposal Schema v1** (`src/proposal_gate.py`): explicit executable contract with `tool`, `operation`, `arguments`, optional `action`, `resource`, `fields`, `limit`, `steps`, `effects`, and metadata. Unknown executable fields are rejected. Semantic policy also checks operation allowlists, destructive operations, argument size/dangerous keys, field/effect limits, and step operations.
- **MORPH-8** (`src/morph8.cpp`, `src/morph8.py`): **core** structural gate on the local agent's proposal before anything runs. Deterministic validation/repair with bounded parser, allowlisted tools, action policy, causal graph checks, and rejection of control/dangerous fields. This is the layer that evaluates what the on-prem Llama (or same-enterprise node) is allowed to *request* toward the premium/cloud path — not an optional side feature.
- **Hard execution barrier** (`ProposalGate` / `ATLDataPlaneMVP.execute_and_issue`): schema + MORPH + semantic policy must accept before the executor runs. A rejected proposal cannot reach side effects on the canonical MVP seam.
- **Field minimization / predigest** (`proposal.fields` + `predigest_records` in `src/data_plane.py`): projects records to the **requested field list** so the ATLP package carries the minimum useful columns, not full row dumps or unsolicited context. Optional catalog/`authorize_request` further enforces sensitivity and node allowlists.
- **Local Data Plane** (`src/data_plane.py`): predigest + metrics + on-prem JSONL audit + ATLP AES-256-GCM.
- **ATLP hardening**: HKDF-derived per-node key, TTL, generic `INERT` rejection, anti-replay, authentication-before-replay-cache ordering, authenticated policy/proposal fingerprints, and finite/consistent timestamp validation.
- **Premium connector**: decrypts only with the matching node-derived key and valid package metadata. Production `from_env()` accepts `ATL_NODE_KEY_HEX`, not the provisioning master key; `from_node_key()` is the preferred explicit constructor.
- **Coherence/observability** (`src/atl_core.py`, `src/integrations.py`): existing FieldMemory, DSP, telemetry, SWAR, AgentGuard shadow, SmartToken (LWE) and AdaptiveTrustLoop remain available as supporting control/observation components. They are not authorization gates.
- **Long-lived protection** (`src/long_lived_protection.py` + the installed `smart_token_prod` package): optional SmartTokenProd path (ML-KEM + master_secret-bound AES-GCM + persistent friction + `.stok`) for artifacts that outlive ATLP packages. See the dedicated section below.

Important: MORPH is now enforced at the **canonical MVP orchestrator seam** (`src/mvp.py`). It is not magically enforced against arbitrary code elsewhere in the repository. Production integration must route all side-effecting tool execution through `ATLDataPlaneMVP.execute_and_issue` or an equivalent mandatory gateway.


## Long-lived artifact protection (SmartTokenProd)

ATL Edge keeps two complementary cryptographic paths:

| Path | Mechanism | Intended use |
|------|-----------|--------------|
| **ATLP** (canonical) | AES-256-GCM + HKDF per-node key + TTL + anti-replay | Short-lived packages for the premium connector |
| **SmartTokenProd** (optional) | ML-KEM-768 + AES-256-GCM bound to `master_secret` + sequential friction + `.stok` | Long-lived files that leave the node or require human secret + out-of-band key |

SmartTokenProd is an **installed dependency** (no longer a copy under `vendor/`), pinned in `requirements.txt` to the tag `v0.10.3` of [Smart-Token-Prod](https://github.com/dcpracmatic-prog/Smart-Token-Prod). It is reached through `smart_token_prod.sdk` (re-exported by `smart_token_bridge.py`) and exposed through a thin functional API:

```python
from src.long_lived_protection import (
    is_available, status,
    protect_artifact, open_artifact, artifact_friction_status,
)

if is_available():
    stok, key = protect_artifact("model.onnx", master_secret=b"...")
    plaintext, info = open_artifact(stok, master_secret=b"...", key_path=key)
```

Properties enforced by the integrated stack (**SmartTokenProd v0.10.3**):

- The AES-GCM key is derived from **both** the ML-KEM shared secret **and** the human `master_secret`. Possession of the ML-KEM secret key (`sk`) alone is not sufficient to decrypt.
- Coherence verifiers (`salt` / `material`) in the `.stok` are derived with **Argon2id** (random `kdf_salt`; defaults `time_cost=2`, `memory_cost=64 MiB`, `parallelism=1`, recorded per artifact in `kdf_params`) so offline dictionary checks against the file pay a **memory-hard** work factor — measured ~113 ms per derivation on the validation host. Use a **high-entropy** `master_secret` (password-manager / random bytes); Argon2id does not make weak passwords safe.
- The ML-KEM secret key never travels inside the `.stok` file; it is written only to a sibling `.stok.key`.
- Failed opens advance a sequential friction state (warning → key mutation → CPU tarpit) stored inside the `.stok` and covered by a header HMAC keyed by `master_secret` (**file-local** persistence — not a distributed lock across workers).
- Friction slows **online** `open_*` attempts; it does **not** replace Argon2id for offline guessing against the `.stok` alone.
- The native friction core (`libfriction.so`) is optional; a pure-Python backend is used when the library is absent. Python and C++ backends match on friction state and `working_key` after the 2nd failure (mutation path) — genuinely so only since 0.10.4: before that an undefined shift in the C++ `fib(n)` encoder made the two diverge, and no test covered it (see `docs/THREAT_MODEL.md`, "Native friction parity"). `pqcrypto` is required for SmartTokenProd itself.
- If `pqcrypto` is not installed the module reports `is_available() == False` and raises a clear error; it never falls back to a weaker crypto path.
- **Format note (rechecked against 0.10.3):** there is no separate legacy verifier and no stored `kdf_salt` any more. Every open pays one Argon2id whose 16-byte salt is derived from `stok_id` (`sha256(stok_id || "|eq-argon2|v1")[:16]`), so even an old artifact gets a per-artifact salt and the old "weak offline" caveat no longer applies to the KDF. What *does* still differ: artifacts with `binding_version == 1` carry no `friction_mac`, so their friction snapshot is unauthenticated and `info["friction_mac_ok"]` comes back `None` instead of `True`. Re-protect those to get snapshot integrity.

Build the optional native friction core together with the rest of the natives:

```bash
./build.sh          # morph8 + swar_fleet + libfriction.so
python examples/long_lived_protection_selftest.py

# Adversarial battery / unified testbench (evidence-producing)
python testbench/run_testbench.py
python testbench/run_testbench.py --json testbench/last_report.json
```


## Proposal Schema v1

Minimal proposal:

```json
{
  "schema_version": 1,
  "tool": "lookup",
  "operation": "read",
  "arguments": {"status": "active"}
}
```

Multi-step proposal:

```json
{
  "schema_version": 1,
  "tool": "lookup",
  "operation": "read",
  "arguments": {},
  "steps": [
    {"id": "a", "tool": "lookup", "operation": "read", "depends_on": []},
    {"id": "b", "tool": "validate", "operation": "validate", "depends_on": ["a"]}
  ]
}
```

The current default policy allowlists `lookup`, `normalize`, `validate`, and `publish`; rejects destructive actions such as `delete`, `drop`, and `truncate`; and rejects `shell`, `exec`, and `command` fields.

## Security boundary

MORPH-8 is a structural/policy gate, not an IAM system. `health` is a deterministic structural score, not a probability. The current C++ JSON parser is bounded and deterministic, but it should be fuzz-tested before making security claims beyond the MVP. Argument authorization is deliberately fail-closed for a small set of executable/control keys; it is not a SQL parser or a general-purpose sandbox.

ATLP uses AES-256-GCM. The package key is derived per node with HKDF-SHA256. In production, the provisioning master should not live on cloud/premium instances; provision the appropriate node-specific key/material instead. `node_claim` is cryptographic node binding, not hardware attestation.

The on-prem audit log records issuance and reduction metrics and now uses a tamper-evident hash chain. This detects modification/reordering when the chain head is protected externally; it is not itself immutable/WORM storage. The package carries authenticated policy/proposal fingerprints plus metadata required by the protocol and the predigested payload.

## Build and tests

```bash
bash build.sh
PYTHONPATH=. python examples/morph_selftest.py
PYTHONPATH=. python examples/atl_mvp_selftest.py
PYTHONPATH=. python src/data_plane.py
```

The end-to-end test verifies all of these connections in one run:

1. valid Proposal Schema reaches MORPH;
2. MORPH accepts deterministically;
3. only an accepted proposal reaches the executor;
4. the same proposal is deterministic on repeat;
5. local records are predigested;
6. the result is sealed as ATLP;
7. the premium connector opens it;
8. a rejected destructive proposal never invokes the executor;
9. audit remains on-prem.

## Existing supporting modules

- `src/atl_core.py`: FieldMemory, DSP calibration, ObservationStack/SWAR fallback, legacy `DCPEngine`, AdaptiveTrustLoop.
- `src/integrations.py`: AgentGuard shadow, EO telemetry schema, SmartToken helpers, ClosedLoopSlim.
- `skills/field_engine`: graph/path planning utility; not the agent authorization gate.

The legacy `DCPEngine` remains for compatibility. The canonical data-plane implementation for this MVP is `src/data_plane.py` + `src/proposal_gate.py` + `src/mvp.py`.

## What ATL does not claim

- It is not a substitute for IAM, database authorization, endpoint security, or the premium agent's own controls.
- It does not promise invulnerability or universal leakage prevention.
- Token/byte reduction is measured from actual input traffic and is not a universal percentage.
- Node binding is not proof of hardware identity.
- SmartToken is governance/structural linkage in this package; it is not the ATLP encryption primitive.

## ATL consolidation: data classification, minimal results and Connector

The MVP now treats data classification as a first-class local control. Assets and
fields can be declared as `public`, `internal`, `confidential`, `sensitive` or
`restricted`. A deterministic detector can raise the effective classification
when labels are missing or too weak. **It never automatically downgrades data.**
The detector is intentionally conservative and is not a legal/compliance DLP engine.

Protection is tiered so not every request pays the same protocol cost:

- `PUBLIC` / `INTERNAL`: `FAST_LOCAL` path.
- `CONFIDENTIAL`: `ATLP_STANDARD`.
- `SENSITIVE`: `ATLP_FIELD_MINIMUM`.
- `RESTRICTED`: `ATLP_RESTRICTED`.

A node request is authorized against the asset/field classification before data is
issued. The response packager preserves request order and emits only the requested
fields. The transport envelope remains the ATLP security boundary.

### Connector

`connector/atl_connector.py` is the beginning of the customer-side deliverable: a
small executable/configuration surface intended to run in the external agent's
instance. `connector/atl-manifest.example.json` shows the one-time declaration of
organization, instance, node, agent, skills and policies. The production identity
must be provisioned cryptographically; manifest IDs alone are not credentials.

The connector does not receive the enterprise master key. Production ATLP opening
uses a provisioned per-node `ATL_NODE_KEY_HEX` in this MVP.

### Request flow

```text
external node/agent
        |
        v
ATL Connector -> identity + request
        |
        v
ATL Data Plane
  -> classify/reclassify
  -> authorize
  -> Llama + Skill
  -> MORPH
  -> local DB processing / predigest
  -> ordered minimal result
  -> ATLP (only when required by classification)
        |
        v
ATL Connector -> premium agent
```

The classification self-test is `PYTHONPATH=. python examples/classification_selftest.py`.

## Licensing and activation model

ATL is distributed as one installable Edge package. Installation alone does not grant production agent access. The Edge can start in `LOCKED` state and is activated with an annual ATL API key obtained from the customer account.

The API key is an activation/licensing credential, **not** the AES key used by ATLP. A production control plane exchanges the activation key for a signed `Entitlement`. The Edge verifies that entitlement locally and provisions a distinct `NodeIdentity` for each installation. The per-node secret is stored separately from the generated SDK/Connector code.

Conceptual lifecycle:

```text
Download ATL Edge
      -> Install beside database (physical/on-prem node)
      -> LOCKED
      -> atlctl request-license  (HTTP call to the Control Plane)
      -> atlctl activate         (verify signed Entitlement locally)
      -> Node identity provisioned
      -> Connector/SDK bundle generated
      -> Cloud Connector installed on the authorized agent's cloud instance
      -> DB -> Edge (predigest + seal) -> Outbox -> push -> Connector -> premium agent
```

`src/licensing.py` implements the primitives: opaque API-key generation, Ed25519-signed entitlements, local entitlement verification, node identity generation, and activation-safe fingerprints. The signing private key must remain in the ATL control plane and must never ship in the customer package.

`src/sdk_provisioner.py` generates a customer-specific Connector/SDK configuration bundle. It does not embed the node secret or ATL signing private key.

`atlctl.py` provides the local activation/status/provisioning CLI surface, including `request-license` (calls the Control Plane over HTTP) and `activate` (verifies the returned entitlement locally, fails closed on a bad signature).

The canonical commercial boundary is therefore **ATL API / annual entitlement**, while Edge, SDK and Connector remain the technical delivery components. Data-plane encryption and node binding remain separate from licensing.

## Control plane (reference implementation)

`src/control_plane.py` + `src/control_plane_server.py` are a real, runnable issuer — not a stub. `ControlPlane.issue_license(...)` mints a license and returns the opaque API key exactly once (only its SHA-256 fingerprint is persisted, same principle as a password hash). `ControlPlane.activate(...)` exchanges that key for a signed, node-bound `Entitlement` and enforces `max_nodes` per license. `ControlPlaneServer` exposes `POST /v1/activate` and `GET /v1/public-key` over HTTP; `atlctl request-license` is the customer-side client for that endpoint.

This is explicitly a *reference* issuer, not the final production service:
- Storage is SQLite (`control_plane.sqlite3`), not a single JSON file — specifically so the `max_nodes` check is a single atomic transaction (`BEGIN IMMEDIATE`) rather than a read-then-write race. `examples/control_plane_selftest.py` proves this with 20 real threads racing for one node slot: exactly one wins. A deployment fronting more than one control-plane process still needs a real server-grade database (Postgres, etc.); SQLite is the smallest thing that demonstrates the atomicity correctly.
- The Ed25519 signing key is persisted to a local `signing-key.pem` (0600). Production should hold it in a KMS/HSM, not a general-purpose filesystem.
- License *issuance* is not exposed over HTTP — only activation is. Minting a license is a back-office operation; this reference server has no admin-auth layer to gate an issuance endpoint safely, so `issue_license()` is meant to be called from an already-authenticated admin tool or billing webhook, not exposed directly.

`examples/control_plane_selftest.py` exercises issuance, HTTP activation, idempotent re-activation, `max_nodes` rejection, entitlement tamper detection, revocation, and the concurrent-activation race, end to end.

### Storage backend: SQLite (default) vs PostgreSQL

Storage is pluggable (`src/control_plane_storage.py`), and `ControlPlane`'s business logic doesn't know or care which backend it's talking to — the whole interface is one method, `register_node_atomic()`, since that's the only operation that actually needs atomicity (read the current node count for a license, then insert a new node only if there's room).

- `SQLiteBackend` (default, what `ControlPlane(state_dir)` uses with no extra arguments): zero external dependencies, one file on disk. Atomicity comes from `BEGIN IMMEDIATE`, which takes SQLite's single writer lock for the *entire database* up front — correct, but coarse: an activation for License A blocks an unrelated activation for License B for the duration of the transaction.
- `PostgresBackend` (`ControlPlane.with_postgres(state_dir, dsn)`, requires `pip install -r requirements-postgres.txt`): atomicity comes from `SELECT ... FOR UPDATE` on the *specific license row*, so concurrent activations against different licenses don't contend with each other at all.

`examples/control_plane_postgres_selftest.py` proves both halves of that claim against a real, running Postgres instance (skips cleanly, without failing the suite, if `ATL_TEST_POSTGRES_DSN` isn't reachable): a 30-thread race for the last slot on one license still produces exactly one winner; a raw connection holding a real `FOR UPDATE` on one license's row does not block an activation against a *different* license (completes in ~20ms); and, as a sanity check on the test itself, an activation against the *same* locked license does correctly wait for the lock to release.

## File workflow: where files actually live

Everything above this point moved `bytes` in memory between function calls — fine for a single process, but it never answered "where does a sealed package live between the moment the Edge issues it and the moment the Cloud Connector picks it up?" `src/file_workflow.py` answers that with two on-disk, discovery-friendly directories:

- **Inbox** (`inbox/<source>/<uuid>__<name>` + `.meta.json` sidecar) — raw input dropped for the Edge to predigest. Writes are write-to-temp + atomic `os.replace()`, so nothing ever reads a half-written file; the sidecar carries provenance (source, sha256, received_at) without opening the payload.
- **Outbox** (`outbox/<node_id>/<request_id>.atlp` + `.meta.json` sidecar) — sealed ATLP packages ready for the Cloud Connector. The sidecar (policy_id, expiry, size, sha256) is what a connector inspects to decide whether to fetch, and it **never contains key material or plaintext**. `list_ready()` skips and sweeps anything already past `expiry` rather than handing out a package that would just come back `INERT`.

Both directories guard against path traversal on caller-supplied identifiers (`node_id`, `request_id`, `source` are all collapsed to a single path segment before touching disk) — see the traversal-guard case in `examples/file_workflow_selftest.py`.

This is intentionally **not** a distributed queue: it's one Edge process writing to local disk that it owns. Getting a package from that Outbox to a Cloud Connector on a different host is `src/transport.py`'s job, described next.

## Authenticated transport: Edge → Cloud Connector

The previous MVP passed `bytes` directly between a `LocalDataPlane` and a `CloudDecryptConnector` in the same process — there was no answer for "who's allowed to feed the Connector packages over a real network?" `src/transport.py` + `connector/cloud_runtime.py` close that gap with a small, real (not mocked) authenticated channel:

- **Direction**: the Edge dials **out** (`push_ready()`, HTTP POST) to the Connector's ingest endpoint. This matches how enterprise networks are usually run — outbound HTTPS from on-prem is commonly allowed, inbound to on-prem commonly is not — so the Connector, which lives in the cloud next to the premium agent, is the side with a stable, reachable address.
- **Signing**: every push is HMAC-SHA256-signed over `method, path, timestamp, nonce, sha256(body)` using a key derived from — but distinct from — the node's ATLP key (`data_plane.derive_transport_key`, HKDF with a different `info` label). Reusing one raw secret as both an AEAD key and a MAC key is a key-reuse smell; this avoids it for the cost of one HKDF call.
- **Two independent replay checks**: the transport layer rejects a replayed `(timestamp, nonce)` within a 300s window (`NonceCache`) *before* the package is even opened; ATLP's own `request_id` replay cache (`ReplayCache`) then independently rejects a replayed package payload. Neither layer trusts the other to have already caught it.
- **No oracle**: both a bad transport signature and a bad ATLP payload return generic status codes (`401` / `422`) with no detail — mirrors ATLP's own `INERT`-only contract so a network attacker gets nothing to enumerate against.
- **Connector responsibilities, and nothing else**: `ConnectorIngestServer` verifies transport auth, opens the ATLP package with its own per-node key (never the provisioning master key), and hands the decrypted, already-predigested payload to a deployment-supplied agent handler. It never persists plaintext to disk.

`examples/transport_selftest.py` runs this over real loopback HTTP: happy-path delivery, a forged-signature request rejected with `401` and never reaching the agent handler, and a byte-for-byte replay of a validly-signed request rejected on its second delivery.

### TLS

Both HTTP surfaces (`ControlPlaneServer`, `ConnectorIngestServer`) accept `tls_certfile`/`tls_keyfile` and wrap their listening socket with a real `ssl.SSLContext` (`src/dev_tls.py`) — this is not optional middleware bolted on later, it's the same server class either way. `src/dev_tls.generate_self_signed_cert()` produces a throwaway dev/test certificate (with a `127.0.0.1` SAN, since that's what the selftests connect to) so the TLS code path itself is exercised by `examples/tls_selftest.py`, not left as untested code that only runs against a production cert nobody can hand this repo. That selftest checks: plaintext HTTP against a TLS-only server fails outright; a client with no matching CA is rejected by the default trust store; a client that explicitly trusts the dev cert succeeds and still verifies; and `client_context(insecure_skip_verify=True)` refuses to run without a second, separate `allow_insecure=True` — a deliberate two-flag guard so a stray config value can't silently turn off certificate verification.

Production points `tls_certfile`/`tls_keyfile` at a certificate from a real CA/internal PKI (most commonly terminated at a reverse proxy in front of these servers instead) and calls `client_context(ca_path=...)` — or nothing at all, since `urllib`'s system default verification is correct against a real cert — instead of `generate_self_signed_cert()`.

### Retry scheduler

`push_ready()` is a single, stateless sweep — call it and it pushes whatever is ready, once. `RetryScheduler` (also in `src/transport.py`) wraps that with the memory a real deployment needs: per-entry exponential backoff with jitter, persisted to `<outbox>/<node_id>/_retry_state.json` so a restarted process doesn't forget how many times an entry has already failed, and dead-lettering (never silently dropping) anything that exceeds `max_attempts` — the package and a reason are preserved under `outbox-dead-letter/` for operator inspection. Like `push_ready()`, `RetryScheduler.run_once()` is a single pass meant to be invoked by whatever scheduler the deployment already runs (systemd timer, cron, a supervised loop); it does not spawn its own background thread. `examples/retry_scheduler_selftest.py` exercises persistence-across-instances and the full failure-to-dead-letter path against an unreachable port.

**Still explicitly out of scope for this MVP**: horizontal scaling of the Connector, and structured/centralized access logging — both are conventional ops concerns that sit on top of, not inside, the authentication and delivery logic above.

## End to end

`examples/e2e_full_stack_selftest.py` wires every piece above together in one run: issue a license → activate it over real HTTP against `ControlPlaneServer` → build `ATLDataPlaneMVP.production()` with the resulting entitlement (fails closed at construction if the entitlement is missing, wrong-capability, or wrong-node) → execute a gated proposal and seal a package → deposit it in the Edge's `Outbox` → `push_ready()` it over authenticated HTTP → `ConnectorIngestServer` (standing in for the process running on the premium agent's cloud instance) verifies, decrypts, and hands the predigested payload to a mock agent handler. That is the actual product, not a diagram of it.

## Sprint de endurecimiento (Hardened v2)

Entregables orientados a due diligence:

| Entregable | Ruta |
|------------|------|
| Batería adversarial 14/14 en verde | `python testbench/run_testbench.py --require-full` |
| Docker multi-etapa + compose | `Dockerfile`, `docker-compose.yml` |
| Sidecar HTTP local | `python -m src.sidecar_server` |
| Dossier de rendimiento | `testbench/perf_report.md` |
| Modelo de amenazas | `docs/THREAT_MODEL.md` |
| Quickstart | `docs/QUICKSTART.md` |

```bash
# Validación completa en host
pip install -r requirements.txt
bash build.sh
PYTHONPATH=. python testbench/run_testbench.py --require-full
PYTHONPATH=. python testbench/perf_dossier.py

# O vía Docker
docker compose up --build -d
docker compose run --rm testbench
```

## CI/CD

Pipelines en `.github/workflows/`:

| Pipeline | Disparador | Qué garantiza |
|----------|------------|---------------|
| `CI` | push / PR | Adversarial 14/14, unit tests, Red-Team, sanitizers, Docker, sidecar |
| `Release` | tag `v*` | ZIP fuente + data room + checksums en GitHub Release |
| `Nightly` | cron | Validación diaria |

Documentación: [`docs/CI_CD.md`](docs/CI_CD.md).

```bash
# Equivalente local al job validate
bash scripts/validate_all.sh
```

## Verificación de workflows (CI)

El repositorio incluye tres workflows en `.github/workflows/`:

| Workflow | Archivo | Qué valida |
|----------|---------|------------|
| **CI** | `ci.yml` | Batería adversarial SmartTokenProd, unit tests, sanitizers nativos, análisis estático, Docker, sidecar, **Red-Team bypass v1** |
| **Release** | `release.yml` | Empaquetado de fuentes + data room en tags `v*` |
| **Nightly** | `nightly.yml` | Validación completa diaria |

### Criterio de verde del CI

1. `testbench/run_testbench.py --require-full` → adversarial SmartTokenProd 14/14, 0 SKIP  
2. `smart-token doctor` → dependencias y núcleo nativo en verde (la suite unitaria vive ahora en el repo del paquete)  
3. `testbench/redteam_bypass_v1.py --require-clean` → sin bypass desconocidos (RT0–RT18)  
4. Imagen Docker construible y testbench dentro del contenedor  
5. Sidecar SmartTokenProd `/health` responde  
6. Sin binarios `.so` precompilados en el árbol  

### Red-Team (frontera de ejecución + HTTP)

```bash
bash build.sh
PYTHONPATH=. python testbench/redteam_bypass_v1.py --require-clean
```

Produce `testbench/redteam_matrix.md` y `testbench/redteam_report.json`.

Propiedad bajo prueba (seam MVP):

```
¬Authorized(proposal)  ⇒  ¬Effect ∧ ¬Issue
Issue                  ⇒  Authorized ∧ Classified ∧ Licensed ∧ Bound
```

Hallazgos de frontera documentados en el harness:

| ID | Tema | Estado |
|----|------|--------|
| RT1 | `LocalDataPlane.issue_for_agent` in-process sin gate | **Confianza de proceso** (no cerrable en el mismo proceso) |
| RT16 | Edge API sin rutas a `issue_for_agent` / `data_plane` | **Cerrado** en HTTP |
| RT17 | `Content-Length` mentiroso | **Cerrado** (`http_limits`, rechazo 413) |
| RT18 | Goteo lento del body | **Cerrado** (deadline absoluto de lectura) |

## Edge API (punto único de ejecución)

Servidor HTTP que envuelve **solo** `ATLDataPlaneMVP` — no expone `LocalDataPlane` ni `issue_for_agent`:

```bash
PYTHONPATH=. python -m src.edge_api_server --host 127.0.0.1 --port 8790
# POST /v1/execute  { "proposal": {...}, "records": [...], "fields": [...] }
```

Rutas permitidas: `/health`, `/v1/capabilities`, `/v1/execute`.  
Límites HTTP (`src/http_limits.py`): cuerpo máx. 1 MiB, timeout de socket, **deadline absoluto** de lectura del body (anti slow-drip).  
Verificación: **RT16–RT18** en `testbench/redteam_bypass_v1.py`.

## Capacidades centrales vs límites de esta versión

### Qué hace el camino canónico (incluido y operativo)

| Capa | Rol real |
|------|----------|
| **Proposal Schema v1** | Contrato ejecutable del agente local (`tool`, `operation`, `fields`, `limit`, …). |
| **MORPH-8 + policy** | Evalúa la **propuesta** del Llama / agente on-prem: estructura, herramientas permitidas, acciones, grafo causal; **REJECT** si trae controles o tools peligrosas. Puerta previa a cualquier efecto. |
| **Data auth** | Catálogo + política de nodo en el Edge API / `production()`: ¿puede pedir esos campos / `resource`? |
| **Predigest** | Proyecta filas a `fields` → paquete con la **información mínima útil**. Tope operativo **`max_records=20`** por paquete ATLP. |
| **ATLP** | Cifra el predigest (AES-GCM, TTL, anti-replay local, clave de nodo). |
| **Edge API** | Único HTTP al MVP; allowlist de rutas; body acotado + deadline; **tope de concurrencia** (503 si se excede). |
| **SmartTokenProd v0.10.3** | Archivos de larga duración: ML-KEM + AES ligado a `master_secret` y al `public_label` + **Argon2id** + fricción con `friction_mac` + lock por inodo. |

**Nota:** MORPH valida la *petición*; la minimización de columnas es `fields` + `predigest_records`. En **`ATLDataPlaneMVP.production()`** y en el Edge API, **`fields` es obligatorio** (fail-closed).

### Cerrado en esta línea (no son “límites abiertos”)

| Tema | Estado |
|------|--------|
| AES solo con `sk` sin `master_secret` | Cerrado (binding) |
| Diccionario offline barato en `.stok` **nuevos** | Cerrado (Argon2id memory-hard + `kdf_salt`, v0.10.3) |
| HTTP expone `issue_for_agent` / data plane | Cerrado (RT16) |
| Content-Length mentiroso / silencio | Cerrado (RT17) |
| Goteo lento del body | Cerrado (RT18) |
| Predigest ignoraba `proposal.fields` | Cerrado (mismo contrato que auth) |
| Paridad mutación de clave Python↔C++ | Cerrado (2.º fallo + shifts definidos) |

### Límites que siguen siendo reales

| Área | Límite honesto |
|------|----------------|
| Despliegue | On-prem / edge MVP — **no** gateway multi-tenant ni service mesh. |
| Confianza de proceso (RT1) | Mismo proceso + `LocalDataPlane` puede sellar; la frontera de **red** es el Edge API. |
| Predigest | Sin `fields` solo en modo dev (`require_fields=False`). Producción/Edge **exigen** `fields`. Tope **20 filas**/paquete. |
| ATLP anti-replay | Caché **in-memory** por proceso (no Redis/DB distribuido). |
| SmartTokenProd | Fricción **file-local**; requiere `pqcrypto`; `.stok` con `binding_version == 1` no traen `friction_mac`, así que su snapshot de fricción no está autenticado (re-proteja para obtenerlo); HSM/KMS es stub de integración. |
| HTTP | Body + deadline + **máx. 32 handlers concurrentes**; aún sin anti-slowloris de **headers** ni cuota por IP avanzada. |
| MORPH | Gate estructural/policy — **no** IAM de usuarios ni parser SQL completo; fuzz del parser C++ recomendado antes de claims más fuertes. |
| Ops / negocio | Redis multi-instancia de fricción, HSM real, acuerdo comercial más allá de ELv2, auditoría externa: decisión del integrador. |
| Side-channels | Constant-time / anti-timing: fuera de alcance. |

Detalle de amenazas: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) y [`data_room/THREAT_MODEL.md`](data_room/THREAT_MODEL.md).

---

**Ver también:** visión de producto en [README.md](README.md).

---

## Hardening v2.1 (implementado)

| Propiedad | Implementación |
|-----------|----------------|
| Idempotencia durable de `request_id` | `src/execution_ledger.py` (SQLite); estados `reserved` → `executed_unissued` → `completed`; reinicio no re-ejecuta el executor |
| `max_agents` | Tabla `license_agents` + `register_agent_atomic` (SQLite/Postgres); `ControlPlane.activate` aplica el cupo |
| Expiración de entitlement en runtime | `_check_license()` valida `issued_at` / `expires_at` en construcción y en cada `execute_and_issue` |
| Caches thread-safe | `ReplayCache`, `NonceCache`, `OnPremAuditLog.append` con `threading.Lock` |
| Edge API fail-closed | Sin `ATL_MASTER_KEY_HEX` (y sin `ATL_ALLOW_DEV_DEFAULTS=1`) el arranque **falla**; no hay crypto/dev silenciosa |

Pruebas: `examples/hardening_v21_selftest.py`.

## Licenciamiento operativo (tokens)

| Comando | Función |
|---------|---------|
| `atlctl issue-license` | Emite licencia + API key (una vez) en state local del control plane |
| `atlctl activate-local` | API key → entitlement firmado (respeta max_nodes / max_agents) |
| `atlctl bootstrap-edge` | Issue + activate + `edge.env` + master key |
| `atlctl write-edge-env` | Solo genera `edge.env` desde entitlement ya firmado |
| `atlctl request-license` | Activación contra control plane HTTP(S) |

Variables Edge: `ATL_ENTITLEMENT_PATH`, `ATL_CONTROL_PLANE_PUBLIC_KEY_PATH`, `ATL_MASTER_KEY_HEX`, …  
Sin ellas y sin `ATL_ALLOW_DEV_DEFAULTS=1`, el Edge **no arranca**.

## Despliegue Edge automatizado

| Comando | Efecto |
|---------|--------|
| `bash scripts/deploy_edge.sh` | Bootstrap tokens si no hay `edge.env` + build + Edge API en host |
| `bash scripts/deploy_edge.sh --docker` | `docker compose up -d edge-api` con secretos montados |
| `bash scripts/deploy_edge.sh --bootstrap-only` | Solo licencia + entitlement + `edge.env` |
| `bash scripts/deploy_edge.sh --status` | Node/license + health HTTP |

Entrypoint contenedor: `scripts/docker-entrypoint-edge.sh` (exige master key o secrets montados en `/secrets`).
