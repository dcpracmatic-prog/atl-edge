# ATL Edge Operator Console — deploy & audit flow

This console is an **additive** operator surface on top of hardened `main`.
It does **not** replace Edge API crypto, and it does **not** issue licenses.

```text
[Operator + ATL_CONSOLE_TOKEN]
            │
            ▼
   Console :8795 (loopback)
            │  execute / status / outbox / artifacts
            ▼
   Edge crypto path via ATLDataPlaneMVP.production()
            │
   Outbox + ledger under ATL_DATA_DIR
            │
            ├─ Edge API :8790 (network execute boundary)
            └─ Sidecar :8787 (SmartTokenProd long-lived artifacts)
```

**Anti-pattern:** do not put Firebase / Gemini / `server.ts` on the data-plane.
Metadatos SaaS (if any) stay off the node that seals ATLP packages.

Full consolidation notes: [`docs/ATL-EDGE-AUDITORIA-INTEGRACION.md`](ATL-EDGE-AUDITORIA-INTEGRACION.md).

---

## Operator token & bind

```bash
export ATL_CONSOLE_TOKEN="$(openssl rand -hex 32)"   # rotate; never commit
# Default bind is 127.0.0.1
# Public bind only with explicit flag + TLS reverse proxy:
#   export ATL_CONSOLE_BIND_PUBLIC=1
```

Authorization: every route except `GET /health` requires:

```http
Authorization: Bearer <ATL_CONSOLE_TOKEN>
```

Missing/wrong token → **401**.  
`POST /api/environments/license` → **404** (use `atlctl issue-license` / control plane).

---

## Phases 0–7 (lab audit stack)

Adapt paths to this tree. Do **not** paste PATs into chat.

### Fase 0 — Preflight

```bash
cd atl-edge-smarttoken-hardened
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# optional for SmartTokenProd:
pip install pqcrypto || true
bash build.sh
wc -c src/data_plane.py   # expect ~25014 (AES-GCM), NOT ~2810
```

### Fase 1 — Trunk validation (before trusting the console)

```bash
bash scripts/validate_all.sh
PYTHONPATH=. python testbench/run_testbench.py --require-full
PYTHONPATH=. python testbench/redteam_bypass_v1.py --require-clean
PYTHONPATH=. python examples/e2e_full_stack_selftest.py
PYTHONPATH=. python examples/web_console_selftest.py
```

If trunk tests are red, **stop** — do not deploy the console.

### Fase 2 — Control plane + Edge tokens

```bash
PYTHONPATH=. python atlctl.py bootstrap-edge   --state .atl/control-plane   --out-dir .atl/edge   --org acme --plan enterprise   --node-id edge-1 --instance-id inst-1 --agent-id agent-1   --print-api-key --save-api-key

unset ATL_ALLOW_DEV_DEFAULTS
# Without edge.env / master key, Edge must refuse to start (fail-closed).
```

### Fase 3 — Edge + sidecar

```bash
# Host
bash scripts/deploy_edge.sh
bash scripts/deploy_edge.sh --status

# Docker
bash scripts/deploy_edge.sh --bootstrap-only
bash scripts/deploy_edge.sh --docker
docker compose --profile sidecar up -d sidecar
```

Criteria: `GET :8790/health` → 200. Execute without body / fields does not seal.

### Fase 4 — Console

```bash
export ATL_CONSOLE_TOKEN="$(openssl rand -hex 32)"
set -a && source .atl/edge/edge.env && set +a
export ATL_DATA_DIR=.atl/edge-data
export ATL_EDGE_DIR=.atl/edge

# Host
PYTHONPATH=. python -m src.web_console --host 127.0.0.1 --port 8795 --data-dir "$ATL_DATA_DIR"
# or
PYTHONPATH=. python atlctl.py console --host 127.0.0.1 --port 8795 --data-dir "$ATL_DATA_DIR"

# Docker profile
ATL_CONSOLE_TOKEN="$ATL_CONSOLE_TOKEN" docker compose --profile console up -d web-console
```

Criteria:

| Check | Expected |
|-------|----------|
| No `Authorization` | 401 (except `/health`) |
| `POST /api/environments/license` | 404/405 |
| Destructive `delete`/`shell` proposal | REJECT, no package |
| Execute without `fields` | 400 / fail-closed |
| Protect/open empty or `default-secret` | 400 |
| Ledger/outbox | under shared `ATL_DATA_DIR` |

### Fase 5 — Cloud connector (lab)

```bash
PYTHONPATH=. python connector/cloud_runtime.py
```

Criteria: valid HMAC push delivers predigest; bad signature → 401; connector has **no** `ATL_MASTER_KEY_HEX`.

### Fase 6 — Long-lived artifacts

```bash
PYTHONPATH=. python -c "from src.long_lived_protection import status; print(status())"
# Protect via console POST /api/artifacts/protect or sidecar :8787
```

Criteria: `is_available()==True` only with `pqcrypto`. Wrong secret advances friction. No AES-without-secret mode.

### Fase 7 — Evidence pack

```bash
docker compose run --rm testbench
PYTHONPATH=. python testbench/perf_dossier.py
# Collect: data_room/ + redteam_report.json + last_report.json
#          + docs/ATL-EDGE-AUDITORIA-INTEGRACION.md
#          + health logs for edge / console / sidecar
```

---

## A1–A14 go / no-go checklist

Copy-paste and tick after a lab run:

| ID | Property | How | Go |
|----|----------|-----|----|
| A1 | ¬Authorized(proposal) ⇒ ¬Effect ∧ ¬Issue | redteam `--require-clean` + execute via Edge and console | |
| A2 | Issue ⇒ Authorized ∧ Classified ∧ Licensed ∧ Bound | e2e + console against `production()` | |
| A3 | Edge HTTP does not expose `issue_for_agent` | RT16 | |
| A4 | Console does not issue licenses | 404 on `/api/environments/license` | |
| A5 | Console authenticated | 401 without token; 200 with token | |
| A6 | Console loopback by default | bind `127.0.0.1`; `0.0.0.0` only with `ATL_CONSOLE_BIND_PUBLIC=1` | |
| A7 | ATLP still AES-GCM (not HMAC-JSON) | `wc -c src/data_plane.py` ≥ 20k + PackageCrypto tests | |
| A8 | `fields` required in prod | execute without fields errors | |
| A9 | SmartToken binding + Argon2id | testbench 14/14 (needs pqcrypto) | |
| A10 | Fail-closed without master | Edge start without env dies | |
| A11 | Connector without provisioning master | inspect bundle + env | |
| A12 | Firestore/Gemini absent from data-plane | no GCP creds in Edge/console compose | |
| A13 | CI green including console job | Actions CI + `console-selftest` | |
| A14 | Proposal stubs not on `main` | `wc -c src/data_plane.py` ≈ 25014 | |

---

## Exact start commands (three processes)

```bash
# 1) Bootstrap once
PYTHONPATH=. python atlctl.py bootstrap-edge --out-dir .atl/edge --print-api-key --save-api-key
set -a && source .atl/edge/edge.env && set +a
export ATL_DATA_DIR=.atl/edge-data
export ATL_CONSOLE_TOKEN="$(openssl rand -hex 32)"

# 2) Edge API :8790
PYTHONPATH=. python -m src.edge_api_server --host 127.0.0.1 --port 8790 &

# 3) Operator console :8795
PYTHONPATH=. python atlctl.py console --host 127.0.0.1 --port 8795 --data-dir "$ATL_DATA_DIR" &

# 4) Sidecar :8787 (optional; needs pqcrypto)
PYTHONPATH=. python -m src.sidecar_server --host 127.0.0.1 --port 8787 &
```

Or with Compose:

```bash
bash scripts/deploy_edge.sh --bootstrap-only
bash scripts/deploy_edge.sh --docker
docker compose --profile sidecar up -d sidecar
ATL_CONSOLE_TOKEN="$(openssl rand -hex 32)" docker compose --profile console up -d web-console
```
