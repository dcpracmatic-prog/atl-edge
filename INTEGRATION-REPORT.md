# ATL Edge Console Integration Report

**Date:** 16 Sep 2026, ~10:33 CST (America/Mexico_City)  
**Tree:** `/workspace/atl-edge-smarttoken-hardened`  
**Base:** GitHub zip `main` @ `2449905d9d4b4f6a168346da756cd92a85b0bf72`  
**Rule:** main crypto path preserved; proposal used as reference only.  
**Status:** Re-verified green (selftest + MVP + `wc -c data_plane.py`).

## What landed

Hardened operator console integrated **on top of** main:

| Path | Change |
|------|--------|
| `src/web_console.py` | **NEW** — Bearer auth; `ATLDataPlaneMVP.production()` via `EdgeRuntime`; no license issuance; loopback bind by default; rejects empty/default secrets; rejects destructive proposals; fields required; reuses Inbox/Outbox/ledger/`http_limits`/`provision_bundle` |
| `examples/web_console_selftest.py` | **NEW** — secure-behavior tests + fail-closed default runtime |
| `atlctl.py` | **ADDITIVE** — `atlctl console`; bootstrap/issue-license kept |
| `docker-compose.yml` | **ADDITIVE** — `web-console` under `profiles: ["console"]`, host `127.0.0.1:8795:8795` |
| `Dockerfile` | **ADDITIVE** — `EXPOSE 8795` |
| `.github/workflows/ci.yml` | **ADDITIVE** — `console-selftest` job |
| `docs/CONSOLE.md` | **NEW** — phases 0–7 + A1–A14 checklist |
| `docs/ATL-EDGE-AUDITORIA-INTEGRACION.md` | **NEW** — audit pack copy |
| `README.md` | **ADDITIVE** — three-process diagram + Firebase/Gemini anti-pattern |
| `src/control_plane_server.py` | **FIX** — moved misplaced import so `__future__` is first (pre-existing SyntaxError) |

### Untouched (golden rule)

| File | Bytes |
|------|-------|
| `src/data_plane.py` | **25014** (AES-GCM) |
| `src/proposal_gate.py` | 12869 |
| `src/mvp.py` | 9240 |
| `src/licensing.py` | 6484 |

No `server.ts` / Firestore / Gemini in the Edge runtime. No secrets committed. No git push.

## Tests run (this verification)

| Suite | Result |
|-------|--------|
| `examples/web_console_selftest.py` | **PASS** (401, no license endpoint, production execute, fields, destructive REJECT, secret reject, fail-closed default) |
| `examples/atl_mvp_selftest.py` | **PASS** |
| SmartToken availability | **True** (`pqcrypto` present) |
| `wc -c src/data_plane.py` | **25014** |
| PackageCrypto | AES-GCM path confirmed |
| Firebase/Gemini in Edge compose/runtime | **absent** |

Prior broader runs (same tree): `file_workflow_selftest`, `control_plane_selftest`, `long_lived_protection_selftest`, `scripts/validate_all.sh` (adversarial 14/14; redteam clean with RT1 known process-trust BYPASS only). Docker skipped (no docker binary on this box).

## Exact start commands

```bash
cd /workspace/atl-edge-smarttoken-hardened
. .venv/bin/activate   # or: python3 -m venv .venv && pip install -r requirements.txt && bash build.sh

PYTHONPATH=. python atlctl.py bootstrap-edge \
  --state .atl/control-plane --out-dir .atl/edge \
  --org acme --plan enterprise \
  --node-id edge-1 --instance-id inst-1 --agent-id agent-1 \
  --print-api-key --save-api-key

set -a && source .atl/edge/edge.env && set +a
export ATL_DATA_DIR=.atl/edge-data
export ATL_CONSOLE_TOKEN="$(openssl rand -hex 32)"

PYTHONPATH=vendor:. python -m src.edge_api_server --host 127.0.0.1 --port 8790 &
PYTHONPATH=vendor:. python atlctl.py console --host 127.0.0.1 --port 8795 --data-dir "$ATL_DATA_DIR" &
PYTHONPATH=vendor:. python -m src.sidecar_server --host 127.0.0.1 --port 8787 &
```

Docker (when available):

```bash
bash scripts/deploy_edge.sh --bootstrap-only
bash scripts/deploy_edge.sh --docker
docker compose --profile sidecar up -d sidecar
ATL_CONSOLE_TOKEN="$(openssl rand -hex 32)" docker compose --profile console up -d web-console
```

Compose note: host publish is `127.0.0.1:8795`; inside the container the process listens on `0.0.0.0` with `ATL_CONSOLE_BIND_PUBLIC=1` so port mapping works without exposing the host NIC.

## Leftover risks / operator must still do

1. **Revoke any PAT** pasted in chat; never commit `edge.env` / API keys.
2. **Do not deploy** AI Studio Firebase / `server.ts` against real data.
3. Console auth is a shared operator bearer — not SSO yet.
4. Non-loopback bind still needs operator TLS / network controls.
5. Replay cache remains in-process (trunk limit).
6. Docker image not built here (no `docker` on this box).
7. Working tree only — no commit/push performed.
8. Full A1–A14 lab tick still needs Edge+sidecar live + CI on a PR (see `docs/CONSOLE.md`).
