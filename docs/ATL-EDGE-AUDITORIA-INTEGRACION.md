# ATL Edge + SmartTokenProd — auditoría, mercado e integración

**Fecha:** 16 sep 2026, ~09:50 (America/Mexico_City)  
**Repo:** https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened  
**Línea auditada:** `main` @ `2449905d9d4b4f6a168346da756cd92a85b0bf72` (feat: deploy Edge bootstrap + host/docker)  
**Rama paralela:** `hardening-update` @ `c8413cd48eb15a54b3d0e555ba5147b3fe23cc00` (no mergear a ciegas)  
**Propuesta adjunta:** ATL Edge Management Console (Gemini AI Studio + Firebase + parches Python)  
**Verificado en vivo** vía conector GitHub (`dcpracmatic-prog`): tamaños de `src/data_plane.py` (25014), `proposal_gate.py` (12869), `mvp.py` (9240), `licensing.py` (6484), `atlctl.py` (18269). `web_console.py` **no existe** en `main`. Zip: 2810 / 1739 / 2666 / 914 / 2538 / **34615** (consola).

Este documento es la **versión consolidada** para integrar, desplegar y re-auditar. No es un dump del zip sobre `main`.

---

## 1. Veredicto

| Dimensión | Nota | Lectura |
|-----------|------|---------|
| Data-plane / crypto (código en `main`) | **Fuerte (MVP)** | Camino canónico real: schema → MORPH-8 → policy → auth → predigest → ATLP AES-256-GCM → conector. Límites documentados con honestidad en `iva.md`. |
| Producto vendible vs mercado | **Incompleto** | Falta consola de operador, identidad de usuario, MCP nativo, attestation de hardware, vault de campos y multi-nodo. |
| Propuesta de consola (zip) | **Dirección correcta, merge peligroso** | El UI y `web_console.py` son el siguiente producto. Los `.py` homónimos del zip **regresionan** el endurecimiento. |
| Listo para auditoría externa post-integración | **No todavía** | Integrar consola *encima* de `main`, sin pisar crypto, con auth y sin Firestore en el data-plane. Luego re-auditar. |

**Regla de oro:** `main` es la fuente de verdad criptográfica. Del zip se toma **solo lo aditivo** (`src/web_console.py`, UI, `atlctl console`, tests de consola). Se **descartan** los stubs de `data_plane.py`, `proposal_gate.py`, `mvp.py`, `licensing.py`, `atlctl.py` y el `docker-compose.yml` de un solo servicio.

---

## 2. Estado del repositorio (`main`)

### 2.1 Qué hay (operativo)

Camino canónico documentado y cableado:

```text
Agente local (Llama / skills)
        │  propuesta (tool, operation, fields, …)
        ▼
Proposal Schema v1          src/proposal_gate.py
        ▼
MORPH-8 + policy            src/morph8.py / morph8.cpp
   ACCEPT / REPAIR | REJECT
        ▼
Auth de catálogo/nodo       src/data_catalog.py
        ▼
Executor (solo lo aceptado) src/mvp.py
        ▼
Predigest (fields + tope)   src/data_plane.py   max_records=20
        ▼
ATLP AES-256-GCM            TTL, anti-replay, clave de nodo (HKDF)
        ▼
Outbox + push HMAC          src/file_workflow.py, src/transport.py
        ▼
Cloud Connector             connector/
```

Piezas de producto ya presentes:

- **Edge API** (`src/edge_api_server.py`): único HTTP de ejecución (`/health`, `/v1/capabilities`, `/v1/execute`). RT16–RT18 cerrados (no expone `issue_for_agent`; body + deadline).
- **Licenciamiento** (`atlctl.py`, `src/control_plane.py`): API key de un solo uso, entitlement Ed25519, `max_nodes` / `max_agents` atómicos (SQLite o Postgres).
- **Despliegue** (`scripts/deploy_edge.sh`): un comando host o `--docker`; contenedor fail-closed (`docker-entrypoint-edge.sh`).
- **SmartTokenProd 0.10.2**: ML-KEM-768 + AES ligado a `master_secret` + Argon2id (64 MiB, t=2) + fricción. `pqcrypto` obligatorio; no hay fallback débil.
- **CI**: `ci.yml` / `nightly.yml` / `release.yml` (adversarial, unit, red-team, sanitizers, Docker, sidecar).
- **Licencia comercial:** Elastic License 2.0.

### 2.2 Tamaños que importan (no pisar)

| Archivo | `main` | Zip propuesta | Si se copia el zip |
|---------|--------|---------------|--------------------|
| `src/data_plane.py` | 25 014 B, AES-GCM + HKDF + replay | 2 810 B, **HMAC-SHA256 sobre JSON** | **Regresión criptográfica** |
| `src/proposal_gate.py` | 12 869 B | 1 739 B | Pierde policy |
| `src/mvp.py` | 9 240 B | 2 666 B | Pierde production fail-closed |
| `src/licensing.py` | 6 484 B | 914 B | Pierde Ed25519 |
| `atlctl.py` | 18 269 B (`bootstrap-edge`, `issue-license`, …) | 2 538 B (`status`/`license`/`console`) | Pierde el CLI de producción |
| `src/web_console.py` | **no existe** | 34 615 B | **Única pieza aditiva real** |
| `docker-compose.yml` | edge-api :8790 + sidecar + testbench | solo `web-console` :8795 | Pierde el Edge |

### 2.3 Límites reales (de `iva.md`, no marketing)

- Confianza de **proceso** (RT1): mismo proceso + `LocalDataPlane` puede sellar. La frontera de **red** es el Edge API.
- Anti-replay ATLP: caché **in-memory** por proceso.
- Predigest: 20 filas/paquete; `fields` obligatorio en producción.
- HTTP: máx. 32 handlers; sin cuota por IP avanzada ni anti-slowloris de headers.
- MORPH: gate estructural, no IAM ni parser SQL; parser C++ sin fuzz público.
- SmartToken: fricción file-local; `.stok` pre-0.4.5 débiles offline; HSM es stub.
- Control plane de referencia: SQLite (o Postgres); clave Ed25519 en fichero, no KMS.
- `node_claim` no es attestation de hardware.
- Auditoría JSONL con hash-chain: detecta tamper si el head está protegido fuera; no es WORM.

### 2.4 Rama `hardening-update`

Línea divergente: README más largo, `src/external_share.py` (no está en `main`), **no** tiene `execution_ledger.py` ni `iva.md`. `docker-compose` y `edge_api_server` difieren. Tratarla como experimento; **integrar contra `main`**, no contra esta rama, salvo cherry-picks revisados uno a uno.

---

## 3. Posición de mercado

ATL no es un LLM gateway ni un vault de pagos. Compite en la **intersección**: borde on-prem entre un agente local y un agente/conector premium, con minimización + sello de vida corta + protección PQ de artefactos.

### 3.1 Mapa de rivales (2026)

| Familia | Ejemplos | Qué hacen bien | Dónde ATL se diferencia | Dónde ATL pierde hoy |
|---------|----------|----------------|-------------------------|----------------------|
| Privacy vault / tokenización | Skyflow for Agents (MCP Gateway/SDK), VGS + Amazon Bedrock AgentCore | Tokenizan PII/PCI **antes** del modelo; rehidratación por política; gateway MCP de campo; VGS proxy inline en tools | ATL **no saca** el dato a un vault cloud: predigerir y sellar **en el nodo**; paquete ATLP de vida corta | Sin vault de campos, sin tokens polimórficos, sin plugin de API gateway ni MCP nativo |
| Confidential computing | OPAQUE 3.0 Confidential MCP (jun 2026), cMCP / TRACE (AgenTrust) | Policy en TEE (Intel/AMD/NVIDIA), attestation, recibo firmado verificable por un tercero | ATL es software + crypto, desplegable sin silicio especial, coste de entrada bajo | Sin TEE / SEV-SNP / TDX; `node_claim` no es attestation; due diligence regulada favorece OPAQUE |
| LLM gateway | LiteLLM, Portkey | Routing, presupuesto, SSO, guardrails, air-gap | ATL no enruta modelos: autoriza **propuestas de trabajo** y empaqueta **filas** | Sin SSO, sin chargeback, sin catálogo de 100+ providers |
| Prompt / agent security | Lakera, Protect AI, Prompt Security | Inyección, PII en prompts, runtime screening | MORPH-8 es contrato estructural (tools/acciones/grafo), no clasificador ML | Sin detector de inyección estadístico; no cubre el texto libre del LLM |
| Data access / DLP | Immuta, Privacera | ABAC sobre warehouses y RAG | ATL vive junto al agente, no en Snowflake/Databricks | Sin cobertura de lakehouse ni índices RAG |
| Secret / file | Vault, age, KMS | Secretos de infra | SmartTokenProd: PQ + secreto humano + fricción en **artefactos** | Fricción local, no HSM real |

### 3.2 Wedge comercial (mantenerlo nítido)

> “El trabajo pesado se queda junto a tus datos. Hacia el agente premium solo sale el mínimo útil, sellado, con TTL y reglas que el propio Llama no puede saltarse.”

Eso **no** lo cubre LiteLLM (enruta el prompt entero). **No** lo cubre Lakera (mira el texto, no el executor). Skyflow for Agents (2026) es el rival más cercano: MCP Gateway + tokenización de campo + rehidratación, pero el dato vive en su vault SaaS. VGS hace lo mismo como proxy PCI delante de AgentCore. OPAQUE 3.0 (Confidential MCP, 23 jun 2026) gana en evidencia hardware verificable; ATL gana en “cabe en un Docker al lado de la DB, Elastic License, sin TEE”.

### 3.3 Gaps que un comprador enterprise va a marcar

1. Consola de operador (el zip intenta esto).
2. Identidad de usuario / SSO en la consola y en el Edge.
3. Replay durable (Redis/DB), no solo memoria.
4. Attestation o al menos TPM/`node_claim` verificable por un tercero.
5. MCP nativo (Skyflow MCP Gateway y OPAQUE Confidential MCP ya venden eso; ATL habla “proposal schema”).
6. Historia de auditoría exportable a SIEM.
7. Multi-nodo y HA del Edge.
8. Certificaciones (SOC2, ISO 27001) y pentest externo — `data_room/` está pensado para due diligence, no las sustituye.

---

## 4. Revisión de la propuesta adjunta

El zip es **dos productos pegados**:

### A. Consola Python on-prem (`src/web_console.py`) — conservar y endurecer

API local prevista:

| Método | Ruta | Intención |
|--------|------|-----------|
| GET | `/api/status` | Nodo, licencia, SmartToken |
| POST | `/api/environments/license` | Emitir API key |
| GET/POST | `/api/resources` | Catálogo |
| POST | `/api/work/execute` | Propuesta → MORPH → ATLP |
| GET | `/api/work/ledger` | Ledger |
| POST | `/api/agents/provision` | Bundle de conector |
| GET | `/api/agents/outbox` | Paquetes listos |
| POST | `/api/artifacts/protect\|open` | SmartTokenProd |

UI HTML embebida + `atlctl console` en :8795.

### B. App AI Studio (React + Vite + Firebase + Gemini + `server.ts`) — demo, no data-plane

- `server.ts` **simula** el Edge en memoria: licencias inventadas (`atl_live_` + random), `smarttoken_available: true` hardcodeado, artefactos en un `Map`, friction de mentira.
- Firestore replica assets/executions/audits en `/users/{uid}/...`.
- Gemini 3.1 Flash-Lite para “SecurityAudit” (el payload de la propuesta puede ir a Google).
- Auth Google en el front; **el Python y `server.ts` no autentican las APIs**.

Las reglas de `security_spec.md` (Dirty Dozen, default-deny, `owner_id` inmutable) están bien **para un SaaS de metadatos**. Aplicadas al **data-plane** contradicen `iva.md`: el catálogo y el ledger deben quedarse on-prem.

### 4.1 Hallazgos de la propuesta (sin PoC)

1. **Regresión crypto** si se copian los stubs: ATLP pasa de AES-256-GCM a HMAC sobre JSON en claro (el payload va en `payload_b64`).
2. **Consola sin autenticación HTTP.** Quien alcance :8795 emite keys, ejecuta propuestas, abre artefactos.
3. **`master_secret` en JSON** y fallback `"default-secret"`.
4. **Emisión de licencia en el Edge.** En `main` la emisión es back-office; el Edge solo activa. El zip rompe esa frontera.
5. **`mock_executor`**: la consola no ejecuta skills reales; solo demuestra el gate.
6. **Bind `0.0.0.0` en compose** de la propuesta.
7. **Firestore + Gemini** sacan metadatos (y potencialmente propuestas) del nodo.
8. **Sin `http_limits`**: Content-Length / slow-drip que ya están cerrados en el Edge API vuelven a abrirse en la consola.
9. **`__pycache__` y `bun.lock`** en el zip: no pertenecen al producto Python endurecido.

---

## 5. Versión consolidada (arquitectura objetivo)

Tres planos, sin mezclar secretos:

```text
[Operador / SSO]          Plano de control (metadatos)
        │
        ▼
 Consola Web :8795        loopback o red admin
  (token de operador)
        │  no emite licencias
        ▼
 Edge API :8790           único execute de producción
        │
        ├─ MORPH-8 / policy / catalog / ledger
        ├─ Predigest + ATLP
        ├─ Outbox ──push HMAC──► Cloud Connector ──► agente premium
        └─ Sidecar :8787 SmartTokenProd (artefactos)
        
 Control Plane            emisión de licencias (admin / billing)
        │                 clave Ed25519 en KMS (prod)
        ▼
 Entitlement firmado ──► Edge (LOCKED → activo)
```

**Firebase/Gemini:** opcionales y **fuera** del data-plane. Solo cuenta, org, estado de licencia, tickets. Cero filas, cero propuestas, cero `.stok`.

**React UI:** puede vivir, pero su backend es `web_console.py` (o el Edge), no `server.ts`.

### 5.1 Qué se integra (checklist de merge)

**Añadir**

- `src/web_console.py` (reescrito sobre APIs reales de `main`)
- `examples/web_console_selftest.py`
- Subcomando **aditivo** `atlctl console` (no reemplazar `atlctl.py`)
- Servicio compose `web-console` con `profiles: ["console"]`, `127.0.0.1:8795:8795`
- `docs/CONSOLE.md` + este documento en `docs/` o `data_room/`
- Tests: consola exige token; bind loopback; no emite `atl_live_`; execute pasa por `ATLDataPlaneMVP.production()`; protect/open sin default secret

**No tocar** (salvo PRs dedicados)

- `src/data_plane.py`, `proposal_gate.py`, `mvp.py`, `licensing.py`, `morph8.*`, `edge_api_server.py`, `transport.py`, `execution_ledger.py`
- Workflows CI existentes (añadir job, no sustituir)

**Endurecimiento mínimo de la consola antes de llamar “integrado”**

- Auth: header `Authorization: Bearer` = token de operador en `ATL_CONSOLE_TOKEN` (rotado, no el master ATLP).
- Bind default `127.0.0.1`. `0.0.0.0` solo con `ATL_CONSOLE_BIND_PUBLIC=1` **y** TLS.
- Reusar `src/http_limits.py`.
- `POST /api/environments/license` **fuera**. Licencias: `atlctl issue-license` / control plane.
- Execute: `fields` obligatorio; mismo fail-closed que Edge.
- Artefactos: rechazar `master_secret` vacío o default; no loguear el secreto.
- CORS cerrado; CSRF irrelevante si no hay cookies de sesión (token bearer).
- La consola **no** instancia `LocalDataPlane.issue_for_agent` (respeta RT1: mismo proceso, pero el camino publicado es MVP).

---

## 6. Flujo completo de despliegue (para re-auditar)

Objetivo: un entorno reproducible donde un auditor corre la batería y ve el stack entero (control plane → Edge → consola → sidecar → conector).

### Fase 0 — Preflight

```bash
# En la máquina de laboratorio (no pegar PATs en chat)
git clone git@github.com:dcpracmatic-prog/atl-edge-smarttoken-hardened.git
cd atl-edge-smarttoken-hardened
git checkout main
git rev-parse HEAD   # esperado de esta auditoría: 2449905d…

python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# SmartTokenProd
pip install pqcrypto
bash build.sh
```

Criterio: `build.sh` produce nativos (`morph8`, friction opcional) y **no** hay `.so` precompilados en el árbol fuente.

### Fase 1 — Validación del tronco (antes de consola)

```bash
bash scripts/validate_all.sh
PYTHONPATH=. python testbench/run_testbench.py --require-full
PYTHONPATH=. python testbench/redteam_bypass_v1.py --require-clean
PYTHONPATH=. python examples/e2e_full_stack_selftest.py
```

Criterio de verde (de `iva.md`):

1. Adversarial SmartTokenProd 14/14, 0 SKIP  
2. Unit tests SmartTokenProd  
3. Red-Team RT0–RT18 sin bypass desconocidos  
4. Docker image + testbench en contenedor  
5. Sidecar `/health`  
6. Sin `.so` en git  

Si esto no está verde, **no** se integra la consola.

### Fase 2 — Control plane + tokens de Edge

```bash
# Emisión (admin, no expuesta por HTTP)
PYTHONPATH=. python atlctl.py bootstrap-edge \
  --state .atl/control-plane \
  --out-dir .atl/edge \
  --org acme --plan enterprise \
  --node-id edge-1 --instance-id inst-1 --agent-id agent-1 \
  --print-api-key --save-api-key

# Verificar fail-closed
unset ATL_ALLOW_DEV_DEFAULTS
# Sin edge.env el contenedor/host NO debe arrancar
```

Criterio: API key se muestra una vez; en disco solo huella. `edge.env` + `entitlement.json` + `control-plane-public-key.pem` en `.atl/edge/` (permisos 0600). Master ATLP **no** viaja al conector cloud.

### Fase 3 — Edge + sidecar (producción local)

```bash
# Host
bash scripts/deploy_edge.sh          # bootstrap si falta + Edge :8790
bash scripts/deploy_edge.sh --status

# Docker (recomendado para auditoría)
bash scripts/deploy_edge.sh --bootstrap-only
bash scripts/deploy_edge.sh --docker
docker compose --profile sidecar up -d sidecar
```

Criterio: `GET :8790/health` 200. `GET :8790/v1/execute` sin body → no sella. Sin `ATL_MASTER_KEY_HEX` y sin `ATL_ALLOW_DEV_DEFAULTS` → no arranca.

### Fase 4 — Consola (post-merge, este documento)

```bash
export ATL_CONSOLE_TOKEN="$(openssl rand -hex 32)"
export ATL_EDGE_DIR=.atl/edge
PYTHONPATH=. python -m src.web_console --host 127.0.0.1 --port 8795 \
  --data-dir .atl/console_data

# o
docker compose --profile console up -d web-console
```

Criterio:

- Sin `Authorization` → 401 en todas las rutas salvo `/health` de consola.
- `POST /api/environments/license` → 404 o 405.
- Execute de propuesta destructiva (`delete`/`shell`) → REJECT, sin paquete, sin efecto.
- Execute sin `fields` → fail-closed.
- Protect/open con secreto vacío → 400.
- Ledger y outbox se leen del mismo `ATL_DATA_DIR` que el Edge, no de un mock.

### Fase 5 — Conector cloud (lab)

```bash
# En el host “premium” (otra red o compose service)
# El Edge hace PUSH outbound; no hay inbound al on-prem
PYTHONPATH=. python connector/cloud_runtime.py   # según docs del repo
```

Criterio: push HMAC válido entrega predigest; firma falsa → 401; replay → rechazo; el conector **no** tiene `ATL_MASTER_KEY_HEX`.

### Fase 6 — Artefactos largos

```bash
PYTHONPATH=. python -c "from src.long_lived_protection import status; print(status())"
# Proteger un modelo/dummy vía consola o API sidecar :8787
```

Criterio: `is_available()==True` solo con `pqcrypto`. Abrir con secreto incorrecto avanza fricción. No hay modo “AES sin master_secret”.

### Fase 7 — Paquete de auditoría (evidencia)

```bash
docker compose run --rm testbench
PYTHONPATH=. python testbench/perf_dossier.py
# Entregar:
#  data_room/ + testbench/redteam_report.json + last_report.json
#  + este documento + logs de health de edge/console/sidecar
```

---

## 7. Matriz de re-auditoría (cuando esté integrado)

Usar como go/no-go. Sin exploits: solo propiedades.

| ID | Propiedad | Cómo se demuestra | Go |
|----|-----------|-------------------|----|
| A1 | ¬Authorized(proposal) ⇒ ¬Effect ∧ ¬Issue | redteam `--require-clean` + execute por Edge y por consola | |
| A2 | Issue ⇒ Authorized ∧ Classified ∧ Licensed ∧ Bound | e2e_full_stack + consola contra `production()` | |
| A3 | Edge HTTP no expone `issue_for_agent` | RT16 | |
| A4 | Consola no emite licencias | 404 en `/api/environments/license` | |
| A5 | Consola autenticada | 401 sin token; 200 con token | |
| A6 | Consola loopback por defecto | `ss`/`docker port` no en 0.0.0.0 salvo flag | |
| A7 | ATLP sigue AES-GCM (no HMAC-JSON) | grep/tests de `PackageCrypto` / selftest data_plane | |
| A8 | `fields` obligatorio en prod | execute sin fields = error | |
| A9 | SmartToken binding + Argon2id | testbench 14/14 | |
| A10 | Fail-closed sin master | arranque Edge sin env muere | |
| A11 | Conector sin master de provisionamiento | inspección de bundle + env | |
| A12 | Firestore/Gemini ausentes del data-plane | no hay credenciales GCP en compose de Edge | |
| A13 | CI verde en el PR de integración | Actions CI + job consola | |
| A14 | Stubs del zip no están en `main` | `wc -c src/data_plane.py` ≥ 20k | |

---

## 8. Plan de integración (orden)

1. **No mergear el zip.** Extraer `web_console.py` + selftest + UI como capa.
2. Reescribir consola contra módulos de `main` (`ATLDataPlaneMVP.production()`, `ExecutionLedger`, `Inbox`/`Outbox`, `provision_bundle`, `http_limits`).
3. Añadir `atlctl console` sin borrar subcomandos actuales.
4. Compose profile `console` + `sidecar` encima del `edge-api` actual.
5. Job CI: `examples/web_console_selftest.py` + casos A4–A8.
6. Documentar en README un diagrama de tres procesos (Edge, Consola, Sidecar) y el anti-patrón Firebase-en-el-nodo.
7. Recién entonces: pentest / data_room pack para terceros.

UI React: segundo PR, proxy a la consola Python, auth bearer, **sin** Firestore en el camino de execute.

---

## 9. Acciones inmediatas (operador)

1. **Revocar** el PAT que se pegó en chat (GitHub → Developer settings → Personal access tokens) y no volver a pegar secretos aquí.
2. Dar a Cursor acceso al repo privado (tarjeta de acceso GitHub) para poder abrir el PR de integración sobre `main`.
3. No desplegar la app de AI Studio (`server.ts` / Firebase) contra datos reales.
4. Congelar `hardening-update` hasta decidir cherry-picks (`external_share.py` merece revisión aparte).

---

*Fin del paquete de consolidación. Próximo paso de ingeniería: PR sobre `main` con consola endurecida, sin tocar el crypto path.*
