# ATL Edge 

[![CI](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/ci.yml)
[![Nightly](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/nightly.yml)
[![Release](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/release.yml/badge.svg)](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/release.yml)
[![CodeQL Advanced](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/codeql.yml/badge.svg)](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/codeql.yml)
[![Docker Image CI](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/docker-image.yml/badge.svg)](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/docker-image.yml)

**Licencia:** [Elastic License 2.0](LICENSE) · [NOTICE](NOTICE)  
**Repositorio:** [dcpracmatic-prog/atl-edge-smarttoken-hardened](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened)  
**Detalle de la versión actual (límites, CI, threat model operativo):** ver **[iva.md](iva.md)**

---

## Arranque (tres comandos)

```bash
pip install -r requirements.txt && bash build.sh   # 1. dependencias + núcleos nativos
bash scripts/validate_all.sh                       # 2. validar el tronco antes de confiar en él
bash scripts/start_stack.sh                        # 3. Edge :8790 + consola :8795 en loopback
```

El paso 3 imprime la URL de la consola y la ruta del token Bearer
(`.atl/edge/console_token.txt`, modo 0600). Se detiene con
`bash scripts/start_stack.sh --stop`.

Recorrido de extremo a extremo (propuesta en lenguaje natural acotado → gate →
sello ATLP → el conector lo abre con la **clave de nodo**, nunca con la master):

```bash
PYTHONPATH=. python examples/mvp_demo_run.py
```

**Límites y estado real de esta versión:** **[iva.md](iva.md)**.

## Alcance de este MVP

Este árbol es un **MVP de laboratorio demostrable**, no un producto certificado.
Un operador arranca Edge y la consola en loopback, propone en lenguaje natural
acotado, solo se ejecuta lo autorizado, sale un paquete ATLP con `fields`, y el
conector lo abre con la clave de nodo.

**Explícitamente fuera de alcance:**

- SSO / identidad corporativa
- HSM / KMS gestionado (la integración es un stub)
- Despliegue multi-nodo
- Pentest externo y certificaciones (SOC 2 y equivalentes)
- Consola expuesta públicamente sin proxy TLS por delante
- Postgres en producción (SQLite de referencia basta para el piloto)
- Datos no sintéticos: la demo usa datos de laboratorio

El siguiente hito ya no es MVP: es un piloto en un nodo real con datos reales.

---


## Operator console (three-process view)

```text
Edge API :8790     — production execute / ATLP seal (network boundary)
Console  :8795     — authenticated operator UI (loopback; Bearer ATL_CONSOLE_TOKEN)
Sidecar  :8787     — SmartTokenProd long-lived artifacts (optional)
```

See **[docs/CONSOLE.md](docs/CONSOLE.md)** for the full audit/deploy flow (phases 0–7)
and the A1–A14 go/no-go table. Consolidation notes:
[docs/ATL-EDGE-AUDITORIA-INTEGRACION.md](docs/ATL-EDGE-AUDITORIA-INTEGRACION.md).

**Anti-pattern:** do not put Firebase, Gemini, or a demo `server.ts` on the
data-plane. License issuance stays in `atlctl` / the control plane — not the console.

Start console (after Edge bootstrap / `edge.env`):

```bash
export ATL_CONSOLE_TOKEN="$(openssl rand -hex 32)"
set -a && source .atl/edge/edge.env && set +a
PYTHONPATH=. python atlctl.py console --host 127.0.0.1 --port 8795
# or: ATL_CONSOLE_TOKEN=... docker compose --profile console up -d web-console
```

## ¿Qué es?

**ATL Edge** es un **intermediario de datos on-prem** entre:

- un **agente local** (p. ej. Llama + skills en la misma empresa), y  
- un **agente premium / conector en la nube** (u otro nodo de confianza).

No sustituye al agente ni a la base de datos. Su trabajo es: **recibir una propuesta de trabajo, decidir si es aceptable, ejecutar solo lo autorizado, reducir los datos al mínimo útil y entregarlos en un paquete cifrado de vida corta**.

**SmartTokenProd** es la pieza complementaria para **archivos de larga duración** (modelos, artefactos, documentos) que deben salir del nodo o vivir fuera del ciclo de un paquete ATLP: cifrado post-cuántico + secreto humano + fricción ante intentos fallidos.

Juntos forman un **borde de protección de datos para agentes de IA**: el trabajo pesado y sensible se queda cerca de los datos; hacia fuera solo viaja lo necesario, sellado y con reglas claras.

---

## ¿Qué problema resuelve?

| Situación habitual | Con ATL Edge / SmartTokenProd |
|--------------------|------------------------------|
| El agente en la nube ve demasiado (filas, columnas, contexto de más) | Solo recibe un **predigest** de campos pedidos, empaquetado y con caducidad |
| Cualquier script puede “ejecutar y listo” | Solo el **camino canónico** (schema → MORPH → auth → executor → sello) produce efecto y paquete |
| Propuestas del LLM local mal formadas o peligrosas (`shell`, borrados, etc.) | **MORPH-8 + policy** las rechaza antes de ejecutar |
| Reutilizar respuestas viejas o reenviar el mismo `request_id` | Paquetes ATLP con **TTL** y **anti-replay** |
| Archivos sensibles en claro o solo con una llave técnica | **SmartTokenProd**: hace falta la llave de custodia **y** el `master_secret`; intentos fallidos activan fricción |

En una frase: **permite que la IA trabaje cerca de tus datos sin regalarle las llaves de la casa ni un volcado completo de contexto.**

---

## Fundamentos de la solución

### 1. Separación de tiempos de vida

- **ATLP (corto):** respuestas para el conector premium — minutos/horas, atadas al nodo, no reutilizables.  
- **SmartTokenProd (largo):** artefactos que deben persistir — `.stok` + `.stok.key` + secreto humano.

### 2. Un solo camino de ejecución

Toda acción con efecto lateral debe pasar por el orquestador MVP (`ATLDataPlaneMVP.execute_and_issue` o el **Edge API** HTTP). No hay un atajo oficial de “sella tú mismo” en la red.

```text
Agente local (Llama / skills)
        │  propuesta (tool, operation, fields, …)
        ▼
Proposal Schema v1
        ▼
MORPH-8 + policy     ──REJECT──► no hay ejecución ni paquete
        │ ACCEPT / REPAIR
        ▼
Autorización de datos (catálogo / nodo)
        ▼
Executor (solo lo aceptado)
        ▼
Predigest (mínimo de campos y filas)
        ▼
ATLP (AES-GCM, TTL, anti-replay, clave de nodo)
        ▼
Conector / agente premium
```



### Agente local: proponer con decoding acotado

El adaptador explícito vive en `src/proposer.py` (antes el README describía el flujo
sin un módulo que generara la propuesta):

```python
from src.proposer import propose, ProposeBackend
from src.proposal_gate import ProposalGate, default_proposal_policy
from src.morph8 import MorphGate

# Deterministic / no-LLM path (always available)
proposal = propose("lookup from crm fields=[id, status] status=active",
                   backend=ProposeBackend.TEMPLATE)

# Grammar backends (outlines | xgrammar | llama_cpp): require the optional stack.
# If the backend cannot enforce grammar → ConstrainedDecodeError (fail closed)
# or template if fallback_template=True. Never unconstrained prose.
# from src.proposer_model import load_proposer_model   # Qwen3-8B GGUF, Apache-2.0
# proposal = propose(text, backend="llama_cpp", model=load_proposer_model())

gate = ProposalGate(default_proposal_policy(), MorphGate())
assert gate.check(proposal).allowed
# then: ATLDataPlaneMVP.execute_and_issue(proposal, records, executor=...)
```

Self-test: `PYTHONPATH=. python examples/proposer_selftest.py`

Defense in depth: the **proposer** constrains *format*, the **gate** constrains *semantics*, and the **catalog** constrains *fields*. Optional LLM stacks live in `requirements-proposer.txt` (not default `requirements.txt`). Runtime: `POST /v1/propose` on the Edge API (proposal only); `atlctl propose --intent ...` and the operator console Propose panel call that path / the same adapter. In notebooks, pin a commit SHA and set `USE_REPO_PROPOSER=True` to import `src.proposer`.

### 3. Minimización explícita

La propuesta declara **qué campos** necesita. El predigest proyecta las filas a esa lista. En modo producción / Edge API, **sin `fields` no hay emisión**. Así se evita el “te mando el record entero por si acaso”.

### 4. Confianza de proceso vs confianza de red

- **Red:** el Edge API expone salud, capacidades, `propose` (solo propuesta) y `execute` sobre el MVP.  
- **Proceso:** quien ya corre código dentro del mismo proceso con acceso al data plane sigue en un modelo de confianza de proceso (detalle en [iva.md](iva.md)).

### 5. Criptografía alineada al uso

- Paquetes cortos: AES-GCM + material derivado del nodo.  
- Archivos largos: ML-KEM-768 (post-cuántico) + AES ligado también al `master_secret` + **Argon2id** (memory-hard) en verificadores del `.stok`.

---

## Capacidades y funciones (mapa del producto)

| Capacidad | Qué hace | Dónde vive |
|-----------|----------|------------|
| **Proposal Schema v1** | Contrato ejecutable del agente local; rechaza campos desconocidos o peligrosos | `src/proposal_gate.py` |
| **Local proposer (constrained)** | Adapta texto del agente local → dict Proposal Schema v1 con decoding acotado (`outlines` / `xgrammar` / llama.cpp GBNF) o plantilla; **nunca** prosa libre | `src/proposer.py` |
| **MORPH-8** | Gate estructural: tools permitidas, acciones, grafo causal, reparación acotada | `src/morph8.py` / `morph8.cpp` |
| **Policy semántica** | Allowlists de operaciones, límites de efectos/campos, rechazo de destructivos | `ProposalGate` |
| **Data catalog / auth** | Clasificación y permiso por recurso y campos en el nodo | `src/data_catalog.py` |
| **Predigest** | Proyección a `fields` + tope de filas por paquete | `src/data_plane.py` |
| **ATLP** | Cifrado, TTL, anti-replay, auditoría on-prem | `src/data_plane.py` |
| **Licenciamiento** | Entitlement de nodo/capacidades en el camino de producción | `src/licensing.py` |
| **Edge API** | Único HTTP de entrada al MVP | `src/edge_api_server.py` |
| **Sidecar SmartToken** | Protect/open de artefactos por HTTP local | `src/sidecar_server.py` |
| **SmartTokenProd** | Protección de archivos de larga duración + fricción | paquete instalado `smart_token_prod` (pin en `requirements.txt`) |
| **Testbench / Red-Team** | Batería adversarial + ataques de frontera (proceso y red) | `testbench/` |

---

## Validación de flujos de trabajo (CI)

La calidad del tronco se mide en GitHub Actions, no solo en demos locales.

| Workflow | Archivo | Qué valida |
|----------|---------|------------|
| **CI** | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Batería adversarial SmartTokenProd, pruebas unitarias, Red-Team, sanitizers nativos, análisis estático, **Docker**, **sidecar** smoke |
| **Nightly** | [`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) | Validación completa diaria |
| **Release** | [`.github/workflows/release.yml`](.github/workflows/release.yml) | Empaquetado de fuentes + data room en tags `v*` |

**Badges (estado en `main`):**

| Pipeline | Estado |
|----------|--------|
| CI | [![CI](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/ci.yml) |
| Nightly | [![Nightly](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/nightly.yml) |
| Release | [![Release](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/release.yml/badge.svg)](https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened/actions/workflows/release.yml) |

Criterio de verde del CI (resumen):

1. Adversarial SmartTokenProd completa  
2. Unit tests del producto vendido  
3. Red-Team sin bypass desconocidos  
4. Imagen Docker + testbench en contenedor  
5. Sidecar `/health`  
6. Sin `.so` precompilados en el árbol fuente  

Equivalente local:

```bash
bash build.sh
bash scripts/validate_all.sh
# o por piezas:
PYTHONPATH=. python testbench/run_testbench.py --require-full
PYTHONPATH=. python testbench/redteam_bypass_v1.py --require-clean
```

---

## Licenciamiento (generar tokens)

El control plane **emite** licencias y **activa** nodos/agentes. Los tokens usables son:

1. **API key** (`atl_live_…`) — se muestra **una sola vez** al emitir; solo se guarda su huella.
2. **Entitlement firmado** (JSON) — resultado de activar con `node_id` + `instance_id` + `agent_id`; lo verifica el Edge.

```bash
# Piloto en un solo paso: licencia + entitlement + edge.env + master key
PYTHONPATH=. python atlctl.py bootstrap-edge \
  --state .atl/control-plane \
  --out-dir .atl/edge \
  --org acme --plan enterprise \
  --node-id edge-1 --instance-id inst-1 --agent-id agent-1 \
  --print-api-key --save-api-key

# Arrancar Edge con tokens reales (sin ATL_ALLOW_DEV_DEFAULTS)
set -a && source .atl/edge/edge.env && set +a
PYTHONPATH=. python -m src.edge_api_server --host 127.0.0.1 --port 8790
```

Pasos separados (admin vs nodo):

```bash
PYTHONPATH=. python atlctl.py issue-license --state .atl/cp --org acme --max-agents 5
PYTHONPATH=. python atlctl.py activate-local --state .atl/cp --key 'atl_live_…' \
  --node-id edge-1 --instance-id inst-1 --agent-id agent-1
PYTHONPATH=. python atlctl.py write-edge-env \
  --entitlement .atl/entitlement.json \
  --public-key .atl/control-plane-public-key.pem
```

HTTP remoto: `atlctl request-license --control-plane-url https://…` (solo activación; la emisión admin no se expone por red a propósito).

## Despliegue automatizado del Edge

```bash
# Un comando (host): bootstrap de licencia si falta + natives + Edge API
bash scripts/deploy_edge.sh

# Solo generar tokens / edge.env (sin arrancar)
bash scripts/deploy_edge.sh --bootstrap-only

# Docker Compose (servicio edge-api en :8790)
bash scripts/deploy_edge.sh --docker

# Estado / health
bash scripts/deploy_edge.sh --status
```

Variables útiles: `ATL_ORG`, `ATL_NODE_ID`, `ATL_AGENT_ID`, `ATL_HOST`, `ATL_PORT`, `ATL_EDGE_DIR`.

## Arranque rápido (visión práctica)

```bash
git clone https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened.git
cd atl-edge-smarttoken-hardened
pip install -r requirements.txt
bash build.sh

# Camino de datos cortos (Edge API)
PYTHONPATH=. python -m src.edge_api_server --host 127.0.0.1 --port 8790

# Artefactos largos (si pqcrypto está instalado)
PYTHONPATH=. python -c "from src.long_lived_protection import status; print(status())"
```

Docker:

```bash
docker compose up --build
```

Guías de integración y amenazas: [`docs/QUICKSTART.md`](docs/QUICKSTART.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).  
**Estado fino de la versión (qué está cerrado, qué sigue fuera de alcance, formatos, RT):** **[iva.md](iva.md)**.

---

## A quién va dirigido

- Equipos que despliegan **agentes on-prem** junto a datos sensibles y deben alimentar un **servicio premium en la nube** sin exportar el dataset completo.  
- Quienes necesitan un **borde auditable**: propuesta → decisión → mínimo de datos → paquete sellado.  
- Quienes además deben **proteger artefactos** (modelos, ficheros) con un ciclo de vida distinto al de un token de respuesta.

---

## Documentación relacionada

| Documento | Contenido |
|-----------|-----------|
| **[iva.md](iva.md)** | Información de **versión actual**: límites, hallazgos cerrados, CI detallado, Edge/SmartToken operativos |
| [`docs/CI_CD.md`](docs/CI_CD.md) | Pipelines y release |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Modelo de amenazas |
| [`data_room/`](data_room/) | Evidencias y manifiestos para evaluación |
| [`LICENSE`](LICENSE) | Elastic License 2.0 |
