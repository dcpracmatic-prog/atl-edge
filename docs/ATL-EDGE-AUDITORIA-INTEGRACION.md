# ATL Edge + SmartTokenProd — auditoría e integración (estado actual)

**Fecha:** 16 sep 2026 (America/Mexico_City)  
**Repo:** https://github.com/dcpracmatic-prog/atl-edge-smarttoken-hardened  
**Línea auditada:** `main` @ `2141361668838722ce6650d52efb865b59b99f8a`  
**Consola:** PR #1 **MERGED** — `src/web_console.py` existe (~21 813 B)

Este documento refleja la verdad operativa de `main` tras la consola y el remediado CI/CodeQL/start_stack de este PR.

---

## 1. Veredicto rápido

| Dimensión | Estado |
|-----------|--------|
| Data-plane / crypto (`data_plane.py`, `mvp.py`, `proposal_gate.py`, `vendor/`) | **Intacto** — no tocado en este remediado |
| Consola operador (`web_console.py` + `atlctl console`) | **Hecho** (PR #1) |
| CI sidecar-smoke | **Roto en main** por corrupción de `ci.yml` (línea diff stray) — **corregido en este PR** |
| CodeQL (~13 alertas) | **En remediación** (higiene de API keys + comentario fingerprint; crypto sin cambios) |
| Un comando cliente → URL consola | **Hecho en este PR** (`scripts/start_stack.sh`) |

---

## 2. Checklist vs intención de producto

| Ítem | Estado |
|------|--------|
| Edge API `:8790` + consola `:8795` + sidecar `:8787` opcional | **Hecho** |
| Fail-closed sin master / entitlement; `fields` obligatorios | **Hecho** |
| Consola Bearer (`ATL_CONSOLE_TOKEN`); loopback por defecto | **Hecho** |
| Licencias solo vía `atlctl` / control plane (no desde consola) | **Hecho** |
| Un comando arranca stack e imprime URL de consola | **Hecho** (`bash scripts/start_stack.sh`) |
| Crypto de `main` sin pisar | **Hecho** (este PR no toca data_plane/mvp/proposal_gate/vendor) |
| Firebase / Gemini / `server.ts` fuera del data-plane | **Hecho** (política) |
| SSO / IdP de usuario | **No hecho** |
| MCP marketplace / gateway nativo | **No hecho** (no aplica como posicionamiento actual) |
| HSM / attestation hardware | **No hecho** / **no aplica** al wedge actual |
| Multi-nodo HA Edge | **No hecho** |
| Certificaciones SOC2 / pentest externo | **No hecho** (data_room es evidencia, no sustituye) |
| Android/Termux como producto | **No aplica** |

---

## 3. Posicionamiento competitivo (honesto)

ATL es un **intermediario de datos on-prem con ejecución gateada** + ATLP (paquetes cortos) + SmartTokenProd (artefactos largos). No es IdP, HSM ni marketplace MCP.

| Familia | Ejemplos | ATL vs ellos |
|---------|----------|--------------|
| Secret managers | HashiCorp Vault, cloud KMS | Vault guarda secretos de infra; ATL **autoriza propuestas** y sella filas. SmartToken no sustituye un HSM. |
| AI gateways / proxies | LiteLLM, Portkey | Enrutan prompts/modelos; ATL **no** enruta LLMs — empaqueta el mínimo de datos tras MORPH/policy. |
| DLP / data access | Immuta, Privacera, clasificadores | Cubren warehouses/RAG; ATL vive **junto al agente** en el borde de ejecución. |
| Agent sandboxes / MCP | sandboxes, MCP gateways (Skyflow, etc.) | ATL no es marketplace MCP; expone proposal schema + Edge execute. Tokenización SaaS saca el dato a un vault cloud — ATL predigerir/sella **en el nodo**. |

Wedge: *el trabajo pesado se queda junto a tus datos; hacia el agente premium solo sale el mínimo útil, sellado, con TTL.*

---

## 4. Estado del tronco (`main` @ 2141361)

- **Consola:** `src/web_console.py` (~21k), selftest en CI (`console-selftest`), compose profile `console`.
- **CI:** job `sidecar-smoke` estaba corrupto (línea `--- /tmp/ci-main.yml …` → YAML roto / exit 127). Este PR limpia el step y añade `permissions: contents: read` a `ci.yml` / `nightly.yml`.
- **CodeQL:** alertas de clear-text API key en `atlctl.py` y weak-hash fingerprint en `licensing.py` — remediadas sin cambiar semántica cripto (solo fingerprint comment + nunca imprimir raw keys).
- **Arranque cliente:** `scripts/start_stack.sh` (host o `--docker`); `deploy_edge.sh` sigue siendo Edge-only y apunta a `start_stack` para el stack completo.

Archivos que **no** se tocan en remediados de producto: `src/data_plane.py`, `src/mvp.py`, `src/proposal_gate.py`, `vendor/`.

---

## 5. Flujo deploy + auditoría (un comando)

```bash
cd atl-edge-smarttoken-hardened
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# opcional SmartTokenProd:
pip install pqcrypto || true

# Un comando: bootstrap si falta → nativos → Edge :8790 → consola :8795
bash scripts/start_stack.sh
# Docker:
# bash scripts/start_stack.sh --docker
# Parar host:
# bash scripts/start_stack.sh --stop
```

Abrir **http://127.0.0.1:8795/** (la app del operador).  
Edge health (no es la app): **http://127.0.0.1:8790/health**.

Fases detalladas 0–7 y checklist A1–A14: [`docs/CONSOLE.md`](CONSOLE.md).

Validación de tronco antes de confiar en lab:

```bash
bash scripts/validate_all.sh
PYTHONPATH=vendor:. python examples/web_console_selftest.py
```

---

## 6. Anti-patrones

- No pisar `data_plane.py` con stubs HMAC “para demo”.
- No emitir licencias desde la consola.
- No loguear API keys / `ATL_CONSOLE_TOKEN` en claro (usar fingerprint + once-file 0600).
- No tratar `GET :8790/` (`INERT`) como la app — la app es `:8795/`.

---

*Próximo paso de ingeniería: CI verde post-fix + re-scan CodeQL; crypto path permanece congelado salvo bug demostrado.*
