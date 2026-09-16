# Comparación de las dos últimas entregas

**Fecha:** 2026-09-15T02:32:45Z

## Entregas comparadas

| # | Entrega | Archivo | SHA-256 (primeros 16) | Rol |
|---|---------|---------|----------------------|-----|
| 1 | Integración funcional (pre-sprint DD) | `atl_edge_smarttoken_integrated.zip` | `3451b0a0b71b96c8…` | Primera fusión ATL + SmartTokenProd + testbench inicial |
| 2 | Hardened v2 + data room (última) | `atl_edge_smarttoken_integrated_hardened_v2.zip` | `924b113d5acefb60…` | Sprint DD completo + evidencia |
| 2b | Data room (subconjunto) | `ATL_Edge_DataRoom_Hardened_v2.zip` | `f84b2c4ead3b76ca…` | Solo documentos/evidencia para revisores |

## Qué aportaba la entrega 1 (integración)

- SmartTokenProd vendored (`vendor/smart_token_prod/`) con amarre `ss || master_secret`
- API `src/long_lived_protection.py`
- Testbench adversarial inicial (muchas casos en SKIP sin pqcrypto)
- Self-test long-lived (con assert débil luego corregido)
- Separación ATLP vs SmartTokenProd documentada en README

**No incluía:** Docker, sidecar, header MAC, dossier de rendimiento, THREAT_MODEL/QUICKSTART dedicados, script `validate_all.sh`, data room, batería 14/14 en verde.

## Qué aporta la entrega 2 (Hardened v2) — superset correcto

| Área | Entrega 1 | Entrega 2 (última) |
|------|-----------|---------------------|
| Key binding AES | Sí | Sí (igual) |
| `header_mac` (metadata + friction autenticados) | No | **Sí** |
| Batería adversarial | Parcial / SKIP | **14/14 PASS, 0 SKIP** |
| Docker multi-etapa | No | **Sí** (`Dockerfile`, `compose`) |
| Sidecar HTTP | No | **Sí** (`src/sidecar_server.py`) |
| Dossier de rendimiento | No | **Sí** (`perf_report.md/json`) |
| THREAT_MODEL + QUICKSTART | No | **Sí** (`docs/` + `data_room/`) |
| Validación un comando | No | **Sí** (`scripts/validate_all.sh`) |
| Paquete data room | No | **Sí** |

## Evidencia vigente (embebida en entrega 2)

- Adversarial: **14/14 PASS**, failed=0, skipped=0
- Protect p50: **1.371 ms**
- Open p50: **1.109 ms**
- Native friction: **True**

## Conclusión de comparación

La **última entrega es un superset estricto** de la penúltima: conserva la integración y añade el sprint de due diligence.  
Para venta / DD debe usarse **solo** `atl_edge_smarttoken_integrated_hardened_v2.zip` + el data room. La entrega 1 queda como histórico.
