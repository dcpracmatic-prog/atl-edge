# Comparación de entregas — histórico real (revisado y corregido)

**Fecha de esta actualización:** 2026-09-15T18:32:52Z

> Esta versión del documento reemplaza la anterior, que afirmaba que la
> entrega "Hardened v2" era un *superset estricto* de la entrega previa.
> Una comparación directa, archivo por archivo, mostró que **no lo era**:
> hubo funcionalidad de seguridad presente en una entrega que faltaba en
> la otra, y viceversa. El detalle está abajo.

## Entregas comparadas

| # | Entrega | Archivo recibido | SHA-256 | Rol |
|---|---------|-------------------|---------|-----|
| A | Snapshot anterior (pre-hardening de red) | `ATL.zip` | `5408b86ffcf7dad1da3d6d72b0b6f07ab38b750ba7f3fa323caac45ae55931f` | Integración ATL + SmartTokenProd, sin auth HTTP, sin fuzzing local, dispatcher del Edge API ya minimizado |
| B | Hardened v2 + data room | `jules_session_11646399822715112139.zip` | `655e4445aa441b269a8892866d29cc382970278c4a9c5ce8e4e0c18e1114888a` | Sprint DD completo + evidencia, pero con regresión en el Edge API dispatcher |
| C | **Corregida (vigente)** | `ATL_corregido.zip` | `ac926bf77fc15d538f126fda053c3ea0c3fc2afb062c2896af400808e320d05` | Base B + fix puntual tomado de A en `dispatch_tool_execution` |

Nota: ni A ni B llevaban nombre de archivo con versión/fecha explícita en su origen; se listan por el nombre con que llegaron para trazabilidad. El hash de C corresponde al paquete generado justo después de aplicar el fix de `dispatch_tool_execution`; como este mismo documento vive dentro del zip, cualquier edición posterior de `COMPARISON.md` (incluida esta) cambia el hash del `.zip` que lo contiene — verificar con `sha256sum` sobre el archivo entregado en cada ocasión en vez de asumir que coincide con el valor de esta tabla.

## Qué tenía cada entrega que la otra no

| Área | A (`ATL.zip`) | B (Hardened v2) |
|------|----------------|------------------|
| Auth HTTP en `edge_api_server.py` / `sidecar_server.py` (Bearer/token) | **No** | Sí |
| `hmac.compare_digest` en `licensing.py` (org/node) | **No** (`!=` plano) | Sí |
| Infraestructura de fuzzing (`fuzz_morph8.sh`, `fuzz_morph8.cpp`, `fuzz_corpus/`) | **No** | Sí |
| Rotación de claves por tiempo/uso en `keymgmt.py` (`InMemoryKeyProvider`) | **No** | Sí |
| `header_mac`, Docker, dossier de rendimiento, THREAT_MODEL/QUICKSTART, `validate_all.sh` | Sí (ya presente) | Sí (igual) |
| `dispatch_tool_execution` en `edge_api_server.py` sin ramificar sobre `tool`/`operation`/`arguments` del proponente | **Sí** (marcador fijo) | **No** — volvió a procesar registros según campos controlados por el llamador |

Es decir: B corrigió varios puntos de seguridad de red y de criptografía que faltaban en A, pero **introdujo una regresión propia** en el dispatcher del Edge API que A no tenía. Ninguna de las dos entregas era, por sí sola, la mejor en todo.

## Qué corrige la entrega C (vigente)

- Parte de B (conserva auth HTTP, `hmac.compare_digest`, fuzzing, rotación de claves).
- Reemplaza `dispatch_tool_execution` por el marcador fijo de A: ya no ejecuta lógica derivada de `tool`/`operation`/`arguments` de la propuesta sobre `records`, cerrando la superficie que B había reabierto.
- Verificado tras el cambio: `build.sh` compila limpio, `examples/morph_selftest.py` y `examples/atl_mvp_selftest.py` en PASS, `testbench/run_testbench.py` en 2/2 PASS (12 casos restantes en SKIP por falta de `pqcrypto` en el entorno de verificación, no por el cambio).

## Evidencia heredada de B (no re-generada en esta corrección)

- Adversarial (con `pqcrypto` disponible, según `data_room/VALIDATION_REPORT.md` de B): 14/14 PASS, failed=0, skipped=0
- Protect p50: 1.371 ms
- Open p50: 1.109 ms
- Native friction: True

Esta evidencia proviene del entorno donde se generó B y **no fue re-ejecutada completa** sobre C (aquí `pqcrypto` no estaba disponible sin red). Antes de usar C como paquete de due diligence, se recomienda re-correr `testbench/run_testbench.py --require-full` en un entorno con `pqcrypto` instalado y regenerar `data_room/VALIDATION_REPORT.md` desde C.

## Conclusión

Ni A ni B eran un superset estricto una de la otra. **C es la única entrega, de las tres, que es superset real de ambas** en los puntos comparados aquí. Para venta / DD debe usarse `ATL_corregido.zip`, no A ni B por separado — y debe re-generarse la evidencia adversarial completa desde C antes de distribuirla.
