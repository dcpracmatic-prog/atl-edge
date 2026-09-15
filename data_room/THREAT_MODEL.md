# Modelo de amenazas — ATL Edge + SmartTokenProd (Hardened)

Estado: **borrador técnico para due diligence**. No sustituye una auditoría externa.

## 1. Componentes y responsabilidades

| Componente | Función | Límite explícito |
|------------|---------|------------------|
| **ATLP** (`src/data_plane.py`) | Paquetes de corta vida, clave por nodo (HKDF), TTL, anti-replay | No es protección de archivos de larga duración |
| **MORPH-8** | Gate estructural/policy antes de efectos secundarios | No es IAM ni sandbox de código arbitrario |
| **SmartTokenProd** | Artefactos de larga duración (`.stok`), ML-KEM + AES-GCM ligado a `master_secret`, fricción file-local autenticada | Requiere `pqcrypto`; fricción no es distribuida |
| **Sidecar HTTP** | Expone protect/open/status en localhost | No añade consenso multi-nodo |

## 2. Qué protege SmartTokenProd

- **Confidencialidad del payload** bajo AES-256-GCM con clave derivada de `SHA256(ss || "|MS|" || master_secret || info)`. Poseer solo `sk` (y por tanto `ss`) no basta.
- **Integridad de metadata y friction_snapshot** mediante HMAC-SHA256 (`header_mac`) con clave derivada de `master_secret`.
- **`sk` fuera de banda**: no se serializa en el `.stok` por defecto.
- **Fricción secuencial file-local** (aviso → mutación → tarpit) persistida dentro del `.stok` autenticado.
- **Detección de manipulación** de ciphertext (tag GCM) y de cabecera (HMAC).

## 3. Qué no protege

- Canales laterales (timing, cache, potencia); el código no es constant-time de extremo a extremo.
- Fricción **distribuida** entre workers sin `FrictionStore` externo.
- Oráculos de error detallados si la API se expone a un llamador no confiable (el `info` de `open` es verboso a propósito para operación local).
- Compromiso del host donde residen `sk` o `master_secret` en memoria.
- Sustitución completa de autorización: MORPH-8 / Proposal Gate siguen siendo el perímetro de ejecución.
- Attestation de hardware del nodo.

## 4. Superficie de ataque prioritaria

1. Atacante con `.stok` + `.stok.key` pero sin `master_secret` → no debe descifrar (cubierto por A1/A6).
2. Atacante que escribe el `.stok` y falsifica `friction_snapshot` → debe fallar `header_mac` (A10).
3. Mezcla `.stok` A + key B → fallo cerrado (A15).
4. Tampering de ciphertext / label / salt → fallo cerrado (A5/A11/A12).
5. Fuerza bruta online de `master_secret` vía sidecar expuesto → mitigado solo parcialmente por fricción file-local; **no** exponer el sidecar sin autenticación de red adicional.

## 5. Primitivas

- ML-KEM-768 vía `pqcrypto` (intercambio de clave post-cuántico).
- AES-256-GCM vía `cryptography`.
- HMAC-SHA256 para `header_mac`.
- HKDF-SHA256 en ATLP (data plane), dominio separado del MAC de SmartTokenProd.

## 6. Evidencia automatizada

```bash
python testbench/run_testbench.py --require-full --json testbench/last_report.json
```

La batería A1–A12, A15, A17 debe reportar `failed=0` y `skipped=0`.

## 7. Recomendación

Antes de un despliegue con datos sensibles: auditoría externa centrada en SmartTokenProd + ATLP y en la política de exposición del sidecar.
