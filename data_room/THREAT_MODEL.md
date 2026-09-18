# Modelo de amenazas — ATL Edge + SmartTokenProd (Hardened)

Estado: **borrador técnico para due diligence**. No sustituye una auditoría externa.

## 1. Componentes y responsabilidades

| Componente | Función | Límite explícito |
|------------|---------|------------------|
| **ATLP** (`src/data_plane.py`) | Paquetes de corta vida, clave por nodo (HKDF), TTL, anti-replay | No es protección de archivos de larga duración |
| **MORPH-8** | Gate estructural/policy antes de efectos secundarios | No es IAM ni sandbox de código arbitrario |
| **SmartTokenProd** | Artefactos de larga duración (`.stok`), ML-KEM + AES-GCM ligado a `master_secret` y al `public_label`, fricción file-local autenticada | Requiere `pqcrypto`; fricción no es distribuida |
| **Sidecar HTTP** | Expone protect/open/status en localhost | No añade consenso multi-nodo |

## 2. Qué protege SmartTokenProd

- **Confidencialidad del payload** bajo AES-256-GCM con clave derivada de `SHA256(ss || "|MS|" || master_secret || info)`. Poseer solo `sk` (y por tanto `ss`) no basta.
- **Integridad del `friction_snapshot`** mediante HMAC-SHA256 (`friction_mac`) sobre el snapshot **en disco** más `pk` y `ct`, con clave derivada del `shared_secret`. Una `friction_mac` inválida es fallo cerrado: no se permite OPEN, no se acepta snapshot vacío y la deuda en disco no se borra.
- **Integridad del `public_label`** por ligadura criptográfica, no por MAC aparte: el AAD del AES-GCM se **deriva** de `public_label` y se **recalcula desde el disco** al abrir (`core.expected_aad`), así que falsificar la etiqueta produce `InvalidTag`. El campo `aad` que viaja en el `.stok` es descriptivo y nunca se confía.
  > **Historial:** hasta la v0.4.5 esto lo cubría un `header_mac` sobre toda la cabecera, que desapareció en la v2 del formato. Entre la v0.4.5 y la v0.10.2 se pasaba al AEAD el `aad` almacenado tal cual, de modo que un `public_label` manipulado abría con `status=OPEN`. Lo detectó el caso A11 de esta batería durante la migración y se corrigió aguas arriba en la [v0.10.3](https://github.com/dcpracmatic-prog/Smart-Token-Prod). El caso A18 cubre además la falsificación auto-consistente (atacante que reescribe `public_label` **y** `aad` a la vez), que es lo que distingue una ligadura criptográfica de una simple comprobación entre dos campos que el atacante controla.
- **`sk` fuera de banda**: no se serializa en el `.stok` por defecto.
- **Fricción secuencial file-local** (aviso → mutación → tarpit) persistida dentro del `.stok` autenticado.
- **Detección de manipulación** de ciphertext y de `public_label` por el tag GCM, y del `friction_snapshot` por `friction_mac`.

## 3. Qué no protege

- Canales laterales (timing, cache, potencia); el código no es constant-time de extremo a extremo.
- Fricción **distribuida** entre workers sin `FrictionStore` externo.
- Oráculos de error detallados **para el dueño**: `friction_status` y `open` con `reveal_friction=True` son verbosos a propósito para operación local. El deny por defecto sí es opaco desde la v0.10 (`OPAQUE_DENY_KEYS`), así que un llamador no confiable no obtiene el motivo del rechazo; aun así, no exponga esas rutas de dueño.
- Compromiso del host donde residen `sk` o `master_secret` en memoria.
- Sustitución completa de autorización: MORPH-8 / Proposal Gate siguen siendo el perímetro de ejecución.
- Attestation de hardware del nodo.

## 4. Superficie de ataque prioritaria

1. Atacante con `.stok` + `.stok.key` pero sin `master_secret` → no debe descifrar (cubierto por A1/A6).
2. Atacante que escribe el `.stok` y falsifica `friction_snapshot` → debe fallar `friction_mac` (A10).
3. Mezcla `.stok` A + key B → fallo cerrado (A15).
4. Tampering de ciphertext o de `public_label` → fallo cerrado (A5/A11/A18). `salt` y `material` van vacíos en el formato v2 a propósito — la coherencia es métrica de vista pública, no un oráculo de autorización — así que A9/A12 se reportan **N/A**, no como aprobados.
5. Fuerza bruta online de `master_secret` vía sidecar expuesto → mitigado solo parcialmente por fricción file-local; **no** exponer el sidecar sin autenticación de red adicional.

## 5. Primitivas

- ML-KEM-768 vía `pqcrypto` (intercambio de clave post-cuántico).
- AES-256-GCM vía `cryptography`.
- HMAC-SHA256 para `friction_mac`.
- HKDF-SHA256 en ATLP (data plane), dominio separado del MAC de SmartTokenProd.

## 6. Evidencia automatizada

```bash
python testbench/run_testbench.py --require-full --json testbench/last_report.json
```

La batería A1–A12, A15, A17, A18 debe reportar `failed=0` y `skipped=0`. Los casos **N/A** (propiedades que el formato v2 no tiene por diseño) se cuentan aparte y no invalidan `--require-full`: ningún host podría ponerlos en verde, así que exigirlos volvería la puerta imposible de cumplir para siempre. Un `SKIP` sí la rompe, porque significa que a este host le falta una dependencia y la evidencia queda incompleta.

## 7. Recomendación

Antes de un despliegue con datos sensibles: auditoría externa centrada en SmartTokenProd + ATLP y en la política de exposición del sidecar.


## Offline dictionary against master_secret (addressed in v0.4.5, strengthened in v0.10.2)

**Previous risk:** `salt` / `material` were `SHA-256(master_secret || …)` with no work factor and
were stored in cleartext inside the `.stok`. An attacker with only the file could test password
candidates offline without calling `open_stok` and without advancing friction.

**Mitigation (v0.10.2; v0.4.5 used PBKDF2 for the same purpose):**
- Random `kdf_salt` (16 bytes) stored in the `.stok`
- `salt` / `material` derived via **Argon2id** (defaults `time_cost=2`,
  `memory_cost=64 MiB`, `parallelism=1`, recorded per artifact in the `.stok`
  `kdf_params`). Argon2id is memory-hard, so unlike the previous
  PBKDF2-HMAC-SHA256 (210 000 iterations) it also penalises GPU and ASIC
  attackers, not just sequential CPU ones. Measured cost on the validation host:
  ~113 ms per derivation, and every failed `open_*` attempt pays it.
- Each offline guess pays the KDF cost; friction remains the online slowdown on `open_*`
- AES-GCM key still requires `ss` (from `sk`) **and** `master_secret`
- Legacy files without `kdf_salt` still open with the old verifier (documented as weak)

**Operational requirement:** `master_secret` must remain high-entropy (password manager /
random bytes). Argon2id slows dictionary attacks; it does not make `"password123"` safe.

## Native friction parity

Python and C++ backends are tested for matching `fail_count`, `fib_seed`, and `working_key`
after the **second** failure (key-mutation path). The C++ encoder for `fib(n)` uses defined
shifts only (≤ 56 on `uint64_t`), matching `int.to_bytes(16, "big")` in Python.

## Field minimization (production)

`ATLDataPlaneMVP.production()` and the Edge API set `require_fields=True`.
Requests without `proposal.fields` / `fields` are rejected before predigest.
Each ATLP package is also capped at `DEFAULT_MAX_RECORDS` (20) rows.
