# CI/CD — Hardened v2

## Workflows

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| **CI** | `.github/workflows/ci.yml` | push/PR a `main`/`master`/`hardened-v2` | Validación completa |
| **Release** | `.github/workflows/release.yml` | tag `v*` o manual | Empaqueta data room + fuente y publica GitHub Release |
| **Nightly** | `.github/workflows/nightly.yml` | cron diario / manual | Validación extendida |

## Jobs del CI

1. **validate** (Python 3.11 y 3.12)  
   `build.sh` → batería `--require-full` → self-test long-lived → dossier de rendimiento → pytest unitario.

2. **native-sanitizers**  
   `libfriction.so` con ASan+UBSan y batería bajo sanitizers.

3. **static-analysis**  
   Compilación con `-Wall -Wextra -Wpedantic`, `clang-tidy` (soft) y prohibición de binarios `.so` en el árbol.

4. **docker**  
   Build de la imagen multi-etapa y ejecución del testbench + dossier dentro del contenedor.

5. **sidecar-smoke**  
   Arranque de `src.sidecar_server` y comprobación de `/health` y `/v1/status`.

## Criterio de verde

- `testbench/run_testbench.py --require-full` → `failed=0`, `skipped=0`
- Self-test long-lived en PASS
- Imagen Docker construible
- Sin `.so` precompilados en el repositorio

## Uso local equivalente

```bash
bash scripts/validate_all.sh
```

## Release

```bash
git tag v2.0.0
git push origin v2.0.0
```

El workflow `Release` genera:

- ZIP de fuentes (sin binarios)
- Data room (`last_report.json`, `perf_report.md`, threat model, quickstart)
- `CHECKSUMS.sha256`
- GitHub Release con esos archivos
