# Integración Smart Token Prod (generado)

Este archivo lo escribió `smart-token integrate`. Pasos recomendados:

## 1. Dependencia

Instala el paquete desde git (o editable local):

```bash
pip install "smart-token-prod @ git+https://github.com/dcpracmatic-prog/Smart-Token-Prod.git@v0.10.2"
# o editable:
# pip install -e /ruta/a/Smart-Token-Prod
```

Si el proyecto usa `requirements.txt`, la línea ya se añadió (o está en
`requirements-smart-token.txt`). Con solo `pyproject.toml`, revisa
`requirements-smart-token.txt` y añade la dependencia a tu `[project]` /
grupo de deps a mano (no se reescribe TOML a ciegas).

## 2. Quitar el vendor

Si existe `vendor/smart_token_prod/` (copia antigua / fork):

1. Elimina ese directorio del árbol y del control de versiones.
2. Deja de exportar `PYTHONPATH=.` (o equivalente) **solo** para STP.
3. Sustituye imports del estilo `from smart_token_prod import ...` que
   dependían del vendor por el bridge:

```python
from smart_token_bridge import (
    protect_artifact,
    open_artifact,
    artifact_friction_status,
    is_available,
    status,
)
```

O importa directo del paquete instalado:

```python
from smart_token_prod.sdk import protect_artifact, open_artifact, status
```

## 3. Comprobar

```bash
smart-token doctor
smart-token version
python -c "from smart_token_bridge import is_available; print(is_available())"
```

## 4. API de alto nivel

- `protect_artifact(path, master_secret=...)` → `(stok_path, key_path)`
- `open_artifact(stok, master_secret=..., key_path=...)` → `(bytes|None, info)`
- `artifact_friction_status(stok)` → dict de inspección
- `is_available()` / `status()` → salud del stack

Detalle: ver `docs/INTEGRATION.md` en el repo Smart-Token-Prod.
