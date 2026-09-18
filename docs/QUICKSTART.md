# Quickstart — ATL Edge + SmartTokenProd

## Opción A — Biblioteca en proceso (< 10 líneas)

```python
from src.long_lived_protection import protect_artifact, open_artifact, is_available

assert is_available()  # requiere pqcrypto

stok, key = protect_artifact("model.onnx", master_secret=b"CHANGE-ME")
pt, info = open_artifact(stok, master_secret=b"CHANGE-ME", key_path=key)
assert info["recoverable"] and pt is not None
```

## Opción B — Sidecar HTTP (multi-proceso local)

Terminal 1:

```bash
bash build.sh
PYTHONPATH=. python -m src.sidecar_server --host 127.0.0.1 --port 8787
```

Terminal 2:

```bash
PYTHONPATH=. python examples/sidecar_client_quickstart.py
```

## Opción C — Docker (un comando)

```bash
docker compose up --build -d
docker compose run --rm testbench
docker compose run --rm bench
```

## Validación adversarial

```bash
pip install -r requirements.txt
bash build.sh
PYTHONPATH=. python testbench/run_testbench.py --require-full
```

Debe terminar con `failed=0 skipped=0`.

## Qué usar cuándo

| Necesidad | Herramienta |
|-----------|-------------|
| Paquete corto para conector premium | **ATLP** (`LocalDataPlane`) |
| Archivo / artefacto de larga duración | **SmartTokenProd** (`protect_artifact`) |
| Agentes en varios procesos en el mismo host | **Sidecar** (`src.sidecar_server`) |
| Fricción compartida entre nodos | `FrictionStore` (Redis) — no incluido en el camino por defecto |
