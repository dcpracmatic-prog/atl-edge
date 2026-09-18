# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T12:26:42Z`  
Version: `0.10.3`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45344 |
| RSS after (KB) | 558104 |
| Dossier runtime (s) | 8.27 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 118.089 | 113.711 | 139.122 | 143.46 |
| open (legitimate) | 115.946 | 113.298 | 117.379 | 151.368 |
| open (forced failure + friction) | 119.841 | 115.68 | 123.677 | 163.761 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1089.1 |
| Mean task (ms) | 490.616 |
| Max task (ms) | 628.181 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
