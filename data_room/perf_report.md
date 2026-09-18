# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T11:25:44Z`  
Version: `0.4.5`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 43924 |
| RSS after (KB) | 47868 |
| Dossier runtime (s) | 2.605 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 37.665 | 37.417 | 37.601 | 41.307 |
| open (legitimate) | 37.041 | 37.014 | 37.197 | 37.352 |
| open (forced failure + friction) | 38.108 | 38.085 | 38.377 | 38.398 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 326.05 |
| Mean task (ms) | 135.367 |
| Max task (ms) | 183.267 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `vendor/smart_token_prod/persistence.py`); file-local MAC-authenticated
  snapshots do not coordinate across processes.
