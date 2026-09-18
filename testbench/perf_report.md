# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T21:30:23Z`  
Version: `0.10.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45344 |
| RSS after (KB) | 522764 |
| Dossier runtime (s) | 8.046 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 113.667 | 112.586 | 117.523 | 124.165 |
| open (legitimate) | 113.491 | 111.369 | 119.963 | 122.561 |
| open (forced failure + friction) | 114.726 | 113.731 | 118.008 | 120.834 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1126.78 |
| Mean task (ms) | 502.041 |
| Max task (ms) | 666.448 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
