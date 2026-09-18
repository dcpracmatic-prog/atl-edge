# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T22:02:05Z`  
Version: `0.10.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45352 |
| RSS after (KB) | 529852 |
| Dossier runtime (s) | 7.905 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 112.062 | 111.179 | 115.759 | 116.042 |
| open (legitimate) | 110.9 | 110.055 | 113.754 | 113.998 |
| open (forced failure + friction) | 111.874 | 111.233 | 116.599 | 117.672 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1089.73 |
| Mean task (ms) | 505.582 |
| Max task (ms) | 617.295 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
