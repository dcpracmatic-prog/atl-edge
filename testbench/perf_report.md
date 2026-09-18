# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T21:39:14Z`  
Version: `0.10.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45188 |
| RSS after (KB) | 551348 |
| Dossier runtime (s) | 8.099 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 114.655 | 114.471 | 118.671 | 126.462 |
| open (legitimate) | 116.555 | 113.48 | 126.901 | 147.591 |
| open (forced failure + friction) | 115.503 | 113.362 | 125.079 | 132.197 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1114.64 |
| Mean task (ms) | 508.104 |
| Max task (ms) | 673.61 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
