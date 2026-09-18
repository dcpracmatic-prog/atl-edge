# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T21:57:22Z`  
Version: `0.10.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45396 |
| RSS after (KB) | 526480 |
| Dossier runtime (s) | 8.157 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 115.667 | 114.436 | 120.305 | 122.231 |
| open (legitimate) | 115.494 | 115.579 | 118.88 | 119.102 |
| open (forced failure + friction) | 115.964 | 116.213 | 118.217 | 121.448 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1106.2 |
| Mean task (ms) | 500.165 |
| Max task (ms) | 636.098 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
