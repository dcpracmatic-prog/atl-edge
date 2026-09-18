# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T17:59:37Z`  
Version: `0.10.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45328 |
| RSS after (KB) | 559408 |
| Dossier runtime (s) | 8.179 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 117.949 | 116.699 | 122.821 | 126.459 |
| open (legitimate) | 116.691 | 115.764 | 120.015 | 122.097 |
| open (forced failure + friction) | 117.772 | 116.995 | 121.425 | 121.904 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1043.76 |
| Mean task (ms) | 466.107 |
| Max task (ms) | 571.989 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
