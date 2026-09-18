# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T21:48:58Z`  
Version: `0.10.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45208 |
| RSS after (KB) | 504252 |
| Dossier runtime (s) | 8.116 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 112.792 | 112.31 | 116.189 | 117.234 |
| open (legitimate) | 111.847 | 110.673 | 115.644 | 120.146 |
| open (forced failure + friction) | 114.427 | 112.518 | 120.238 | 126.62 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1173.07 |
| Mean task (ms) | 517.64 |
| Max task (ms) | 739.798 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
