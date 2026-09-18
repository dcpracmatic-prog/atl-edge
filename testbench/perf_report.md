# SmartTokenProd — Performance Dossier

Generated: `2026-09-18T12:26:57Z`  
Version: `0.10.3`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 45256 |
| RSS after (KB) | 540612 |
| Dossier runtime (s) | 8.281 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 120.415 | 115.791 | 134.141 | 157.55 |
| open (legitimate) | 115.865 | 115.235 | 119.28 | 124.612 |
| open (forced failure + friction) | 118.778 | 116.609 | 124.792 | 136.72 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 1088.25 |
| Mean task (ms) | 501.378 |
| Max task (ms) | 681.526 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `smart_token_prod/persistence.py` in the pinned package); file-local MAC-authenticated
  snapshots do not coordinate across processes.
