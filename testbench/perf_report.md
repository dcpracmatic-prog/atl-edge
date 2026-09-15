# SmartTokenProd — Performance Dossier

Generated: `2026-09-15T17:42:31Z`  
Version: `0.4.4`  
Native friction core: **yes**

## Process footprint

| Metric | Value |
|--------|------:|
| RSS before (KB) | 42740 |
| RSS after (KB) | 45304 |
| Dossier runtime (s) | 0.208 |

## Serial protect / open (artifact 65536 bytes, n=15)

| Operation | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|-----------|----------:|---------:|---------:|---------:|
| protect_file | 2.924 | 2.8 | 3.086 | 4.586 |
| open (legitimate) | 2.316 | 2.28 | 2.578 | 2.684 |
| open (forced failure + friction) | 4.373 | 4.449 | 4.653 | 5.068 |

## Concurrent failed opens (tarpit pressure)

| Metric | Value |
|--------|------:|
| Workers | 8 |
| Tasks | 16 |
| Wall clock (ms) | 40.9 |
| Mean task (ms) | 14.935 |
| Max task (ms) | 25.218 |

## Notes for reviewers

- Forced-failure path includes sequential friction (and optional CPU tarpit). Elevated
  latency on that path is intentional defensive behaviour, not a throughput bug.
- Measurements are single-host laboratory numbers; they are not an SLA.
- Multi-worker **shared** friction state requires an external FrictionStore
  (see `vendor/smart_token_prod/persistence.py`); file-local MAC-authenticated
  snapshots do not coordinate across processes.
